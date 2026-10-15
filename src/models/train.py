# out_path, train_path, dev_path, log_dir, test_path, model_path

import argparse
import csv
import io
import json
import os
import pickle
import random

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import tqdm
from torch.utils.tensorboard import SummaryWriter

print("os path dir is:", os.getcwd())
# GPU selection is controlled externally through CUDA_VISIBLE_DEVICES.

from uer.layers import *
from uer.encoders import *
from uer.utils.vocab import Vocab
from uer.utils.constants import *
from uer.utils import *
from uer.utils.optimizers import *
from uer.utils.config import load_hyperparam
from uer.utils.seed import set_seed
from uer.model_saver import save_model
from uer.opts import finetune_opts


class Classifier(nn.Module):
    def __init__(self, args, len_embedding_matrix, iat_embedding_matrix):
        """
        len_embedding_matrix: numpy array [len_vocab_size, hidden_size]
        iat_embedding_matrix: numpy array [iat_vocab_size, hidden_size]
        """
        super(Classifier, self).__init__()

        self.embedding = str2embedding[args.embedding](args, len(args.tokenizer.vocab))
        self.encoder = str2encoder[args.encoder](args)

        self.labels_num = args.labels_num
        self.pooling = args.pooling
        self.soft_targets = args.soft_targets
        self.soft_alpha = args.soft_alpha
        self.hidden_size = args.hidden_size

        packet_num = getattr(args, "packet_num", 8)

        # =========================
        # Statistical feature embeddings
        # =========================
        len_weight = torch.tensor(len_embedding_matrix, dtype=torch.float32)
        iat_weight = torch.tensor(iat_embedding_matrix, dtype=torch.float32)

        self.length_emb = nn.Embedding.from_pretrained(len_weight, freeze=False)
        self.time_emb = nn.Embedding.from_pretrained(iat_weight, freeze=False)

        stat_emb_dim = len_weight.shape[1]
        dir_matrix = np.array([
            [1] * stat_emb_dim,
            [-1] * stat_emb_dim,
            [0] * stat_emb_dim
        ])
        dir_weight = torch.tensor(dir_matrix, dtype=torch.float32)
        self.dir_emb = nn.Embedding.from_pretrained(dir_weight, freeze=False)

        # =========================
        # Modality encoders
        # =========================
        self.fusion_dim = 512
        self.payload_fc = nn.Linear(self.hidden_size, self.fusion_dim)

        # Input: [B, 3, packet_num, stat_emb_dim]
        # Output: [B, 1, 1, stat_emb_dim]
        self.stat_cnn = nn.Conv2d(3, 1, kernel_size=(packet_num, 1))
        self.stat_fc = nn.Linear(stat_emb_dim, self.fusion_dim)

        # =========================
        # Interaction-aware Dimension-wise Gated Fusion
        # z = [hp; hs; hp ⊙ hs; |hp - hs|]
        # g = sigmoid(MLP(z)), g ∈ R^512
        # hf = g ⊙ hp + (1 - g) ⊙ hs
        # =========================
        self.fusion_gate = nn.Sequential(
            nn.Linear(self.fusion_dim * 4, self.fusion_dim),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(self.fusion_dim, self.fusion_dim),
            nn.Sigmoid()
        )

        # Optional: keep the latest gate values for visualization.
        self.last_gate = None

        # =========================
        # Classifier
        # =========================
        self.classifier = nn.Sequential(
            nn.Linear(self.fusion_dim, self.hidden_size),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(self.hidden_size, self.hidden_size // 2),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(self.hidden_size // 2, self.labels_num)
        )

    def encode_payload(self, src, seg):
        emb = self.embedding(src, seg)
        enc_out = self.encoder(emb, seg)

        if self.pooling == "mean":
            payload_vec = torch.mean(enc_out, dim=1)
        elif self.pooling == "max":
            payload_vec = torch.max(enc_out, dim=1)[0]
        elif self.pooling == "last":
            payload_vec = enc_out[:, -1, :]
        else:
            payload_vec = enc_out[:, 0, :]

        payload_vec = torch.tanh(self.payload_fc(payload_vec))
        return payload_vec

    def encode_stat(self, length_idx, time_idx, direction_idx):
        len_emb = self.length_emb(length_idx)       # [B, packet_num, H]
        time_emb = self.time_emb(time_idx)          # [B, packet_num, H]
        dir_emb = self.dir_emb(direction_idx)       # [B, packet_num, H]

        stat_input = torch.stack([len_emb, time_emb, dir_emb], dim=1)  # [B, 3, packet_num, H]
        stat_out = self.stat_cnn(stat_input).squeeze(2).squeeze(1)     # [B, H]
        stat_vec = torch.tanh(self.stat_fc(stat_out))                  # [B, 512]
        return stat_vec

    def interaction_gate_fusion(self, payload_vec, stat_vec):
        interaction = payload_vec * stat_vec
        difference = torch.abs(payload_vec - stat_vec)

        fusion_input = torch.cat(
            [payload_vec, stat_vec, interaction, difference],
            dim=1
        )

        gate = self.fusion_gate(fusion_input)  # [B, 512]
        fusion_vec = gate * payload_vec + (1.0 - gate) * stat_vec

        self.last_gate = gate.detach()
        return fusion_vec

    def forward(self, src, tgt, seg, soft_tgt=None, length_idx=None, time_idx=None, direction_idx=None):
        mode = getattr(self, "ablation_mode", "full")

        # =========================
        # Payload modality
        # =========================
        if mode in ["full", "payload"]:
            payload_vec = self.encode_payload(src, seg)
        else:
            payload_vec = torch.zeros((src.size(0), self.fusion_dim), device=src.device)

        # =========================
        # Statistical modality
        # =========================
        has_stat = length_idx is not None and time_idx is not None and direction_idx is not None
        if mode in ["full", "stat"] and has_stat:
            stat_vec = self.encode_stat(length_idx, time_idx, direction_idx)
        else:
            stat_vec = torch.zeros_like(payload_vec)

        # =========================
        # Fusion
        # =========================
        if mode == "payload":
            fusion_vec = payload_vec
        elif mode == "stat":
            fusion_vec = stat_vec
        else:
            fusion_vec = self.interaction_gate_fusion(payload_vec, stat_vec)

        logits = self.classifier(fusion_vec)

        # =========================
        # Loss
        # =========================
        if tgt is not None:
            if self.soft_targets and soft_tgt is not None:
                loss = self.soft_alpha * nn.MSELoss()(logits, soft_tgt) + \
                       (1 - self.soft_alpha) * nn.NLLLoss()(F.log_softmax(logits, dim=-1), tgt.view(-1))
            else:
                loss = nn.NLLLoss()(F.log_softmax(logits, dim=-1), tgt.view(-1))
            return loss, logits
        else:
            return None, logits


def count_labels_num(path):
    labels_set = []
    with open(path, mode="r", encoding="utf-8") as f:
        csv_reader = csv.reader(f)
        next(csv_reader)
        for row in csv_reader:
            label = row[0].strip()
            labels_set.append(label)

    labels_set = sorted(list(set(labels_set)))
    label_dict = {label: i for i, label in enumerate(labels_set)}
    return len(labels_set), label_dict


def load_or_initialize_parameters_with_path(model, model_path=None):
    if model_path is not None:
        state_dict = torch.load(model_path, map_location="cpu")
        model.load_state_dict(state_dict, strict=False)
    else:
        for n, p in model.named_parameters():
            if "gamma" not in n and "beta" not in n:
                p.data.normal_(0, 0.02)


def build_optimizer(args, model):
    param_optimizer = list(model.named_parameters())
    no_decay = ["bias", "gamma", "beta"]

    optimizer_grouped_parameters = [
        {
            "params": [p for n, p in param_optimizer if not any(nd in n for nd in no_decay)],
            "weight_decay_rate": 0.01
        },
        {
            "params": [p for n, p in param_optimizer if any(nd in n for nd in no_decay)],
            "weight_decay_rate": 0.0
        }
    ]

    if args.optimizer in ["adamw"]:
        optimizer = str2optimizer[args.optimizer](optimizer_grouped_parameters, lr=args.learning_rate, correct_bias=False)
    else:
        optimizer = str2optimizer[args.optimizer](
            optimizer_grouped_parameters,
            lr=args.learning_rate,
            scale_parameter=False,
            relative_step=False
        )

    if args.scheduler in ["constant"]:
        scheduler = str2scheduler[args.scheduler](optimizer)
    elif args.scheduler in ["constant_with_warmup"]:
        scheduler = str2scheduler[args.scheduler](optimizer, args.train_steps * args.warmup)
    else:
        scheduler = str2scheduler[args.scheduler](optimizer, args.train_steps * args.warmup, args.train_steps)

    return optimizer, scheduler


def read_dataset(args, path, length_dictionary, iat_dictionary, label_dict):
    """
    Each entry:
    (src_ids, tgt, seg, length_ids, iat_ids, direction_ids)
    """
    dataset = []
    packet_num = getattr(args, "packet_num", 8)
    args.seq_length = 64 * packet_num

    with open(path, mode="r", encoding="utf-8") as f:
        csv_reader = csv.reader(f)
        _ = next(csv_reader, [])

        for row_idx, row in enumerate(csv_reader, start=1):
            tgt = row[0].strip()
            tgt = label_dict[tgt]

            payloads = json.loads(row[-1])

            cls_token_id = args.tokenizer.convert_tokens_to_ids(['[CLS]'])
            pad_token_id = args.tokenizer.convert_tokens_to_ids(['[PAD]'])

            src_token_id = cls_token_id.copy()

            for packet_payload in payloads:
                packet_payload = packet_payload.strip()
                packet_token = args.tokenizer.tokenize(packet_payload)
                packet_token_id = args.tokenizer.convert_tokens_to_ids(packet_token)
                src_token_id.extend(packet_token_id)

            seg = [1] * len(src_token_id)

            if len(src_token_id) >= args.seq_length:
                src_token_id = src_token_id[: args.seq_length]
                seg = seg[: args.seq_length]

            while len(src_token_id) < args.seq_length:
                src_token_id.append(pad_token_id[0])
                seg.append(0)

            lengths = [str(i) for i in json.loads(row[1])]
            length_ids = [length_dictionary[i] if i in length_dictionary else length_dictionary["UNK"] for i in lengths]
            if len(length_ids) >= packet_num:
                length_ids = length_ids[:packet_num]
            else:
                length_ids += [length_dictionary["PAD"]] * (packet_num - len(length_ids))

            directions_dictionary = {
                "1": 0,
                "-1": 1,
                "PAD": 2
            }
            raw_directions = json.loads(row[2])
            direction_ids = [directions_dictionary.get(str(i), 2) for i in raw_directions]
            if len(direction_ids) >= packet_num:
                direction_ids = direction_ids[:packet_num]
            else:
                direction_ids += [2] * (packet_num - len(direction_ids))

            iats = [str(i) for i in json.loads(row[3])]
            iat_ids = [iat_dictionary[i] if i in iat_dictionary else iat_dictionary["UNK"] for i in iats]
            if len(iat_ids) >= packet_num:
                iat_ids = iat_ids[:packet_num]
            else:
                iat_ids += [iat_dictionary["PAD"]] * (packet_num - len(iat_ids))

            entry = (src_token_id, tgt, seg, length_ids, iat_ids, direction_ids)
            dataset.append(entry)

    return dataset


def train_model(args, model, optimizer, scheduler, src_batch, tgt_batch, seg_batch,
                length_idx_batch=None, time_idx_batch=None, dir_idx_batch=None, soft_tgt_batch=None):
    model.zero_grad()

    src_batch = src_batch.to(args.device)
    tgt_batch = tgt_batch.to(args.device)
    seg_batch = seg_batch.to(args.device)

    if length_idx_batch is not None:
        length_idx_batch = length_idx_batch.to(args.device)
        time_idx_batch = time_idx_batch.to(args.device)
        dir_idx_batch = dir_idx_batch.to(args.device)

    if soft_tgt_batch is not None:
        soft_tgt_batch = soft_tgt_batch.to(args.device)

    loss, _ = model(
        src_batch,
        tgt_batch,
        seg_batch,
        soft_tgt_batch,
        length_idx=length_idx_batch,
        time_idx=time_idx_batch,
        direction_idx=dir_idx_batch
    )

    if torch.cuda.device_count() > 1:
        loss = torch.mean(loss)

    if args.fp16:
        with args.amp.scale_loss(loss, optimizer) as scaled_loss:
            scaled_loss.backward()
    else:
        loss.backward()

    optimizer.step()
    scheduler.step()

    current_lr = optimizer.param_groups[0]["lr"]
    return loss, current_lr


def evaluate(args, dataset, print_confusion_matrix=False):
    src = torch.LongTensor([sample[0] for sample in dataset])
    tgt = torch.LongTensor([sample[1] for sample in dataset])
    seg = torch.LongTensor([sample[2] for sample in dataset])

    length_idx = torch.LongTensor([sample[3] for sample in dataset])
    time_idx = torch.LongTensor([sample[4] for sample in dataset])
    direction_idx = torch.LongTensor([sample[5] for sample in dataset])

    batch_size = args.batch_size
    correct = 0
    confusion = torch.zeros(args.labels_num, args.labels_num, dtype=torch.long)

    args.model.eval()
    total_batches = (src.size(0) + batch_size - 1) // batch_size

    all_gates = []

    for i in range(total_batches):
        start = i * batch_size
        end = min((i + 1) * batch_size, src.size(0))

        src_batch = src[start:end].to(args.device)
        tgt_batch = tgt[start:end].to(args.device)
        seg_batch = seg[start:end].to(args.device)

        len_batch = length_idx[start:end].to(args.device)
        time_batch = time_idx[start:end].to(args.device)
        dir_batch = direction_idx[start:end].to(args.device)

        with torch.no_grad():
            _, logits = args.model(
                src_batch,
                tgt_batch,
                seg_batch,
                length_idx=len_batch,
                time_idx=time_batch,
                direction_idx=dir_batch
            )

        # Save gate values for visualization/statistics.
        real_model = args.model.module if isinstance(args.model, torch.nn.DataParallel) else args.model
        if getattr(real_model, "last_gate", None) is not None:
            all_gates.append(real_model.last_gate.cpu())

        pred = torch.argmax(F.softmax(logits, dim=1), dim=1)
        gold = tgt_batch

        for j in range(pred.size(0)):
            confusion[pred[j], gold[j]] += 1

        correct += torch.sum(pred == gold).item()

    metrics_dict = {}
    eps = 1e-9

    for i in range(args.labels_num):
        p = confusion[i, i].item() / (confusion[i, :].sum().item() + eps)
        r = confusion[i, i].item() / (confusion[:, i].sum().item() + eps)
        f1 = 0 if (p + r) == 0 else 2 * p * r / (p + r)
        metrics_dict[f"Label_{i}"] = {
            "precision": p,
            "recall": r,
            "f1": f1
        }

    macro_precision = sum([v["precision"] for v in metrics_dict.values()]) / args.labels_num
    macro_recall = sum([v["recall"] for v in metrics_dict.values()]) / args.labels_num
    macro_f1 = sum([v["f1"] for v in metrics_dict.values()]) / args.labels_num
    accuracy = correct / len(dataset)

    if print_confusion_matrix:
        out_path = args.output_model_path + ".metrics.tsv"
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "a+", encoding="utf-8") as f:
            f.write("===== Experiment Configuration =====\n")
            f.write(f"learning_rate\t{args.learning_rate}\n")
            f.write(f"batch_size\t{args.batch_size}\n")
            f.write(f"seq_length\t{args.packet_num * 64}\n")
            f.write(f"epochs\t{args.epochs_num}\n")
            f.write(f"hidden_size\t{args.hidden_size}\n")
            f.write(f"packet_num\t{getattr(args, 'packet_num', 8)}\n")
            f.write(f"labels_num\t{args.labels_num}\n")
            f.write(f"ablation_mode\t{args.ablation_mode}\n")
            f.write(f"pooling\t{args.pooling}\n")
            f.write(f"optimizer\t{args.optimizer}\n")
            f.write(f"scheduler\t{args.scheduler}\n")
            f.write(f"device\t{args.device}\n")
            f.write(f"model_path\t{args.output_model_path}\n")
            f.write("fusion\tInteraction-aware Dimension-wise Gated Fusion\n")
            f.write("\n")

            f.write("===== Confusion Matrix (rows=predicted, cols=true) =====\n")
            f.write("\t" + "\t".join([f"Label_{i}" for i in range(args.labels_num)]) + "\n")

            for i in range(args.labels_num):
                f.write(f"Label_{i}\t" + "\t".join(str(x.item()) for x in confusion[i]) + "\n")

            f.write("\n===== Precision / Recall / F1 =====\n")
            for label, scores in metrics_dict.items():
                f.write(
                    f"{label}\t"
                    f"P={scores['precision']:.6f}\t"
                    f"R={scores['recall']:.6f}\t"
                    f"F1={scores['f1']:.6f}\n"
                )

            f.write("\n===== Overall =====\n")
            f.write(f"Accuracy\t{accuracy:.6f}\n")
            f.write(f"Macro Precision\t{macro_precision:.6f}\n")
            f.write(f"Macro Recall\t{macro_recall:.6f}\n")
            f.write(f"Macro F1\t{macro_f1:.6f}\n")

            if len(all_gates) > 0:
                gates = torch.cat(all_gates, dim=0)
                gate_mean = gates.mean().item()
                payload_ratio = gate_mean
                stat_ratio = 1.0 - gate_mean
                f.write("\n===== Gate Statistics =====\n")
                f.write(f"Gate Mean Payload Contribution\t{payload_ratio:.6f}\n")
                f.write(f"Gate Mean Statistical Contribution\t{stat_ratio:.6f}\n")

    print(f"Macro Precision: {macro_precision:.4f}, Macro Recall={macro_recall:.4f}, Macro F1={macro_f1:.4f}")
    return accuracy, confusion, metrics_dict, macro_f1


def main():
    import matplotlib.pyplot as plt
    import torchvision
    import PIL.Image

    log_dir = os.environ.get("MULTIFLOW_LOG_DIR", "runs/multiflow")
    os.makedirs(log_dir, exist_ok=True)
    writer = SummaryWriter(log_dir)

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    finetune_opts(parser)
    print("开始加载数据集")

    parser.set_defaults(
        train_path="data/USTC-TFC/splits/train.csv",
        dev_path="data/USTC-TFC/splits/valid.csv",
        test_path="data/USTC-TFC/splits/test.csv",
        vocab_path="models/encryptd_vocab.txt",
        length_emb_path="wordembedding/len_embedding.npy",
        time_emb_path="wordembedding/iat_embedding.npy",
        len_dict_path="wordembedding/len_dict.pkl",
        iat_dict_path="wordembedding/iat_dict.pkl",
        epochs_num=20,
        learning_rate=2e-5,
    )

    parser.add_argument("--length_emb_path", default="wordembedding/len_embedding.npy")
    parser.add_argument("--time_emb_path", default="wordembedding/iat_embedding.npy")
    parser.add_argument("--len_dict_path", default="wordembedding/len_dict.pkl")
    parser.add_argument("--iat_dict_path", default="wordembedding/iat_dict.pkl")
    parser.add_argument("--packet_num", type=int, default=8, help="Number of packets for stat features and payload seq_length (seq_length = 64 * packet_num)")
    parser.add_argument("--ablation_mode", choices=["full", "payload", "stat"], default="full")
    parser.add_argument("--pooling", choices=["mean", "max", "first", "last"], default="first")
    parser.add_argument("--tokenizer", choices=["bert", "char", "space"], default="bert")
    parser.add_argument("--soft_targets", action="store_true")
    parser.add_argument("--soft_alpha", type=float, default=0.5)
    parser.add_argument("--reg_lambda", type=float, default=0.0, help="Reserved. Current version does not use gate regularization.")

    args = parser.parse_args()
    print(f"初始学习率 (--learning_rate): {args.learning_rate:.6f}")
    print(f"数据集路径: {args.train_path}")
    os.makedirs(os.path.dirname(os.path.abspath(args.output_model_path)), exist_ok=True)
    model_path = args.pretrained_model_path
    BEST_MODEL_TEMP_PATH = args.output_model_path + ".best_temp"

    args = load_hyperparam(args)
    set_seed(args.seed)

    args.labels_num, label_dict = count_labels_num(args.train_path)
    train_base_path = os.path.dirname(args.train_path)
    label_dict_path = os.path.join(train_base_path, "label.json")
    with open(label_dict_path, "w", encoding="utf-8") as f:
        json.dump(label_dict, f, ensure_ascii=False, indent=2)

    args.tokenizer = str2tokenizer[args.tokenizer](args)

    with open(args.len_dict_path, "rb") as f:
        length_vocab = pickle.load(f)
    with open(args.iat_dict_path, "rb") as f:
        time_vocab = pickle.load(f)

    len_embedding = np.load(args.length_emb_path)
    iat_embedding = np.load(args.time_emb_path)

    trainset = read_dataset(args, args.train_path, length_vocab, time_vocab, label_dict)
    devset = read_dataset(args, args.dev_path, length_vocab, time_vocab, label_dict)
    testset = read_dataset(args, args.test_path, length_vocab, time_vocab, label_dict) if args.test_path else None

    print(f"Train: {len(trainset)} | Dev: {len(devset)} | Test: {len(testset) if testset else 0}")

    random.shuffle(trainset)
    instances_num = len(trainset)
    batch_size = args.batch_size

    print("=" * 50)
    print(f"初始学习率 (--learning_rate): {args.learning_rate:.6f}")
    print(f"Training batch_size: {batch_size}")
    print(f"Training seq_length: {args.seq_length}")
    print("=" * 50)

    model = Classifier(args, len_embedding, iat_embedding)
    model.ablation_mode = args.ablation_mode

    load_or_initialize_parameters_with_path(model, model_path=model_path)

    args.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = model.to(args.device)

    args.train_steps = int(instances_num * args.epochs_num / batch_size) + 1
    optimizer, scheduler = build_optimizer(args, model)

    if args.fp16:
        from apex import amp
        model, optimizer = amp.initialize(model, optimizer, opt_level=args.fp16_opt_level)
        args.amp = amp

    if torch.cuda.device_count() > 1:
        model = torch.nn.DataParallel(model)

    args.model = model

    best_dev_F1 = 0.0
    best_epoch = 0
    print("Start training.")

    src = torch.LongTensor([ex[0] for ex in trainset])
    tgt = torch.LongTensor([ex[1] for ex in trainset])
    seg = torch.LongTensor([ex[2] for ex in trainset])
    length_idx = torch.LongTensor([ex[3] for ex in trainset])
    time_idx = torch.LongTensor([ex[4] for ex in trainset])
    direction_idx = torch.LongTensor([ex[5] for ex in trainset])

    for epoch in tqdm.tqdm(range(1, args.epochs_num + 1)):
        model.train()
        total_loss = 0.0
        num_batches = (src.size(0) + batch_size - 1) // batch_size

        for i in range(num_batches):
            start = i * batch_size
            end = min((i + 1) * batch_size, src.size(0))

            src_batch = src[start:end]
            tgt_batch = tgt[start:end]
            seg_batch = seg[start:end]
            len_batch = length_idx[start:end]
            time_batch = time_idx[start:end]
            dir_batch = direction_idx[start:end]

            loss, current_lr = train_model(
                args,
                model,
                optimizer,
                scheduler,
                src_batch,
                tgt_batch,
                seg_batch,
                length_idx_batch=len_batch,
                time_idx_batch=time_batch,
                dir_idx_batch=dir_batch
            )

            if i % 10 == 0:
                print(f"epoches:{epoch},steps:{i},loss:{loss.item()},lr:{current_lr}")

            total_loss += loss.item()
            global_step = epoch * num_batches + i
            writer.add_scalar("Loss/train", loss.item(), global_step)
            writer.add_scalar("LearningRate/train", current_lr, global_step)

        acc, confusion, metrics_dict, macro_f1 = evaluate(args, devset)

        print(f"Epoch {epoch} Dev Accuracy: {acc:.4f}, Macro F1: {macro_f1:.4f}")
        dev_F1 = macro_f1
        writer.add_scalar("F1/dev", dev_F1, epoch)

        for i in range(args.labels_num):
            eps = 1e-9
            p = confusion[i, i].item() / (confusion[i, :].sum().item() + eps)
            r = confusion[i, i].item() / (confusion[:, i].sum().item() + eps)
            f1 = 0 if (p + r) == 0 else 2 * p * r / (p + r)
            writer.add_scalar(f"Precision/Label_{i}", p, epoch)
            writer.add_scalar(f"Recall/Label_{i}", r, epoch)
            writer.add_scalar(f"F1/Label_{i}", f1, epoch)

        if dev_F1 > best_dev_F1:
            best_dev_F1 = dev_F1
            best_epoch = epoch
            print(f"--- Epoch {epoch}: New best Dev F1: {best_dev_F1:.4f}. Saving best model temporarily to {BEST_MODEL_TEMP_PATH} ---")

            if torch.cuda.device_count() > 1:
                save_model(model.module, BEST_MODEL_TEMP_PATH)
            else:
                save_model(model, BEST_MODEL_TEMP_PATH)

    if testset is not None:
        print("\nTest set evaluation.")
        print(f"Loading best model from Epoch {best_epoch} with Dev F1: {best_dev_F1:.4f}")

        if torch.cuda.device_count() > 1:
            model.module.load_state_dict(torch.load(BEST_MODEL_TEMP_PATH))
            test_model = model.module
        else:
            model.load_state_dict(torch.load(BEST_MODEL_TEMP_PATH))
            test_model = model

        args.model = model
        acc, confusion, metrics_dict, macro_f1 = evaluate(args, testset, print_confusion_matrix=True)
        writer.add_scalar("Accuracy/test", acc, 0)
        writer.add_scalar("F1/test", macro_f1, 0)

        fig, ax = plt.subplots(figsize=(8, 8))
        cax = ax.matshow(confusion.numpy(), cmap="Blues")
        plt.colorbar(cax)
        ax.set_xlabel("True label")
        ax.set_ylabel("Predicted label")
        ax.set_title("Confusion matrix (Test)")

        buf = io.BytesIO()
        plt.savefig(buf, format="png")
        buf.seek(0)
        image = PIL.Image.open(buf)
        image = torchvision.transforms.ToTensor()(image)
        writer.add_image("ConfusionMatrix/test", image, 0)
        buf.close()
        plt.close(fig)

    writer.close()


if __name__ == "__main__":
    main()
