import os
import json
import pickle
import numpy as np

# ===================== 配置 =====================
embedding_dim = 768  # embedding 维度
packet_num = 40      # 每条流最多 packet 数

# --- 数据集路径 ---
all_paths = [
    # IOT
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/IOT/tsv/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/IOT/tsv/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/IOT/tsv/tsv/flow/test_dataset.tsv",

    # USTC
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/USTC-TFC2016/tsv/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/USTC-TFC2016/tsv/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/USTC-TFC2016/tsv/tsv/flow/test_dataset.tsv",

    # CSTNET
    "/3241903007/workstation/AnomalyTrafficDetection/dataset/cstnet-tls1.3/forTrain/train_dataset_fixed.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/dataset/cstnet-tls1.3/forTrain/valid_dataset_fixed.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/dataset/cstnet-tls1.3/forTrain/test_dataset_fixed.tsv",

    # ISCX-VPN-app
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-app/tsv/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-app/tsv/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-app/tsv/tsv/flow/test_dataset.tsv",

    # ISCX-VPN-service
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-6-Service/tsv/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-6-Service/tsv/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-VPN-6-Service/tsv/tsv/flow/test_dataset.tsv",

    # ISCX-TOR
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor/tsv/Tor/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor/tsv/Tor/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor/tsv/Tor/tsv/flow/test_dataset.tsv",
     # ISCX-TOR-new
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor-new/tsv/tsv/flow/train_1.0_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor-new/tsv/tsv/flow/valid_dataset.tsv",
    "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/datasets/own_lyj/ISCX-Tor-new/tsv/tsv/flow/test_dataset.tsv",

]

# --- 输出路径 ---
len_dict_path = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/len_dict.pkl"
iat_dict_path = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/iat_dict.pkl"
dir_dict_path = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/dir_dict.pkl"

length_emb_path = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/len_embedding.npy"
time_emb_path   = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/iat_embedding.npy"
dir_emb_path    = "/3241903007/workstation/AnomalyTrafficDetection/FlowVocab/dataset/AttributeValueDictionary/dir_embedding.npy"

# ===================== 收集 length / time / direction =====================
len_set = set()
iat_set = set()
dir_set = set([-1, 0, 1])  # direction 固定
for path in all_paths:
    if not os.path.exists(path):
        print(f"Warning: 文件不存在 {path}, 已跳过")
        continue

    with open(path, 'r', encoding='utf-8') as f:
        columns = {}
        for line_id, line in enumerate(f):
            line = line.strip()
            if line_id == 0:
                for i, col_name in enumerate(line.split("\t")):
                    columns[col_name] = i
                continue

            row = line.split("\t")
            try:
                flow = json.loads(row[columns["text_a"]].replace("'", '"'))
            except:
                continue

            lengths = flow.get("length", [])[:packet_num]
            times   = flow.get("time", [])[:packet_num]
            directions = flow.get("direction", [])[:packet_num]  # 已固定为 -1/0/1

            len_set.update(lengths)
            iat_set.update(times)

# ===================== 构建词典 =====================
len_list = sorted(list(len_set))
iat_list = sorted(list(iat_set))
dir_list = sorted(list(dir_set))

len_dict = {v:i for i,v in enumerate(len_list)}
iat_dict = {v:i for i,v in enumerate(iat_list)}
dir_dict = {v:i for i,v in enumerate(dir_list)}

# ===================== 初始化 embedding =====================
len_emb = np.random.normal(0, 0.02, (len(len_dict), embedding_dim)).astype(np.float32)
iat_emb = np.random.normal(0, 0.02, (len(iat_dict), embedding_dim)).astype(np.float32)
dir_emb = np.random.normal(0, 0.02, (len(dir_dict), embedding_dim)).astype(np.float32)

# ===================== 保存 =====================
os.makedirs(os.path.dirname(len_dict_path), exist_ok=True)

with open(len_dict_path, 'wb') as f:
    pickle.dump(len_dict, f)
with open(iat_dict_path, 'wb') as f:
    pickle.dump(iat_dict, f)
with open(dir_dict_path, 'wb') as f:
    pickle.dump(dir_dict, f)

np.save(length_emb_path, len_emb)
np.save(time_emb_path, iat_emb)
np.save(dir_emb_path, dir_emb)

print("词库和 embedding 已生成完成：")
print(f"Length vocab: {len(len_dict)} | IAT vocab: {len(iat_dict)} | Direction vocab: {len(dir_dict)} | Embedding dim: {embedding_dim}")