# MultiFlow

**MultiFlow: Robust Multimodal Representation Learning for Encrypted Network Traffic Classification**

MultiFlow combines ET-BERT payload representations and CNN-encoded packet statistics (length, direction and inter-arrival time) through gated fusion for encrypted traffic classification.

This repository follows one workflow:

**Dataset → split PCAPs into sessions → extract features → split the dataset → train and test.**

## Repository Structure

```text
src/
├── preprocessing/
│   ├── split_pcap.py       # Raw PCAPs → session PCAPs (SplitCap)
│   └── split_dataset.py    # Feature CSV → train/dev/test
├── data/
│   └── extract_features.py # Session PCAPs → payload + statistical features
└── models/
    └── train.py            # MultiFlow training and best-checkpoint testing
scripts/train.sh            # Training command with explicit settings
models/bert/paper_config.json
uer/                        # Required ET-BERT/UER support modules
licenses/UER-LICENSE        # Upstream license
```

The `uer/` files are dependencies imported by the existing model. Historical experiments, duplicate preprocessing variants and unrelated models are omitted. The model computation and feature extraction logic are preserved from the research project; the scripts expose paths for use on another machine.

## 1. Datasets

| Dataset | Classification task | Classes | Train | Dev | Test |
|---|---|---:|---:|---:|---:|
| CSTNET-TLS-1.3 | TLS 1.3 application classification | 120 | 37,098 | 4,637 | 4,637 |
| ISCX-VPN-Service | VPN service classification | 6 | 1,780 | 222 | 222 |
| ISCX-VPN-App | VPN application classification | 14 | 2,695 | 337 | 337 |
| USTC-TFC | 10 benign and 10 malware categories | 20 | 6,032 | 754 | 754 |

These are the retained flow counts reported in the paper. Raw datasets and prepared CSVs are not included. Obtain the captures from the original providers and arrange them by class:

```text
/path/to/raw/
├── class_a/
│   └── capture_a.pcap
└── class_b/
    └── capture_b.pcap
```

ISCX-VPN-Service and ISCX-VPN-App use different label mappings. Prepare separate class directories for these two tasks; the exact paper label mappings and original split files still need to be supplied. CSTNET captures that are already split into individual flows can skip the PCAP splitting step.

## 2. Installation

Use Linux and Python 3.10. Install a matching PyTorch/torchvision pair for your CUDA driver, then the remaining dependencies:

```bash
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
sudo apt-get install tshark mono-runtime
```

TShark is required by flowcontainer. Mono runs the external **SplitCap.exe** tool; provide that executable separately. The inspected environment uses Python 3.10.12 and PyTorch 2.3.0; dependency ranges are not an exact environment lockfile.

Run all commands below from the repository root.

## 3. Split PCAPs into Sessions

The splitter invokes `mono SplitCap.exe -r INPUT -s session -o OUTPUT` for each capture, preserving its class directory:

```bash
python3 src/preprocessing/split_pcap.py \
  --input-dir /path/to/raw \
  --output-dir data/USTC-TFC/flows \
  --splitcap /path/to/SplitCap.exe
```

Outputs are arranged as `data/USTC-TFC/flows/<class>/<capture>/...pcap`. The raw captures are kept unchanged. Completed captures are skipped on rerun; unfinished output requires a fresh output directory. For other datasets, substitute their labeled capture directories and output names.

## 4. Extract Features

```bash
python3 src/data/extract_features.py \
  --pcap-root data/USTC-TFC/flows \
  --output-dir data/USTC-TFC/features
```

The input must contain one directory per class. For already split CSTNET flows, pass their root directly to `--pcap-root`.

The existing extractor:

- Samples up to 500 session PCAPs per class (`--max-flows-per-label`, seed 40).
- Extracts packet lengths, directions and IATs using flowcontainer.
- Multiplies IATs by 100 and rounds to one decimal place.
- Randomizes IP addresses/ports in the packet representation and generates byte-bigram strings.
- Retains up to 40 packets; the training reader applies its K-dependent sequence limit.

Output: `data/USTC-TFC/features/all_flows.csv`, with columns in this order:

```text
label,lengths,directions,iats,payloads
```

The feature columns contain JSON arrays. The existing implementation takes full packet bytes before bigram generation and limits the number of emitted segments to 64; it does not strictly strip all headers. One input PCAP may produce multiple flow records. These behaviors are retained rather than replaced with a new extractor. A processed-file manifest supports resuming; use a new output directory for an independent extraction run.

### Split Features into Train / Dev / Test

```bash
python3 src/preprocessing/split_dataset.py \
  --input data/USTC-TFC/features/all_flows.csv \
  --output-dir data/USTC-TFC/splits
```

This uses the existing stratified 80/10/10 split with seeds 41 and 42. It prints the split sizes and writes `train.csv`, `valid.csv` and `test.csv`. Each class needs enough samples for stratification. Existing split files are overwritten; preserve original paper splits separately. Reprocessing captures can produce counts different from the paper's table.

## 5. Train and Test

Place the required vocabulary, pretrained checkpoint and matched attribute-value dictionaries/embeddings at:

```text
models/encryptd_vocab.txt
models/pre-trained_model.bin
wordembedding/len_dict.pkl
wordembedding/iat_dict.pkl
wordembedding/len_embedding.npy
wordembedding/iat_embedding.npy
```

These assets are not included in Git. The dictionaries and embedding matrices must come from the same release; `PAD` and `UNK` entries are required. Public download links still need to be provided.

```bash
CUDA_VISIBLE_DEVICES=0 bash scripts/train.sh USTC-TFC data/USTC-TFC/splits
```

For another dataset, use its corresponding split directory:

```bash
CUDA_VISIBLE_DEVICES=0 bash scripts/train.sh CSTNET-TLS-1.3 data/CSTNET-TLS-1.3/splits
CUDA_VISIBLE_DEVICES=0 bash scripts/train.sh ISCX-VPN-Service data/ISCX-VPN-Service/splits
CUDA_VISIBLE_DEVICES=0 bash scripts/train.sh ISCX-VPN-App data/ISCX-VPN-App/splits
```

The wrapper invokes `src/models/train.py` with:

| Setting | Value |
|---|---|
| Packets per flow | 8 |
| Payload token budget | 64 × K, 512 at K=8 |
| Epochs | 20 |
| Learning rate | 2e-5 |
| Batch size | 16 |
| Warmup ratio | 0.15 |
| Seed | 7 |
| Scheduler | Cosine |

Additional arguments can override training settings or asset paths:

```bash
CUDA_VISIBLE_DEVICES=0 bash scripts/train.sh USTC-run2 data/USTC-TFC/splits \
  --batch_size 8 --pretrained_model_path /path/to/pre-trained_model.bin
```

The supplied JSON config sets Transformer dropout to 0.5; the preserved gate/classifier use dropout 0.2. JSON values override matching CLI settings. This is the available code snapshot, so exact paper numbers also require the matching original splits, assets and code/checkpoint version.

### Test Outputs

Testing happens automatically after training. The script reloads the checkpoint with the best **validation Macro-F1**, evaluates the test CSV, and reports **Macro Precision / Macro Recall / Macro-F1**.

```text
outputs/USTC-TFC/train.log             # Console log
outputs/USTC-TFC/model.bin.best_temp   # Best checkpoint (actual saved filename)
outputs/USTC-TFC/model.bin.metrics.tsv # Test metrics and confusion matrix
runs/USTC-TFC/                        # TensorBoard events
```

```bash
grep -E 'Macro Precision|Macro Recall|Macro F1' outputs/USTC-TFC/train.log
tensorboard --logdir runs
```

Use a different run name for each experiment. The selected entry point has no standalone test-only flag. If an existing TensorBoard installation raises `Descriptors cannot not be created directly`, set `export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` before running, or install compatible TensorBoard/protobuf versions in your virtual environment.

## Assets to Add

- Original dataset selections/splits and ISCX service/application label mappings.
- Download links for the ET-BERT vocabulary/checkpoint and four matched AVD files.
- Paper-specific trained MultiFlow checkpoints, if independent checkpoint evaluation is to be released.
- Final paper URL and citation metadata.

The source release does not include raw captures, generated datasets, weights or experiment logs. ET-BERT/UER support code retains its upstream license; an author-selected license for the original project code still needs to be added.
