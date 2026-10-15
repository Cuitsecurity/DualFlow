#!/usr/bin/env bash
# Usage: bash scripts/train.sh DATASET SPLIT_DIR [extra training arguments]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
name="${1:?Usage: train.sh DATASET SPLIT_DIR [extra arguments]}"
splits="${2:?Provide the directory containing train.csv, valid.csv and test.csv}"
shift 2
mkdir -p "outputs/$name" "runs/$name"
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
export MULTIFLOW_LOG_DIR="${MULTIFLOW_LOG_DIR:-runs/$name}"
python3 -u src/models/train.py \
  --train_path "$splits/train.csv" --dev_path "$splits/valid.csv" \
  --test_path "$splits/test.csv" \
  --vocab_path models/encryptd_vocab.txt \
  --pretrained_model_path models/pre-trained_model.bin \
  --output_model_path "outputs/$name/model.bin" \
  --config_path models/bert/paper_config.json \
  --packet_num 8 --epochs_num 20 --batch_size 16 \
  --learning_rate 2e-5 --warmup 0.15 --ablation_mode full \
  "$@" 2>&1 | tee "outputs/$name/train.log"
