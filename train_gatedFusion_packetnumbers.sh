#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_CMD=python3
PYTHON_SCRIPT="/3241903007/workstation/AnomalyTrafficDetection/MutilFlow/code_5_28/classfiy_New_wiseGatedFusion.py"

packet_numbers=(
  1 2 3 4 5 6 7 8
)

LOG_DIR="${SCRIPT_DIR}/logs/packets"
mkdir -p "$LOG_DIR"
echo "#################"
for pa in "${packet_numbers[@]}"; do
  echo "================================================================"
  echo "Running training with packet_num=$pa"
  echo "================================================================"

  log_file="$LOG_DIR/train_packet_${pa}.log"
  $PYTHON_CMD -u "$PYTHON_SCRIPT" --packet_num "$pa" 2>&1 | tee "$log_file"

done
