#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
from pathlib import Path

INPUT_ROOT = Path("/3241903007/daisy/dataset/USTC-TFC2016")

OUTPUT_ROOT = Path(
    "/3241903007/workstation/AnomalyTrafficDetection/"
    "MutilFlow/datasets/splited/USTC_splitcap_test"
)

SPLITCAP = "/3241903007/daisy/SplitCap.exe"

MAX_FLOWS_PER_LABEL = 500

OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

results = []

for category in ["Benign", "Malware"]:

    category_dir = INPUT_ROOT / category

    for label_dir in sorted(category_dir.iterdir()):

        if not label_dir.is_dir():
            continue

        label = label_dir.name
        output_dir = OUTPUT_ROOT / label
        output_dir.mkdir(parents=True, exist_ok=True)

        pcap_files = sorted(label_dir.glob("*.pcap"))

        print()
        print("=" * 80)
        print(f"Category : {category}")
        print(f"Label    : {label}")
        print(f"PCAPs    : {len(pcap_files)}")

        for pcap in pcap_files:

            # 每个源 PCAP 单独建目录，防止多个源文件产生同名 session
            current_output = output_dir / pcap.stem
            current_output.mkdir(parents=True, exist_ok=True)

            # 已经产生结果则跳过，方便中断后继续
            existing = list(current_output.rglob("*.pcap"))

            if existing:
                print(
                    f"Skip     : {pcap.name} "
                    f"({len(existing)} sessions already exist)"
                )
                continue

            print(f"Splitting: {pcap}")

            cmd = [
                "mono",
                SPLITCAP,
                "-r", str(pcap),
                "-s", "session",
                "-o", str(current_output)
            ]

            result = subprocess.run(cmd)

            if result.returncode != 0:
                print(f"ERROR    : SplitCap failed for {pcap}")
                continue

        # 统计这个类别全部 session
        flow_files = list(output_dir.rglob("*.pcap"))
        raw_count = len(flow_files)
        capped_count = min(raw_count, MAX_FLOWS_PER_LABEL)

        results.append(
            (category, label, raw_count, capped_count)
        )

        print(f"Raw      : {raw_count}")
        print(f"Cap 500  : {capped_count}")


print()
print("=" * 80)
print("FINAL RESULT")
print("=" * 80)

total_raw = 0
total_capped = 0

for category, label, raw_count, capped_count in results:

    total_raw += raw_count
    total_capped += capped_count

    print(
        f"{category:8s} | "
        f"{label:25s} | "
        f"{raw_count:8d} -> {capped_count:3d}"
    )

print("-" * 80)
print(f"Classes          : {len(results)}")
print(f"Raw sessions     : {total_raw}")
print(f"After cap=500    : {total_capped}")
print(f"Expected         : 7540")
print(f"Difference       : {total_capped - 7540}")

if total_capped == 7540:
    print()
    print("*** EXACT MATCH: 7540 ***")
