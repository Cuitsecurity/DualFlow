#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

BASE = "/3241903007/workstation/AnomalyTrafficDetection/MutilFlow/20261014/USTC-TFC2016"

BASE = os.environ.get("MULTIFLOW_WORK_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW = os.environ.get("MULTIFLOW_RAW_DIR", os.path.join(BASE, "raw", "source"))
OUT = os.path.join(BASE, "splitcap")
TOOL = os.environ.get("MULTIFLOW_SPLITCAP", os.path.join(BASE, "tools", "SplitCap.exe"))

LOG_DIR = os.path.join(BASE, "logs")
RUN_LOG = os.path.join(LOG_DIR, "03_splitcap_parallel.log")
MANIFEST = os.path.join(LOG_DIR, "03_splitcap_manifest.tsv")
COUNT_FILE = os.path.join(LOG_DIR, "03_splitcap_label_counts.txt")

# 同时运行几个 SplitCap 进程
WORKERS = 4


# ============================================================
# 24 raw PCAP -> 20 labels
# ============================================================

TASKS = [
    # Benign
    ("BitTorrent", "Benign/BitTorrent.pcap"),
    ("FTP", "Benign/FTP.pcap"),
    ("Facetime", "Benign/Facetime.pcap"),
    ("Gmail", "Benign/Gmail.pcap"),
    ("MySQL", "Benign/MySQL.pcap"),
    ("Outlook", "Benign/Outlook.pcap"),

    ("SMB", "Benign/SMB/SMB/SMB-1.pcap"),
    ("SMB", "Benign/SMB/SMB/SMB-2.pcap"),

    ("Skype", "Benign/Skype.pcap"),

    ("Weibo", "Benign/Weibo/Weibo/Weibo-1.pcap"),
    ("Weibo", "Benign/Weibo/Weibo/Weibo-2.pcap"),
    ("Weibo", "Benign/Weibo/Weibo/Weibo-3.pcap"),
    ("Weibo", "Benign/Weibo/Weibo/Weibo-4.pcap"),

    ("WorldOfWarcraft", "Benign/WorldOfWarcraft.pcap"),

    # Malware
    ("Cridex", "Malware/Cridex/Cridex.pcap"),
    ("Geodo", "Malware/Geodo/Geodo.pcap"),
    ("Htbot", "Malware/Htbot/Htbot.pcap"),
    ("Miuref", "Malware/Miuref.pcap"),
    ("Neris", "Malware/Neris/Neris.pcap"),
    ("Nsis-ay", "Malware/Nsis-ay/Nsis-ay.pcap"),
    ("Shifu", "Malware/Shifu/Shifu.pcap"),
    ("Tinba", "Malware/Tinba.pcap"),
    ("Virut", "Malware/Virut/Virut.pcap"),
    ("Zeus", "Malware/Zeus.pcap"),
]


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def count_pcaps(directory):
    count = 0

    for root, dirs, files in os.walk(directory):
        for name in files:
            if name.lower().endswith((".pcap", ".pcapng")):
                count += 1

    return count


def process_task(task_id, label, relative_path):
    src = os.path.join(RAW, relative_path)

    source_name = os.path.splitext(os.path.basename(src))[0]

    # 保留源文件层级，防止：
    # SMB-1 / SMB-2
    # Weibo-1 / Weibo-2 / ...
    # 输出文件发生冲突
    dest = os.path.join(
        OUT,
        label,
        source_name
    )

    if not os.path.isfile(src):
        return {
            "id": task_id,
            "label": label,
            "source": src,
            "output": dest,
            "sessions": 0,
            "seconds": 0,
            "status": "SOURCE_NOT_FOUND",
            "stdout": "",
        }

    os.makedirs(dest, exist_ok=True)

    # 防止不小心覆盖/混入已有结果
    existing = count_pcaps(dest)

    if existing > 0:
        return {
            "id": task_id,
            "label": label,
            "source": src,
            "output": dest,
            "sessions": existing,
            "seconds": 0,
            "status": "SKIPPED_EXISTING",
            "stdout": "",
        }

    cmd = [
        "mono",
        TOOL,
        "-r", src,
        "-s", "session",
        "-o", dest,
    ]

    start = time.time()

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

        elapsed = time.time() - start

        sessions = count_pcaps(dest)

        status = "OK" if result.returncode == 0 else f"FAILED_{result.returncode}"

        return {
            "id": task_id,
            "label": label,
            "source": src,
            "output": dest,
            "sessions": sessions,
            "seconds": elapsed,
            "status": status,
            "stdout": result.stdout or "",
        }

    except Exception as e:
        elapsed = time.time() - start

        return {
            "id": task_id,
            "label": label,
            "source": src,
            "output": dest,
            "sessions": count_pcaps(dest),
            "seconds": elapsed,
            "status": "EXCEPTION",
            "stdout": repr(e),
        }


def main():

    os.makedirs(OUT, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.isdir(RAW):
        raise RuntimeError(f"RAW directory does not exist: {RAW}")

    if not os.path.isfile(TOOL):
        raise RuntimeError(f"SplitCap does not exist: {TOOL}")

    print("=" * 90, flush=True)
    print("USTC-TFC2016 SplitCap reconstruction", flush=True)
    print(f"Started : {timestamp()}", flush=True)
    print(f"RAW     : {RAW}", flush=True)
    print(f"OUT     : {OUT}", flush=True)
    print(f"TOOL    : {TOOL}", flush=True)
    print(f"WORKERS : {WORKERS}", flush=True)
    print(f"TASKS   : {len(TASKS)}", flush=True)
    print("MODE    : SplitCap -s session", flush=True)
    print("=" * 90, flush=True)

    start_all = time.time()

    results = []

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:

        futures = {}

        for i, (label, relative_path) in enumerate(TASKS, 1):

            future = executor.submit(
                process_task,
                i,
                label,
                relative_path
            )

            futures[future] = (i, label, relative_path)

        completed = 0

        for future in as_completed(futures):

            result = future.result()
            results.append(result)

            completed += 1

            print(
                f"[DONE {completed:02d}/{len(TASKS)}] "
                f"{result['label']:<16} "
                f"{os.path.basename(result['source']):<22} "
                f"sessions={result['sessions']:<8} "
                f"time={result['seconds']:.1f}s "
                f"status={result['status']}",
                flush=True
            )

            # 保存这个任务自己的 SplitCap 输出
            if result["stdout"]:
                task_log = os.path.join(
                    LOG_DIR,
                    f"splitcap_task_{result['id']:02d}_"
                    f"{result['label']}_"
                    f"{os.path.basename(result['source'])}.log"
                )

                with open(task_log, "w", encoding="utf-8", errors="replace") as f:
                    f.write(result["stdout"])

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    results.sort(key=lambda x: x["id"])

    with open(MANIFEST, "w", newline="") as f:

        writer = csv.writer(f, delimiter="\t")

        writer.writerow([
            "task_id",
            "label",
            "source",
            "output_dir",
            "sessions",
            "seconds",
            "status",
        ])

        for r in results:
            writer.writerow([
                r["id"],
                r["label"],
                r["source"],
                r["output"],
                r["sessions"],
                f"{r['seconds']:.3f}",
                r["status"],
            ])

    # --------------------------------------------------------
    # 20类统计
    # --------------------------------------------------------

    label_counts = {}

    for label, _ in TASKS:
        label_counts[label] = count_pcaps(
            os.path.join(OUT, label)
        )

    with open(COUNT_FILE, "w") as f:

        for label in sorted(label_counts):
            line = f"{label:<20} {label_counts[label]:>10}"
            f.write(line + "\n")

    print()
    print("=" * 90)
    print("PER-LABEL SESSION COUNTS")
    print("=" * 90)

    for label in sorted(label_counts):
        print(
            f"{label:<20} "
            f"{label_counts[label]:>10}"
        )

    total_sessions = sum(label_counts.values())

    elapsed_all = time.time() - start_all

    ok = sum(
        1 for r in results
        if r["status"] in ("OK", "SKIPPED_EXISTING")
    )

    failed = len(results) - ok

    print()
    print("=" * 90)
    print("FINAL SUMMARY")
    print("=" * 90)

    print(f"Raw PCAP tasks : {len(TASKS)}")
    print(f"Completed      : {ok}")
    print(f"Failed         : {failed}")
    print(f"Labels         : {len(label_counts)}")
    print(f"Total sessions : {total_sessions}")
    print(f"Elapsed        : {elapsed_all:.1f}s")
    print(f"Finished       : {timestamp()}")

    print()
    print("Manifest:")
    print(MANIFEST)

    print()
    print("Label counts:")
    print(COUNT_FILE)

    if failed:
        print()
        print("[WARNING] Some tasks failed. Check manifest and task logs.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
