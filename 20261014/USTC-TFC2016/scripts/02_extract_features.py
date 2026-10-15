#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
USTC-TFC2016 MultiFlow reconstruction - serial feature extraction

重建语义：
1. random.seed(40)
2. label 使用 os.listdir() 原始顺序，不排序
3. PCAP 使用 os.walk() 原始顺序，不排序
4. 如果 selected_pcaps.json 已存在，直接复用，不重新抽样
5. 如果不存在，则每类先 random.sample(..., 500)
6. 抽样完成后才进行特征提取
7. 特征提取直接调用历史 multiflow_batch_feature_extractor_historical.py
8. feature_results == -1 -> 丢弃，不补抽
9. 单线程串行执行，与历史特征提取执行方式更接近
10. reconstruction 不宣称恢复历史 May-27 精确 RNG 状态

关键数据语义：
    splitcap 中的每个 PCAP 已经代表一个切分后的 flow。

    因此：
        1 selected flow PCAP
            -> 最多 1 条最终 CSV feature row

    每个 label：
        selected <= 500
        csv_rows <= 500
        csv_rows == successful_pcaps

注意：
    历史 get_flow_features() 在少数单流 PCAP 上可能返回多个
    internal feature records。

    当前 semantic reconstruction 不把这些 internal records
    展开成多个训练样本，而只保留第一个 record，使数据集保持：

        one selected flow -> one sample

    同时将 raw_feature_count > 1 的 PCAP 写入：
        logs/04_multi_record_pcaps.tsv

    以便后续分析 extractor 为什么会对单流 PCAP 返回多个 record。
"""

import os
import sys
import csv
import json
import random
import time
import traceback

from datetime import datetime


# ============================================================
# 配置
# ============================================================

BASE = (
    "/3241903007/workstation/AnomalyTrafficDetection/"
    "MutilFlow/20261014/USTC-TFC2016"
)

PCAP_ROOT = os.path.join(
    BASE,
    "splitcap"
)

BASE = os.environ.get("MULTIFLOW_WORK_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PCAP_ROOT = os.environ.get("MULTIFLOW_PCAP_ROOT", os.path.join(BASE, "splitcap"))

OUTPUT_DIR = os.path.join(
    BASE,
    "features"
)

LOG_DIR = os.path.join(
    BASE,
    "logs"
)

HISTORICAL_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_CSV = os.path.join(
    OUTPUT_DIR,
    "all_flows.csv"
)

PROCESSED_LOG = os.path.join(
    OUTPUT_DIR,
    "processed_files.json"
)

SELECTED_LOG = os.path.join(
    OUTPUT_DIR,
    "selected_pcaps.json"
)

SUMMARY_JSON = os.path.join(
    OUTPUT_DIR,
    "feature_summary.json"
)

SUMMARY_TSV = os.path.join(
    LOG_DIR,
    "04_feature_summary.tsv"
)

RUN_INFO = os.path.join(
    LOG_DIR,
    "04_feature_run_info.txt"
)

FAIL_LOG = os.path.join(
    LOG_DIR,
    "04_feature_failures.tsv"
)

MULTI_RECORD_LOG = os.path.join(
    LOG_DIR,
    "04_multi_record_pcaps.tsv"
)


SEED = 40

# 每个类别最多选择 500 个已经切分好的 flow PCAP
MAX_FLOWS_PER_LABEL = 500

# 串行执行
WORKERS = 1


# ============================================================
# 基础函数
# ============================================================

def now():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S %z"
    )


def collect_pcaps(input_dir):
    """
    故意不排序。

    与历史代码：
        os.listdir()
        os.walk()

    的原始枚举行为保持一致。
    """

    all_pcaps = []

    for root, dirs, files in os.walk(
        input_dir
    ):

        for filename in files:

            if (
                filename.endswith(".pcap")
                or
                filename.endswith(".pcapng")
            ):

                all_pcaps.append(
                    os.path.join(
                        root,
                        filename
                    )
                )

    return all_pcaps


# ============================================================
# 单个 flow PCAP 特征提取
# ============================================================

def extract_one(task):
    """
    一个 selected PCAP 在当前数据定义中就是一个
    已经切分完成的 flow。

    数据集语义：

        1 selected flow PCAP
            -> 1 feature row

    因此：

    1. feature_results == -1
       -> 提取失败
       -> 0 row

    2. feature_results 有效
       -> 最终只产生 1 row

    3. 如果历史 extractor 返回多个 internal feature records，
       不把它们展开成多个训练样本。

       当前 semantic reconstruction 使用第一个 record，
       同时记录 raw_feature_count 供后续诊断。
    """

    label, pcap_path, order = task

    try:

        # ----------------------------------------------------
        # 确保可以导入历史 extractor
        # ----------------------------------------------------

        if HISTORICAL_SCRIPT_DIR not in sys.path:

            sys.path.insert(
                0,
                HISTORICAL_SCRIPT_DIR
            )

        import multiflow_batch_feature_extractor_historical as mf

        # ----------------------------------------------------
        # 直接调用历史 get_flow_features()
        # ----------------------------------------------------

        feature_results, total_packets, fpath = (
            mf.get_flow_features(
                pcap_path,
                max_packets=mf.max_packets
            )
        )

        # ----------------------------------------------------
        # 历史失败语义：
        # feature_results == -1 -> 丢弃，不补抽
        # ----------------------------------------------------

        if feature_results == -1:

            return {
                "order": order,
                "label": label,
                "pcap": pcap_path,
                "status": "FAILED",
                "reason": "feature_results == -1",
                "raw_feature_count": 0,
                "total_packets": total_packets,
                "rows": [],
            }

        # ----------------------------------------------------
        # 解包历史 extractor 返回结果
        # ----------------------------------------------------

        (
            lengths_list,
            dirs_list,
            iats_list,
            payloads_list
        ) = feature_results

        # ----------------------------------------------------
        # 基础一致性检查
        # ----------------------------------------------------

        component_counts = {
            "lengths": len(lengths_list),
            "directions": len(dirs_list),
            "iats": len(iats_list),
            "payloads": len(payloads_list),
        }

        raw_feature_count = len(
            lengths_list
        )

        if not (
            len(lengths_list)
            == len(dirs_list)
            == len(iats_list)
            == len(payloads_list)
        ):

            return {
                "order": order,
                "label": label,
                "pcap": pcap_path,
                "status": "EXCEPTION",
                "reason": (
                    "Feature component counts mismatch: "
                    f"{component_counts}"
                ),
                "raw_feature_count": raw_feature_count,
                "total_packets": total_packets,
                "rows": [],
            }

        # ----------------------------------------------------
        # 非 -1 但没有 feature
        # ----------------------------------------------------

        if raw_feature_count == 0:

            return {
                "order": order,
                "label": label,
                "pcap": pcap_path,
                "status": "FAILED",
                "reason": (
                    "feature_results valid but "
                    "contains zero feature records"
                ),
                "raw_feature_count": 0,
                "total_packets": total_packets,
                "rows": [],
            }

        # ----------------------------------------------------
        # 关键语义修正
        #
        # 输入 PCAP 本身已经是一个切分后的 flow。
        #
        # 所以无论历史 extractor 内部返回多少 record，
        # 这个输入 flow PCAP 在最终数据集中只能贡献一行。
        #
        # 当前 semantic reconstruction 使用第一个 record。
        #
        # raw_feature_count > 1 的情况会被另外记录，
        # 后续继续分析其根本原因。
        # ----------------------------------------------------

        row = [
            label,
            lengths_list[0],
            dirs_list[0],
            iats_list[0],
            payloads_list[0],
        ]

        return {
            "order": order,
            "label": label,
            "pcap": pcap_path,
            "status": "OK",
            "reason": "",
            "raw_feature_count": raw_feature_count,
            "total_packets": total_packets,
            "rows": [row],
        }

    except Exception as e:

        return {
            "order": order,
            "label": label,
            "pcap": pcap_path,
            "status": "EXCEPTION",
            "reason": repr(e),
            "traceback": traceback.format_exc(),
            "raw_feature_count": 0,
            "total_packets": None,
            "rows": [],
        }


# ============================================================
# Main
# ============================================================

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # 防止覆盖已有 reconstruction 输出
    #
    # selected_pcaps.json 不包含在这里，
    # 因为需要继续复用已经锁定的 selection。
    # --------------------------------------------------------

    existing = [
        path
        for path in [
            OUTPUT_CSV,
            PROCESSED_LOG,
            SUMMARY_JSON,
            SUMMARY_TSV,
            FAIL_LOG,
            MULTI_RECORD_LOG,
        ]
        if os.path.exists(path)
    ]

    if existing:

        print(
            "[STOP] Existing reconstruction "
            "outputs detected:"
        )

        for path in existing:
            print(" ", path)

        print()

        print(
            "No files were modified."
        )

        print(
            "selected_pcaps.json is intentionally "
            "reusable, but other result files must "
            "be removed before a clean rerun."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # 固定 RNG
    # --------------------------------------------------------

    random.seed(
        SEED
    )

    # --------------------------------------------------------
    # label 顺序
    #
    # 故意不排序
    # --------------------------------------------------------

    input_dirs = [
        os.path.join(
            PCAP_ROOT,
            d
        )
        for d in os.listdir(
            PCAP_ROOT
        )
        if os.path.isdir(
            os.path.join(
                PCAP_ROOT,
                d
            )
        )
    ]

    labels = [
        os.path.basename(d)
        for d in input_dirs
    ]

    candidate_counts = {}

    # --------------------------------------------------------
    # 优先复用已经锁定的抽样
    # --------------------------------------------------------

    reuse_selection = os.path.exists(
        SELECTED_LOG
    )

    if reuse_selection:

        print("=" * 100)

        print(
            "PHASE 1: reuse locked selection"
        )

        print("=" * 100)

        with open(
            SELECTED_LOG
        ) as f:

            selected_record = json.load(
                f
            )

        print(
            f"Reusing: {SELECTED_LOG}"
        )

    else:

        print("=" * 100)

        print(
            "PHASE 1: historical-style sampling"
        )

        print("=" * 100)

        selected_record = {}

    tasks = []

    global_order = 0

    # --------------------------------------------------------
    # 构建 task
    # --------------------------------------------------------

    for index, input_dir in enumerate(
        input_dirs,
        1
    ):

        label = os.path.basename(
            input_dir
        )

        all_pcaps = collect_pcaps(
            input_dir
        )

        candidate_counts[label] = len(
            all_pcaps
        )

        # ----------------------------------------------------
        # 已经锁定 selection
        # ----------------------------------------------------

        if label in selected_record:

            selected = selected_record[
                label
            ]

        # ----------------------------------------------------
        # 第一次运行：
        # 每个 label 随机选择最多 500 个 flow PCAP
        # ----------------------------------------------------

        else:

            if (
                len(all_pcaps)
                > MAX_FLOWS_PER_LABEL
            ):

                selected = random.sample(
                    all_pcaps,
                    MAX_FLOWS_PER_LABEL
                )

            else:

                selected = all_pcaps

            selected_record[label] = (
                selected
            )

        print(
            f"{index:02d} "
            f"{label:<20} "
            f"candidates={len(all_pcaps):>7} "
            f"selected={len(selected):>3}"
        )

        # ----------------------------------------------------
        # selected PCAP -> task
        # ----------------------------------------------------

        for pcap_path in selected:

            if not os.path.isfile(
                pcap_path
            ):

                raise FileNotFoundError(
                    f"Selected PCAP missing: "
                    f"{pcap_path}"
                )

            tasks.append(
                (
                    label,
                    pcap_path,
                    global_order
                )
            )

            global_order += 1

    # --------------------------------------------------------
    # 保存 / 刷新抽样清单
    # --------------------------------------------------------

    with open(
        SELECTED_LOG,
        "w"
    ) as f:

        json.dump(
            selected_record,
            f,
            indent=2
        )

    print()

    print(
        f"Labels selected : "
        f"{len(selected_record)}"
    )

    print(
        f"Total selected  : "
        f"{len(tasks)}"
    )

    print(
        f"Selection reused: "
        f"{reuse_selection}"
    )

    print(
        f"Selection file  : "
        f"{SELECTED_LOG}"
    )

    # --------------------------------------------------------
    # 基本完整性检查
    # --------------------------------------------------------

    if len(selected_record) != 20:

        raise RuntimeError(
            f"Expected 20 labels, "
            f"got {len(selected_record)}"
        )

    # 每类绝不能超过 500 个 selected flow
    for label in labels:

        selected_count = len(
            selected_record[label]
        )

        if selected_count > MAX_FLOWS_PER_LABEL:

            raise RuntimeError(
                f"Selection invariant violated: "
                f"{label} has "
                f"{selected_count} selected flows, "
                f"limit={MAX_FLOWS_PER_LABEL}"
            )

    if len(tasks) != 10000:

        print(
            "[WARNING] Total selected is "
            f"{len(tasks)}, not 10000."
        )

    # --------------------------------------------------------
    # 记录运行环境
    # --------------------------------------------------------

    historical_script = os.path.join(
        HISTORICAL_SCRIPT_DIR,
        "multiflow_batch_feature_extractor_historical.py"
    )

    with open(
        RUN_INFO,
        "w"
    ) as f:

        f.write(
            "USTC-TFC2016 MultiFlow "
            "semantic reconstruction\n"
        )

        f.write(
            f"Started: {now()}\n"
        )

        f.write(
            f"Python: {sys.executable}\n"
        )

        f.write(
            f"PCAP_ROOT: "
            f"{PCAP_ROOT}\n"
        )

        f.write(
            f"Historical extractor: "
            f"{historical_script}\n"
        )

        f.write(
            f"Seed: {SEED}\n"
        )

        f.write(
            f"MAX_FLOWS_PER_LABEL: "
            f"{MAX_FLOWS_PER_LABEL}\n"
        )

        f.write(
            f"Workers: {WORKERS}\n"
        )

        f.write(
            "Execution mode: serial\n"
        )

        f.write(
            f"Selection reused: "
            f"{reuse_selection}\n"
        )

        f.write(
            "Label and PCAP enumeration "
            "intentionally NOT sorted.\n"
        )

        f.write(
            "Semantic invariant: "
            "one selected flow PCAP -> "
            "at most one final CSV row.\n"
        )

        f.write(
            "If historical get_flow_features() "
            "returns multiple internal records, "
            "only the first record is used in "
            "the final dataset and the case is "
            "logged separately.\n"
        )

        f.write(
            "NOTE: standalone USTC "
            "reconstruction; historical RNG "
            "state before USTC cannot be "
            "guaranteed.\n"
        )

        f.write(
            "NOTE: feature extraction is "
            "executed serially.\n\n"
        )

        for i, label in enumerate(
            labels,
            1
        ):

            f.write(
                f"{i:02d}\t"
                f"{label}\t"
                f"{candidate_counts[label]}\t"
                f"{len(selected_record[label])}\n"
            )

    # ========================================================
    # PHASE 2
    # ========================================================

    print()

    print("=" * 100)

    print(
        f"PHASE 2: feature extraction "
        f"(serial, {WORKERS} worker)"
    )

    print("=" * 100)

    print(
        f"Python executable: "
        f"{sys.executable}"
    )

    print(
        f"Tasks: {len(tasks)}"
    )

    print()

    start = time.time()

    results = {}

    completed = 0

    ok_count = 0

    failed_count = 0

    exception_count = 0

    row_count_live = 0

    multi_record_count = 0

    # --------------------------------------------------------
    # 单线程串行特征提取
    # --------------------------------------------------------

    for task in tasks:

        result = extract_one(
            task
        )

        results[
            result["order"]
        ] = result

        completed += 1

        if result["status"] == "OK":

            ok_count += 1

            # 当前语义下 OK 必须正好一行
            if len(result["rows"]) != 1:

                raise RuntimeError(
                    "One-flow-one-row invariant "
                    "violated during extraction: "
                    f"{result['pcap']} produced "
                    f"{len(result['rows'])} final rows"
                )

            row_count_live += 1

            if (
                result.get(
                    "raw_feature_count",
                    0
                )
                > 1
            ):

                multi_record_count += 1

        elif result["status"] == "FAILED":

            failed_count += 1

        else:

            exception_count += 1

        # ----------------------------------------------------
        # 进度
        # ----------------------------------------------------

        if (
            completed <= 10
            or completed % 50 == 0
            or completed == len(tasks)
        ):

            elapsed = (
                time.time()
                - start
            )

            rate = (
                completed / elapsed
                if elapsed > 0
                else 0
            )

            remaining = (
                len(tasks)
                - completed
            )

            eta = (
                remaining / rate
                if rate > 0
                else 0
            )

            print(
                f"[PROGRESS] "
                f"{completed}/{len(tasks)} | "
                f"OK={ok_count} | "
                f"FAILED={failed_count} | "
                f"EXC={exception_count} | "
                f"rows={row_count_live} | "
                f"multi={multi_record_count} | "
                f"rate={rate:.3f}/s | "
                f"ETA={eta/60:.1f} min",
                flush=True
            )

    # ========================================================
    # PHASE 3
    # ========================================================

    print()

    print("=" * 100)

    print(
        "PHASE 3: writing results "
        "in original selected order"
    )

    print("=" * 100)

    summary = {
        label: {
            "candidate_sessions":
                candidate_counts[label],

            "selected_pcaps":
                len(
                    selected_record[
                        label
                    ]
                ),

            "successful_pcaps": 0,

            "failed_pcaps": 0,

            "exception_pcaps": 0,

            "csv_rows": 0,

            "multi_record_pcaps": 0,

            "raw_feature_records": 0,
        }
        for label in labels
    }

    total_rows = 0

    total_raw_feature_records = 0

    # --------------------------------------------------------
    # 写最终结果
    # --------------------------------------------------------

    with open(
        OUTPUT_CSV,
        "w",
        newline=""
    ) as csv_file, open(
        PROCESSED_LOG,
        "w"
    ) as processed_file, open(
        FAIL_LOG,
        "w",
        newline=""
    ) as fail_file, open(
        MULTI_RECORD_LOG,
        "w",
        newline=""
    ) as multi_file:

        writer = csv.writer(
            csv_file
        )

        fail_writer = csv.writer(
            fail_file,
            delimiter="\t"
        )

        multi_writer = csv.writer(
            multi_file,
            delimiter="\t"
        )

        # ----------------------------------------------------
        # CSV header
        # ----------------------------------------------------

        writer.writerow([
            "label",
            "lengths",
            "directions",
            "iats",
            "payloads",
        ])

        # ----------------------------------------------------
        # failure log header
        # ----------------------------------------------------

        fail_writer.writerow([
            "label",
            "pcap",
            "status",
            "reason",
        ])

        # ----------------------------------------------------
        # multiple internal records diagnostic log
        # ----------------------------------------------------

        multi_writer.writerow([
            "label",
            "pcap",
            "raw_feature_count",
            "total_packets",
        ])

        # ----------------------------------------------------
        # 按原 selected task 顺序写入
        # ----------------------------------------------------

        for order in range(
            len(tasks)
        ):

            result = results[
                order
            ]

            label = result[
                "label"
            ]

            # =================================================
            # OK
            # =================================================

            if (
                result["status"]
                == "OK"
            ):

                summary[label][
                    "successful_pcaps"
                ] += 1

                raw_count = result.get(
                    "raw_feature_count",
                    0
                )

                summary[label][
                    "raw_feature_records"
                ] += raw_count

                total_raw_feature_records += (
                    raw_count
                )

                # ---------------------------------------------
                # 记录 extractor 返回多个内部 record 的 PCAP
                # ---------------------------------------------

                if raw_count > 1:

                    summary[label][
                        "multi_record_pcaps"
                    ] += 1

                    multi_writer.writerow([
                        label,
                        result["pcap"],
                        raw_count,
                        result.get(
                            "total_packets",
                            ""
                        ),
                    ])

                # ---------------------------------------------
                # processed file
                # ---------------------------------------------

                processed_file.write(
                    json.dumps(
                        {
                            "file":
                                result[
                                    "pcap"
                                ],

                            "raw_feature_count":
                                raw_count,
                        }
                    )
                    + "\n"
                )

                # ---------------------------------------------
                # 当前语义下：
                # 一个成功 flow 必须正好一行
                # ---------------------------------------------

                if len(result["rows"]) != 1:

                    raise RuntimeError(
                        "One-flow-one-row invariant "
                        "violated while writing: "
                        f"{result['pcap']} produced "
                        f"{len(result['rows'])} rows"
                    )

                row = result[
                    "rows"
                ][0]

                writer.writerow([
                    row[0],

                    json.dumps(
                        row[1]
                    ),

                    json.dumps(
                        row[2]
                    ),

                    json.dumps(
                        row[3]
                    ),

                    json.dumps(
                        row[4]
                    ),
                ])

                summary[label][
                    "csv_rows"
                ] += 1

                total_rows += 1

            # =================================================
            # FAILED / EXCEPTION
            # =================================================

            else:

                summary[label][
                    "failed_pcaps"
                ] += 1

                if (
                    result["status"]
                    == "EXCEPTION"
                ):

                    summary[label][
                        "exception_pcaps"
                    ] += 1

                fail_writer.writerow([
                    label,
                    result["pcap"],
                    result["status"],
                    result["reason"],
                ])

    # ========================================================
    # PHASE 4: 数据语义完整性检查
    # ========================================================

    print()

    print("=" * 100)

    print(
        "PHASE 4: validating "
        "one-flow-one-row invariant"
    )

    print("=" * 100)

    for label in labels:

        s = summary[
            label
        ]

        # ----------------------------------------------------
        # 1. 每个成功 PCAP 必须对应一条 CSV
        # ----------------------------------------------------

        if (
            s["csv_rows"]
            != s["successful_pcaps"]
        ):

            raise RuntimeError(
                f"Invariant violated for {label}: "
                f"successful_pcaps="
                f"{s['successful_pcaps']}, "
                f"csv_rows="
                f"{s['csv_rows']}"
            )

        # ----------------------------------------------------
        # 2. 每个类别最多 500 行
        # ----------------------------------------------------

        if (
            s["csv_rows"]
            > MAX_FLOWS_PER_LABEL
        ):

            raise RuntimeError(
                f"Label {label} produced "
                f"{s['csv_rows']} rows, "
                f"exceeding limit "
                f"{MAX_FLOWS_PER_LABEL}"
            )

        # ----------------------------------------------------
        # 3. success + failed == selected
        # ----------------------------------------------------

        if (
            s["successful_pcaps"]
            + s["failed_pcaps"]
            != s["selected_pcaps"]
        ):

            raise RuntimeError(
                f"Accounting invariant violated "
                f"for {label}: "
                f"success="
                f"{s['successful_pcaps']}, "
                f"failed="
                f"{s['failed_pcaps']}, "
                f"selected="
                f"{s['selected_pcaps']}"
            )

    print(
        "[OK] All labels satisfy:"
    )

    print(
        "     csv_rows == successful_pcaps"
    )

    print(
        f"     csv_rows <= "
        f"{MAX_FLOWS_PER_LABEL}"
    )

    # ========================================================
    # 汇总
    # ========================================================

    elapsed = (
        time.time()
        - start
    )

    total_success = sum(
        item["successful_pcaps"]
        for item in summary.values()
    )

    total_failed = sum(
        item["failed_pcaps"]
        for item in summary.values()
    )

    total_exceptions = sum(
        item["exception_pcaps"]
        for item in summary.values()
    )

    total_multi_record_pcaps = sum(
        item["multi_record_pcaps"]
        for item in summary.values()
    )

    # --------------------------------------------------------
    # 全局 invariant
    # --------------------------------------------------------

    if total_rows != total_success:

        raise RuntimeError(
            "Global invariant violated: "
            f"rows={total_rows}, "
            f"success={total_success}"
        )

    result_summary = {

        "reconstruction_date":
            "2026-10-14",

        "python":
            sys.executable,

        "seed":
            SEED,

        "workers":
            WORKERS,

        "execution_mode":
            "serial",

        "selection_reused":
            reuse_selection,

        "max_flows_per_label":
            MAX_FLOWS_PER_LABEL,

        "sample_semantics":
            "one selected flow PCAP -> at most one CSV row",

        "multi_record_policy":
            (
                "If historical get_flow_features() "
                "returns multiple internal records, "
                "use only the first record and log "
                "the PCAP for diagnosis."
            ),

        "label_order":
            labels,

        "total_candidates":
            sum(
                candidate_counts.values()
            ),

        "total_selected":
            len(tasks),

        "total_successful_pcaps":
            total_success,

        "total_failed_pcaps":
            total_failed,

        "total_exception_pcaps":
            total_exceptions,

        "total_csv_rows":
            total_rows,

        "total_raw_feature_records":
            total_raw_feature_records,

        "total_multi_record_pcaps":
            total_multi_record_pcaps,

        "historical_final_rows":
            7540,

        "difference_from_historical":
            total_rows - 7540,

        "elapsed_seconds":
            round(
                elapsed,
                3
            ),

        "labels":
            summary,

        "notes": [
            (
                "Each splitcap PCAP is treated "
                "as one already-separated flow."
            ),
            (
                "Each selected flow PCAP can "
                "contribute at most one final "
                "CSV sample."
            ),
            (
                "feature_results == -1 is "
                "discarded without replacement."
            ),
            (
                "Historical get_flow_features() "
                "is called directly."
            ),
            (
                "If get_flow_features() returns "
                "multiple internal records for "
                "one flow PCAP, only the first "
                "record is retained."
            ),
            (
                "Multi-record PCAPs are recorded "
                "in 04_multi_record_pcaps.tsv."
            ),
            (
                "Existing selected_pcaps.json "
                "is reused."
            ),
            (
                "Feature extraction is executed "
                "serially."
            ),
            (
                "Historical exact USTC RNG state "
                "cannot be guaranteed because "
                "USTC was fourth in the original "
                "multi-dataset run."
            ),
            (
                "This is a semantic reconstruction, "
                "not a claim of bit-exact historical "
                "reproduction."
            ),
        ],
    }

    # --------------------------------------------------------
    # JSON summary
    # --------------------------------------------------------

    with open(
        SUMMARY_JSON,
        "w"
    ) as f:

        json.dump(
            result_summary,
            f,
            indent=2
        )

    # ========================================================
    # TSV summary
    # ========================================================

    with open(
        SUMMARY_TSV,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(
            f,
            delimiter="\t"
        )

        writer.writerow([
            "label",
            "candidates",
            "selected",
            "success",
            "failed",
            "exceptions",
            "csv_rows",
            "multi_record_pcaps",
            "raw_feature_records",
        ])

        for label in labels:

            s = summary[
                label
            ]

            writer.writerow([
                label,

                s[
                    "candidate_sessions"
                ],

                s[
                    "selected_pcaps"
                ],

                s[
                    "successful_pcaps"
                ],

                s[
                    "failed_pcaps"
                ],

                s[
                    "exception_pcaps"
                ],

                s[
                    "csv_rows"
                ],

                s[
                    "multi_record_pcaps"
                ],

                s[
                    "raw_feature_records"
                ],
            ])

    # ========================================================
    # 最终输出
    # ========================================================

    print()

    print("=" * 120)

    print(
        f"{'Label':<20} "
        f"{'Candidates':>10} "
        f"{'Selected':>8} "
        f"{'Success':>8} "
        f"{'Failed':>8} "
        f"{'Rows':>8} "
        f"{'Multi':>8} "
        f"{'Raw':>8}"
    )

    print("-" * 120)

    for label in labels:

        s = summary[
            label
        ]

        print(
            f"{label:<20} "
            f"{s['candidate_sessions']:>10} "
            f"{s['selected_pcaps']:>8} "
            f"{s['successful_pcaps']:>8} "
            f"{s['failed_pcaps']:>8} "
            f"{s['csv_rows']:>8} "
            f"{s['multi_record_pcaps']:>8} "
            f"{s['raw_feature_records']:>8}"
        )

    print("-" * 120)

    print(
        f"{'TOTAL':<20} "
        f"{sum(candidate_counts.values()):>10} "
        f"{len(tasks):>8} "
        f"{total_success:>8} "
        f"{total_failed:>8} "
        f"{total_rows:>8} "
        f"{total_multi_record_pcaps:>8} "
        f"{total_raw_feature_records:>8}"
    )

    print("=" * 120)

    print(
        "Historical final rows : "
        "7540"
    )

    print(
        f"Reconstructed rows    : "
        f"{total_rows}"
    )

    print(
        f"Difference            : "
        f"{total_rows - 7540:+d}"
    )

    print(
        f"Successful flow PCAPs : "
        f"{total_success}"
    )

    print(
        f"Failed flow PCAPs     : "
        f"{total_failed}"
    )

    print(
        f"Exceptions            : "
        f"{total_exceptions}"
    )

    print(
        f"Multi-record PCAPs    : "
        f"{total_multi_record_pcaps}"
    )

    print(
        f"Raw feature records   : "
        f"{total_raw_feature_records}"
    )

    print(
        f"Workers               : "
        f"{WORKERS}"
    )

    print(
        "Execution mode        : "
        "serial"
    )

    print(
        "Sample semantics      : "
        "1 flow PCAP -> <= 1 CSV row"
    )

    print(
        f"Elapsed               : "
        f"{elapsed:.1f}s "
        f"({elapsed/60:.1f} min)"
    )

    print(
        f"Finished              : "
        f"{now()}"
    )

    print("=" * 120)


if __name__ == "__main__":
    main()
# Historical shell note: grep -n "def get_flow_features" USTC-TFC2016/scripts/multiflow_batch_feature_extractor_historical.py
