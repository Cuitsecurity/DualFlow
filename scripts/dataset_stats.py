"""Report split sizes and class counts without changing dataset files."""
import argparse
import csv
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("split_dir", type=Path)
    args = parser.parse_args()
    label_sets = {}
    print("split\tflows\tclasses")
    for name in ("train", "valid", "test"):
        with (args.split_dir / f"{name}.csv").open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            counts = Counter(row["label"] for row in reader)
        label_sets[name] = set(counts)
        print(f"{name}\t{sum(counts.values())}\t{len(counts)}")
    unseen = (label_sets["valid"] | label_sets["test"]) - label_sets["train"]
    if unseen:
        raise SystemExit(f"Validation/test labels absent from training: {sorted(unseen)}")


if __name__ == "__main__":
    main()
