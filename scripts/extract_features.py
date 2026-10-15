"""CLI adapter for the existing batch feature extractor; no feature logic is changed."""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap-root", type=Path, required=True,
                        help="Root containing one folder per class, with flow PCAPs below it")
    parser.add_argument("--output-root", type=Path, default=Path("data"))
    parser.add_argument("--name", required=True)
    parser.add_argument("--max-flows-per-label", type=int, default=500)
    args = parser.parse_args()
    if not args.pcap_root.is_dir():
        parser.error(f"PCAP root does not exist: {args.pcap_root}")
    if Path(args.name).name != args.name or args.name in (".", ".."):
        parser.error("--name must be a single directory name")
    if args.max_flows_per_label < 1:
        parser.error("--max-flows-per-label must be positive")
    script = Path(__file__).resolve().parents[1] / "data_process/multiflow_batch_feature_extractor.py"
    spec = importlib.util.spec_from_file_location("multiflow_extractor", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.BASE_OUTPUT_DIR = str(args.output_root.resolve())
    module.process_dataset({"name": args.name, "pcap_root": str(args.pcap_root.resolve()),
                            "max_flows_per_label": args.max_flows_per_label})


if __name__ == "__main__":
    main()
