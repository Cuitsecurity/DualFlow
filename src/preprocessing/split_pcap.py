"""Split class-labeled captures into sessions using the existing SplitCap tool."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True,
                        help="Raw captures arranged as <input-dir>/<class>/**/*.pcap")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--splitcap", type=Path, required=True,
                        help="Path to external SplitCap.exe; Mono must be installed")
    args = parser.parse_args()
    if not args.input_dir.is_dir() or not args.splitcap.is_file():
        parser.error("Check --input-dir and --splitcap")
    source = args.input_dir.resolve()
    output = args.output_dir.resolve()
    if output == source or source in output.parents:
        parser.error("Output must be outside the raw input directory")
    tasks = []
    destinations = set()
    for label in sorted(p for p in source.iterdir() if p.is_dir()):
        for capture in sorted(label.rglob("*")):
            if capture.suffix.lower() not in (".pcap", ".pcapng") or not capture.is_file():
                continue
            destination = output / label.name / capture.relative_to(label).with_suffix("")
            if destination in destinations:
                parser.error(f"Capture names collide: {destination}")
            destinations.add(destination)
            marker = destination / ".splitcap_complete"
            if destination.exists() and any(destination.iterdir()) and not marker.exists():
                parser.error(f"Unfinished or unrelated output exists: {destination}; use a fresh output directory")
            tasks.append((capture, destination, marker))
    if not tasks:
        parser.error("No labeled PCAP captures found")
    for capture, destination, marker in tasks:
        if marker.exists():
            print(f"Skip completed: {capture}")
            continue
        destination.mkdir(parents=True, exist_ok=True)
        with (destination / "splitcap.log").open("w") as log:
            subprocess.run(["mono", str(args.splitcap.resolve()), "-r", str(capture),
                            "-s", "session", "-o", str(destination)],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        marker.touch()
        print(f"Split: {capture} -> {destination}")


if __name__ == "__main__":
    main()
