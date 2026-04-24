from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def iter_inputs(root: Path, include_queue: bool) -> list[Path]:
    directories = ["crashes", "hangs"]
    if include_queue:
        directories.append("queue")

    inputs: list[Path] = []
    for directory in directories:
        path = root / directory
        if not path.exists():
            continue
        for child in sorted(path.iterdir()):
            if child.is_file() and not child.name.startswith("README"):
                inputs.append(child)
    return inputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay AFL findings using the benchmark runner output format.")
    parser.add_argument("--afl-out", required=True, help="Path to AFL output directory, usually afl-out/default.")
    parser.add_argument("--include-queue", action="store_true", help="Replay queue entries in addition to crashes and hangs.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    afl_out = Path(args.afl_out)
    inputs = iter_inputs(afl_out, include_queue=args.include_queue)
    if not inputs:
        print(f"No replayable inputs found under {afl_out}")
        return

    for path in inputs:
        print("=" * 80)
        print(f"Replaying: {path}")
        print("=" * 80)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "json_case_runner.py"),
                "--input-file",
                str(path),
                "--timeout-seconds",
                str(args.timeout_seconds),
            ],
            check=False,
        )


if __name__ == "__main__":
    main()
