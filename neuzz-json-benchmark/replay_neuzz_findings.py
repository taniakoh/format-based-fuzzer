from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def iter_inputs(root: Path, include_vari_seeds: bool) -> list[Path]:
    directories = ["crashes", "seeds"]
    if include_vari_seeds:
        directories.append("vari_seeds")

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
    parser = argparse.ArgumentParser(description="Replay Neuzz findings using the benchmark runner output format.")
    parser.add_argument("--workspace", default=".", help="Path to the Neuzz benchmark workspace.")
    parser.add_argument("--include-vari-seeds", action="store_true", help="Replay vari_seeds in addition to crashes and seeds.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    inputs = iter_inputs(workspace, include_vari_seeds=args.include_vari_seeds)
    if not inputs:
        print(f"No replayable inputs found under {workspace}")
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
