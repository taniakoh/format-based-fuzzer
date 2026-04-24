from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from neuzz_text_benchmark_common import iter_neuzz_inputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay Neuzz findings using the benchmark runner output format.")
    parser.add_argument("--workspace", default=".", help="Path to the Neuzz benchmark workspace.")
    parser.add_argument("--include-vari-seeds", action="store_true", help="Replay vari_seeds in addition to crashes and seeds.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    inputs = iter_neuzz_inputs(workspace, include_vari_seeds=args.include_vari_seeds)
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
                str(workspace / "text_case_runner.py"),
                "--input-file",
                str(path),
                "--timeout-seconds",
                str(args.timeout_seconds),
            ],
            check=False,
        )


if __name__ == "__main__":
    main()
