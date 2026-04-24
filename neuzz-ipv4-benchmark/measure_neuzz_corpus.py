from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from neuzz_text_benchmark_common import (
    BITMAP_SIZE,
    analyze_text_input,
    detect_workspace_target,
    iter_neuzz_inputs,
    parse_run_log,
    replay_showmap_edges,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure Neuzz corpus results with bitmap coverage and bug breakdown for direct comparison."
    )
    parser.add_argument("--workspace", default=".", help="Path to the Neuzz benchmark workspace.")
    parser.add_argument("--include-vari-seeds", action="store_true", help="Include vari_seeds in the measurement.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    parser.add_argument("--run-log", default="logs/neuzz.log", help="Relative path to the Neuzz run log.")
    parser.add_argument("--showmap-timeout-ms", type=int, default=1000, help="afl-showmap timeout per replayed input.")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    inputs = iter_neuzz_inputs(workspace, include_vari_seeds=args.include_vari_seeds)
    if not inputs:
        raise SystemExit(f"No replayable Neuzz inputs found under {workspace}")

    target = detect_workspace_target(workspace)
    python_bin = str((workspace / ".venv" / "bin" / "python").resolve()) if (workspace / ".venv" / "bin" / "python").exists() else sys.executable
    target_script = workspace / "neuzz_target.py"

    bug_counts: Counter[str] = Counter()
    unique_bug_messages: set[tuple[str, str]] = set()
    clean_inputs = 0
    unique_edges: set[int] = set()

    for path in inputs:
        outcome = analyze_text_input(target, path.read_bytes(), timeout_seconds=args.timeout_seconds)
        unique_edges |= replay_showmap_edges(target_script, path, python_bin, timeout_ms=args.showmap_timeout_ms)
        if outcome.bug is None:
            clean_inputs += 1
            continue
        bug_counts[outcome.bug.bug_type] += 1
        unique_bug_messages.add((outcome.bug.bug_type, outcome.bug.message))

    stats = parse_run_log(workspace / args.run_log)
    bitmap_cov_percent = (len(unique_edges) / BITMAP_SIZE) * 100.0 if unique_edges else 0.0

    print("=" * 60)
    print("Neuzz corpus benchmark summary")
    print("=" * 60)
    print(f"target                   : {target}")
    print(f"inputs measured          : {len(inputs)}")
    print(f"clean inputs             : {clean_inputs}")
    print(f"bug-triggering inputs    : {sum(bug_counts.values())}")
    print(f"unique bug signatures    : {len(unique_bug_messages)}")
    print(f"vari_seeds included      : {'yes' if args.include_vari_seeds else 'no'}")
    if stats:
        if "neuzz_execs" in stats:
            print(f"neuzz execs              : {stats['neuzz_execs']}")
        if "max_edge_coverage" in stats:
            print(f"max edge coverage        : {stats['max_edge_coverage']}")
    print(f"replayed bitmap edges    : {len(unique_edges)}")
    print(f"bitmap coverage percent  : {bitmap_cov_percent:.2f}%")

    print("\nBug type breakdown")
    print("-" * 60)
    for bug_type in sorted(bug_counts):
        print(f"{bug_type:24} {bug_counts[bug_type]}")
    if not bug_counts:
        print("no bug-triggering inputs found")


if __name__ == "__main__":
    main()
