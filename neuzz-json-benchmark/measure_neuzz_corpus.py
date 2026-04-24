from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

from json_benchmark_common import (
    DEFAULT_COVERAGE_FILE,
    analyze_json_input,
    maybe_create_coverage,
    print_full_coverage_summary,
    print_missing_branches,
)


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


def parse_run_log(log_path: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    if not log_path.exists():
        return stats

    total_execs = None
    edge_coverages: list[str] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"total execs\s+(\d+)\s+edge coverage\s+(\d+)", line)
        if match:
            total_execs = match.group(1)
            edge_coverages.append(match.group(2))
            continue
        match = re.search(r"edge num\s+(\d+)", line)
        if match:
            edge_coverages.append(match.group(1))

    if total_execs is not None:
        stats["neuzz_execs"] = total_execs
    if edge_coverages:
        stats["max_edge_coverage"] = str(max(int(value) for value in edge_coverages))
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure Neuzz corpus results with source-level coverage and bug breakdown for direct comparison."
    )
    parser.add_argument("--workspace", default=".", help="Path to the Neuzz benchmark workspace.")
    parser.add_argument("--include-vari-seeds", action="store_true", help="Include vari_seeds in the measurement.")
    parser.add_argument("--coverage-file", default=DEFAULT_COVERAGE_FILE, help="Coverage data file to write.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    parser.add_argument("--run-log", default="logs/neuzz.log", help="Relative path to the Neuzz run log.")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    inputs = iter_inputs(workspace, include_vari_seeds=args.include_vari_seeds)
    if not inputs:
        raise SystemExit(f"No replayable Neuzz inputs found under {workspace}")

    cov = maybe_create_coverage(args.coverage_file)
    if cov is None:
        raise SystemExit("coverage.py is not installed in this environment.")

    bug_counts: Counter[str] = Counter()
    unique_bug_messages: set[tuple[str, str]] = set()
    clean_inputs = 0

    cov.erase()
    cov.start()
    try:
        for path in inputs:
            outcome = analyze_json_input(path.read_bytes(), timeout_seconds=args.timeout_seconds)
            if outcome.bug is None:
                clean_inputs += 1
                continue
            bug_counts[outcome.bug.bug_type] += 1
            unique_bug_messages.add((outcome.bug.bug_type, outcome.bug.message))
    finally:
        cov.stop()
        cov.save()

    stats = parse_run_log(workspace / args.run_log)

    print("=" * 60)
    print("Neuzz corpus benchmark summary")
    print("=" * 60)
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

    print("\nBug type breakdown")
    print("-" * 60)
    for bug_type in sorted(bug_counts):
        print(f"{bug_type:24} {bug_counts[bug_type]}")
    if not bug_counts:
        print("no bug-triggering inputs found")

    print(f"\nCoverage data saved to: {args.coverage_file}")
    print("\n" + "=" * 60)
    print("COVERAGE REPORT (ACCUMULATED)")
    print("=" * 60)
    cov.report(file=None, show_missing=True)
    print_full_coverage_summary(cov)
    print_missing_branches(cov)


if __name__ == "__main__":
    main()
