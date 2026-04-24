from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from json_benchmark_common import (
    DEFAULT_COVERAGE_FILE,
    analyze_json_input,
    maybe_create_coverage,
    print_full_coverage_summary,
    print_missing_branches,
)


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


def parse_fuzzer_stats(path: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    if not path.exists():
        return stats
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def format_duration_seconds(raw_seconds: str) -> str:
    try:
        total_seconds = int(float(raw_seconds))
    except (TypeError, ValueError):
        return raw_seconds

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or parts:
        parts.append(f"{hours}h")
    if minutes or parts:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure AFL corpus results with source-level coverage and bug breakdown for direct comparison."
    )
    parser.add_argument("--afl-out", required=True, help="Path to AFL output directory, usually afl-out/default.")
    parser.add_argument("--include-queue", action="store_true", help="Include the AFL queue corpus in the measurement.")
    parser.add_argument("--coverage-file", default=DEFAULT_COVERAGE_FILE, help="Coverage data file to write.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    afl_out = Path(args.afl_out)
    inputs = iter_inputs(afl_out, include_queue=args.include_queue)
    if not inputs:
        raise SystemExit(f"No replayable AFL inputs found under {afl_out}")

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

    stats = parse_fuzzer_stats(afl_out / "fuzzer_stats")

    print("=" * 60)
    print("AFL corpus benchmark summary")
    print("=" * 60)
    print(f"inputs measured          : {len(inputs)}")
    print(f"clean inputs             : {clean_inputs}")
    print(f"bug-triggering inputs    : {sum(bug_counts.values())}")
    print(f"unique bug signatures    : {len(unique_bug_messages)}")
    print(f"queue included           : {'yes' if args.include_queue else 'no'}")
    if stats:
        execs_done = stats.get("execs_done")
        execs_per_sec = stats.get("execs_per_sec")
        saved_crashes = stats.get("saved_crashes")
        saved_hangs = stats.get("saved_hangs")
        run_time = stats.get("run_time")
        if run_time is not None:
            print(f"afl run time             : {format_duration_seconds(run_time)} ({run_time} s)")
        if execs_done is not None:
            print(f"afl execs done           : {execs_done}")
        if execs_per_sec is not None:
            print(f"afl execs/sec            : {execs_per_sec}")
        if saved_crashes is not None:
            print(f"afl saved crashes        : {saved_crashes}")
        if saved_hangs is not None:
            print(f"afl saved hangs          : {saved_hangs}")

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
