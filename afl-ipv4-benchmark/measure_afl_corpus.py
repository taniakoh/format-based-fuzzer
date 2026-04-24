from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from ipv4_benchmark_common import analyze_ipv4_input


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
    parser = argparse.ArgumentParser(description="Measure AFL IPv4 corpus results with oracle-based bug breakdown.")
    parser.add_argument("--afl-out", required=True, help="Path to AFL output directory, usually afl-out/default.")
    parser.add_argument("--include-queue", action="store_true", help="Include the AFL queue corpus in the measurement.")
    args = parser.parse_args()

    afl_out = Path(args.afl_out)
    inputs = iter_inputs(afl_out, include_queue=args.include_queue)
    if not inputs:
        raise SystemExit(f"No replayable AFL inputs found under {afl_out}")

    bug_counts: Counter[str] = Counter()
    unique_bug_messages: set[tuple[str, str]] = set()
    clean_inputs = 0

    for path in inputs:
        outcome = analyze_ipv4_input(path.read_bytes())
        if outcome.bug is None:
            clean_inputs += 1
            continue
        bug_counts[outcome.bug.bug_type] += 1
        unique_bug_messages.add((outcome.bug.bug_type, outcome.bug.message))

    stats = parse_fuzzer_stats(afl_out / "fuzzer_stats")
    print("=" * 60)
    print("AFL IPv4 corpus benchmark summary")
    print("=" * 60)
    print(f"inputs measured          : {len(inputs)}")
    print(f"clean inputs             : {clean_inputs}")
    print(f"bug-triggering inputs    : {sum(bug_counts.values())}")
    print(f"unique bug signatures    : {len(unique_bug_messages)}")
    print(f"queue included           : {'yes' if args.include_queue else 'no'}")
    if stats:
        run_time = stats.get("run_time")
        execs_done = stats.get("execs_done")
        execs_per_sec = stats.get("execs_per_sec")
        saved_crashes = stats.get("saved_crashes")
        saved_hangs = stats.get("saved_hangs")
        bitmap_cvg = stats.get("bitmap_cvg")
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
        if bitmap_cvg is not None:
            print(f"afl bitmap coverage      : {bitmap_cvg}")

    print("\nBug type breakdown")
    print("-" * 60)
    for bug_type in sorted(bug_counts):
        print(f"{bug_type:24} {bug_counts[bug_type]}")
    if not bug_counts:
        print("no bug-triggering inputs found")


if __name__ == "__main__":
    main()
