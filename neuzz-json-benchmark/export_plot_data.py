from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_NEUZZ_LOG = ROOT / "logs" / "neuzz.log"
DEFAULT_NN_LOG = ROOT / "logs" / "nn.log"
DEFAULT_SEEDS = ROOT / "seeds"
DEFAULT_VARI_SEEDS = ROOT / "vari_seeds"
DEFAULT_NEUZZ_CRASHES = ROOT / "crashes"
DEFAULT_RESULTS_CRASHES = ROOT / "results" / "crashes"
DEFAULT_OUTPUT = ROOT / "plot_data"


@dataclass(frozen=True)
class TimedEvent:
    relative_time_sec: float
    category: str
    path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert Neuzz JSON benchmark outputs into project-style plot_data.")
    parser.add_argument("--neuzz-log", default=str(DEFAULT_NEUZZ_LOG))
    parser.add_argument("--nn-log", default=str(DEFAULT_NN_LOG))
    parser.add_argument("--seeds-dir", default=str(DEFAULT_SEEDS))
    parser.add_argument("--vari-seeds-dir", default=str(DEFAULT_VARI_SEEDS))
    parser.add_argument("--crashes-dir", default=str(DEFAULT_NEUZZ_CRASHES))
    parser.add_argument("--results-crashes", default=str(DEFAULT_RESULTS_CRASHES))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def bug_bucket_from_name(name: str) -> str:
    bug_type = name.split("-", 1)[0]
    if bug_type in {"validity", "wrong_exception_type"}:
        return "validity_bugs"
    if bug_type == "bonus":
        return "bonus_bugs"
    return "functional_bugs"


def parse_final_stats(path: Path) -> tuple[int, int]:
    total_execs = 0
    max_edge = 0
    if not path.exists():
        return total_execs, max_edge
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"total execs\s+(\d+)\s+edge coverage\s+(\d+)", line)
        if match:
            total_execs = int(match.group(1))
            max_edge = int(match.group(2))
        match = re.search(r"edge num\s+(\d+)", line)
        if match:
            max_edge = max(max_edge, int(match.group(1)))
    return total_execs, max_edge


def collect_events(
    seeds_dir: Path,
    vari_seeds_dir: Path,
    crashes_dir: Path,
    results_crashes: Path,
    start_epoch: float,
) -> list[TimedEvent]:
    events: list[TimedEvent] = []
    sources = [
        (seeds_dir, "seed"),
        (vari_seeds_dir, "vari_seed"),
        (crashes_dir, "neuzz_crash"),
        (results_crashes, "json_bug"),
    ]
    for directory, category in sources:
        if not directory.exists():
            continue
        for child in directory.iterdir():
            if not child.is_file() or child.name.startswith("."):
                continue
            relative = max(child.stat().st_mtime - start_epoch, 0.0)
            events.append(TimedEvent(relative, category, child))
    events.sort(key=lambda item: (item.relative_time_sec, item.category, item.path.name))
    return events


def guess_start_epoch(neuzz_log: Path, nn_log: Path, events: list[TimedEvent]) -> float:
    candidates: list[float] = []
    for path in (neuzz_log, nn_log):
        if path.exists():
            candidates.append(path.stat().st_mtime)
    for event in events:
        candidates.append(event.path.stat().st_mtime)
    return min(candidates) if candidates else 0.0


def main() -> None:
    args = parse_args()
    neuzz_log = Path(args.neuzz_log)
    nn_log = Path(args.nn_log)
    seeds_dir = Path(args.seeds_dir)
    vari_seeds_dir = Path(args.vari_seeds_dir)
    crashes_dir = Path(args.crashes_dir)
    results_crashes = Path(args.results_crashes)
    output = Path(args.output)

    provisional_events = collect_events(seeds_dir, vari_seeds_dir, crashes_dir, results_crashes, 0.0)
    start_epoch = guess_start_epoch(neuzz_log, nn_log, provisional_events)
    events = collect_events(seeds_dir, vari_seeds_dir, crashes_dir, results_crashes, start_epoch)
    total_execs, max_edge = parse_final_stats(neuzz_log)

    final_time = 0.0
    if events:
        final_time = max(event.relative_time_sec for event in events)
    if neuzz_log.exists():
        final_time = max(final_time, max(neuzz_log.stat().st_mtime - start_epoch, 0.0))
    if nn_log.exists():
        final_time = max(final_time, max(nn_log.stat().st_mtime - start_epoch, 0.0))
    final_time = max(final_time, 1.0)

    checkpoints = sorted({0.0, final_time, *[event.relative_time_sec for event in events]})

    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "relative_time_sec",
        "total_execs",
        "coverage_seen",
        "coverage_percent",
        "interesting_test_cases",
        "corpus_size",
        "unique_bugs",
        "unique_crashes",
        "validity_bugs",
        "functional_bugs",
        "bonus_bugs",
    ]

    event_index = 0
    seeds_seen = 0
    vari_seen = 0
    neuzz_crashes_seen = 0
    validity = 0
    functional = 0
    bonus = 0
    written = 0

    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for checkpoint in checkpoints:
            while event_index < len(events) and events[event_index].relative_time_sec <= checkpoint:
                event = events[event_index]
                if event.category == "seed":
                    seeds_seen += 1
                elif event.category == "vari_seed":
                    vari_seen += 1
                elif event.category == "neuzz_crash":
                    neuzz_crashes_seen += 1
                elif event.category == "json_bug":
                    bucket = bug_bucket_from_name(event.path.name)
                    if bucket == "validity_bugs":
                        validity += 1
                    elif bucket == "bonus_bugs":
                        bonus += 1
                    else:
                        functional += 1
                event_index += 1

            progress_ratio = min(max(checkpoint / final_time, 0.0), 1.0)
            coverage_seen = max_edge * progress_ratio
            writer.writerow(
                {
                    "relative_time_sec": f"{checkpoint:.6f}",
                    "total_execs": f"{total_execs * progress_ratio:.6f}",
                    "coverage_seen": f"{coverage_seen:.6f}",
                    "coverage_percent": f"{(coverage_seen / 65536.0) * 100.0:.6f}",
                    "interesting_test_cases": seeds_seen + vari_seen,
                    "corpus_size": seeds_seen,
                    "unique_bugs": validity + functional + bonus,
                    "unique_crashes": neuzz_crashes_seen,
                    "validity_bugs": validity,
                    "functional_bugs": functional,
                    "bonus_bugs": bonus,
                }
            )
            written += 1

    print(f"Wrote {written} Neuzz plot rows to {output}")
    print("Note: Neuzz exec and coverage curves are interpolated from sparse run logs plus artifact timestamps.")


if __name__ == "__main__":
    main()
