from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_AFL_PLOT_DATA = ROOT / "afl-out" / "default" / "plot_data"
DEFAULT_FUZZER_STATS = ROOT / "afl-out" / "default" / "fuzzer_stats"
DEFAULT_RESULTS_CRASHES = ROOT / "results" / "crashes"
DEFAULT_OUTPUT = ROOT / "plot_data"


@dataclass(frozen=True)
class BugArtifact:
    relative_time_sec: float
    bug_bucket: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert AFL IPv6 benchmark outputs into project-style plot_data.")
    parser.add_argument("--afl-plot-data", default=str(DEFAULT_AFL_PLOT_DATA))
    parser.add_argument("--fuzzer-stats", default=str(DEFAULT_FUZZER_STATS))
    parser.add_argument("--results-crashes", default=str(DEFAULT_RESULTS_CRASHES))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


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


def bug_bucket_from_name(name: str) -> str:
    bug_type = name.split("-", 1)[0]
    if bug_type == "validity":
        return "validity_bugs"
    if bug_type == "bonus":
        return "bonus_bugs"
    return "functional_bugs"


def collect_bug_artifacts(results_crashes: Path, start_epoch: float) -> list[BugArtifact]:
    if not results_crashes.exists():
        return []
    artifacts: list[BugArtifact] = []
    for child in results_crashes.iterdir():
        if not child.is_file():
            continue
        relative = max(child.stat().st_mtime - start_epoch, 0.0)
        artifacts.append(BugArtifact(relative, bug_bucket_from_name(child.name)))
    artifacts.sort(key=lambda item: item.relative_time_sec)
    return artifacts


def main() -> None:
    args = parse_args()
    afl_plot_data = Path(args.afl_plot_data)
    fuzzer_stats = Path(args.fuzzer_stats)
    results_crashes = Path(args.results_crashes)
    output = Path(args.output)

    stats = parse_fuzzer_stats(fuzzer_stats)
    start_epoch = float(stats.get("start_time", "0") or 0.0)
    bug_artifacts = collect_bug_artifacts(results_crashes, start_epoch)

    with afl_plot_data.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, skipinitialspace=True)
        rows = [{(key or "").lstrip("# ").strip(): value for key, value in row.items()} for row in reader]

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

    written = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        artifact_index = 0
        validity = 0
        functional = 0
        bonus = 0

        for row in rows:
            relative_time = float(row["relative_time"])
            while artifact_index < len(bug_artifacts) and bug_artifacts[artifact_index].relative_time_sec <= relative_time:
                bucket = bug_artifacts[artifact_index].bug_bucket
                if bucket == "validity_bugs":
                    validity += 1
                elif bucket == "bonus_bugs":
                    bonus += 1
                else:
                    functional += 1
                artifact_index += 1

            coverage_seen = float(row["edges_found"])
            writer.writerow(
                {
                    "relative_time_sec": f"{relative_time:.6f}",
                    "total_execs": row["total_execs"],
                    "coverage_seen": f"{coverage_seen:.6f}",
                    "coverage_percent": f"{(coverage_seen / 65536.0) * 100.0:.6f}",
                    "interesting_test_cases": row["corpus_count"],
                    "corpus_size": row["corpus_count"],
                    "unique_bugs": validity + functional + bonus,
                    "unique_crashes": row["saved_crashes"],
                    "validity_bugs": validity,
                    "functional_bugs": functional,
                    "bonus_bugs": bonus,
                }
            )
            written += 1

    print(f"Wrote {written} AFL plot rows to {output}")


if __name__ == "__main__":
    main()
