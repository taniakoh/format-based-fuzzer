"""Aggregate finished fuzzing runs into report-ready metrics and curve CSVs.

This script scans run directories that already contain:
    - fuzzer_config
    - bug_coverage_summary.json
    - plot_data (or Atheris-compatible coverage logs via plot_progress helpers)

It produces:
    - report_metrics.json
    - report_metrics.md
    - curves/*.csv for the main RQ1/RQ3 graph families

The goal is to automate the PDF's evaluation requirements:
    RQ1: effectiveness over time/tests plus bug tables and saved crashes
    RQ2: time-to-first and average timing costs
    RQ3: baseline/ablation comparisons
    RQ4: stability across repeated runs
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, stdev
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_ROOT = ROOT / "results"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "report"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.plot_progress import load_atheris_rows, load_rows

CURVE_SPECS = (
    ("rq1_unique_crashes_vs_time", "relative_time_sec", "unique_crashes"),
    ("rq1_interesting_tests_vs_time", "relative_time_sec", "interesting_test_cases"),
    ("rq1_interesting_tests_vs_execs", "total_execs", "interesting_test_cases"),
    ("rq1_coverage_vs_time", "relative_time_sec", "coverage_percent"),
)

SUMMARY_METRICS = (
    "total_executions",
    "execs_per_sec",
    "coverage_seen",
    "coverage_percent",
    "interesting_test_cases",
    "interesting_results",
    "unique_findings",
    "unique_real_bugs",
    "unique_crashes",
    "time_to_first_interesting_result",
    "time_to_first_real_bug",
    "time_to_first_crash",
    "avg_generation_time_ms",
    "avg_execution_time_ms",
)


@dataclass
class RunData:
    run_dir: Path
    target: str
    evaluation_mode: str
    executor_mode: str
    time_budget_secs: float | None
    stats: dict[str, float | int | None]
    bug_type_totals: dict[str, int]
    plot_rows: list[dict[str, float]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate fuzzing run outputs into report-ready metrics and CSV curves."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=(
            "Run directories or parent directories to scan. Defaults to results/. "
            "A run directory must contain fuzzer_config and bug_coverage_summary.json."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for report_metrics.json, report_metrics.md, and curves/*.csv.",
    )
    parser.add_argument(
        "--min-runs",
        type=int,
        default=1,
        help="Only include target/mode groups with at least this many runs (default: 1).",
    )
    parser.add_argument(
        "--curve-points",
        type=int,
        default=25,
        help="Number of evenly-spaced aggregate sample points for each averaged curve (default: 25).",
    )
    return parser.parse_args()


def _safe_mean(values: list[float]) -> float | None:
    return mean(values) if values else None


def _safe_stdev(values: list[float]) -> float | None:
    return stdev(values) if len(values) >= 2 else None


def _round_optional(value: float | None, digits: int = 6) -> float | None:
    if value is None:
        return None
    return round(value, digits)


def _coerce_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _discover_candidate_dirs(path: Path) -> list[Path]:
    if path.is_file():
        path = path.parent

    candidates: list[Path] = []
    if (path / "fuzzer_config").exists() and (path / "bug_coverage_summary.json").exists():
        candidates.append(path)
        return candidates

    for cfg in path.rglob("fuzzer_config"):
        run_dir = cfg.parent
        if (run_dir / "bug_coverage_summary.json").exists():
            candidates.append(run_dir)
    return candidates


def _load_plot_rows(run_dir: Path) -> list[dict[str, float]]:
    plot_path = run_dir / "plot_data"
    if plot_path.exists():
        return load_rows(plot_path)
    atheris_rows = load_atheris_rows(run_dir)
    return atheris_rows


def _load_run(run_dir: Path) -> RunData:
    config = json.loads((run_dir / "fuzzer_config").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "bug_coverage_summary.json").read_text(encoding="utf-8"))
    plot_rows = _load_plot_rows(run_dir)

    run_scalars = summary.get("run_scalars", {})
    totals = summary.get("totals", {})

    stats = {
        "wall_time_secs": _coerce_float(run_scalars.get("wall_time_secs")),
        "total_executions": _coerce_float(run_scalars.get("total_executions")),
        "execs_per_sec": _coerce_float(run_scalars.get("execs_per_sec")),
        "pass_count": _coerce_float(run_scalars.get("pass_count")),
        "pass_rate": _coerce_float(run_scalars.get("pass_rate")),
        "coverage_seen": _coerce_float(run_scalars.get("coverage_seen")),
        "coverage_percent": _coerce_float(run_scalars.get("coverage_percent")),
        "interesting_test_cases": _coerce_float(run_scalars.get("interesting_test_cases")),
        "corpus_size": _coerce_float(run_scalars.get("corpus_size")),
        "avg_generation_time_ms": _coerce_float(run_scalars.get("avg_generation_time_ms")),
        "avg_execution_time_ms": _coerce_float(run_scalars.get("avg_execution_time_ms")),
        "interesting_results": _coerce_float(totals.get("interesting_results")),
        "unique_findings": _coerce_float(totals.get("unique_findings")),
        "unique_real_bugs": _coerce_float(totals.get("unique_real_bugs")),
        "unique_crashes": _coerce_float(totals.get("unique_crashes")),
    }

    if plot_rows:
        last_row = plot_rows[-1]
        _fill_missing_stat(stats, "coverage_seen", _coerce_float(last_row.get("coverage_seen")))
        _fill_missing_stat(stats, "coverage_percent", _coerce_float(last_row.get("coverage_percent")))
        _fill_missing_stat(stats, "interesting_test_cases", _coerce_float(last_row.get("interesting_test_cases")))
        _fill_missing_stat(stats, "unique_crashes", _coerce_float(last_row.get("unique_crashes")))
        _fill_missing_stat(stats, "total_executions", _coerce_float(last_row.get("total_execs")))

    stats_path = run_dir / "stats.txt"
    if stats_path.exists():
        stats.update(_parse_stats_txt(stats_path))

    return RunData(
        run_dir=run_dir,
        target=str(config.get("target", run_dir.name)),
        evaluation_mode=str(config.get("evaluation_mode_resolved", "unknown")),
        executor_mode=str(config.get("executor_mode", "unknown")),
        time_budget_secs=_coerce_float(config.get("time_budget_secs")),
        stats=stats,
        bug_type_totals={
            str(key): int(value)
            for key, value in summary.get("by_bug_type", {}).get("total", {}).items()
        },
        plot_rows=plot_rows,
    )


def _fill_missing_stat(stats: dict[str, float | int | None], key: str, value: float | None) -> None:
    if stats.get(key) is None and value is not None:
        stats[key] = value


def _parse_stats_txt(stats_path: Path) -> dict[str, float | None]:
    parsed: dict[str, float | None] = {}
    key_map = {
        "Time-to-1st-interesting": "time_to_first_interesting_result",
        "Time-to-1st-real-bug": "time_to_first_real_bug",
        "Time-to-1st-crash": "time_to_first_crash",
    }
    for line in stats_path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        label = label.strip()
        value = value.strip()
        metric_key = key_map.get(label)
        if metric_key is None:
            continue
        if value == "N/A":
            parsed[metric_key] = None
            continue
        number = value.split("s", 1)[0].strip()
        try:
            parsed[metric_key] = float(number)
        except ValueError:
            parsed[metric_key] = None
    return parsed


def discover_runs(paths: list[str]) -> list[RunData]:
    roots = [Path(p) for p in paths] if paths else [DEFAULT_RESULTS_ROOT]
    run_dirs: dict[Path, None] = {}
    for root in roots:
        for candidate in _discover_candidate_dirs(root):
            run_dirs[candidate.resolve()] = None
    runs = [_load_run(run_dir) for run_dir in sorted(run_dirs)]
    return runs


def _group_runs(runs: Iterable[RunData]) -> dict[tuple[str, str], list[RunData]]:
    groups: dict[tuple[str, str], list[RunData]] = defaultdict(list)
    for run in runs:
        groups[(run.target, run.evaluation_mode)].append(run)
    return dict(sorted(groups.items()))


def _metric_values(runs: list[RunData], metric: str) -> list[float]:
    values = []
    for run in runs:
        value = run.stats.get(metric)
        numeric = _coerce_float(value)
        if numeric is not None:
            values.append(numeric)
    return values


def _summarize_runs(runs: list[RunData]) -> dict[str, object]:
    summary: dict[str, object] = {
        "run_count": len(runs),
        "run_dirs": [str(run.run_dir) for run in runs],
        "executor_modes": sorted({run.executor_mode for run in runs}),
        "time_budgets_secs": sorted({
            float(run.time_budget_secs) for run in runs if run.time_budget_secs is not None
        }),
    }

    metrics: dict[str, object] = {}
    for metric in SUMMARY_METRICS:
        values = _metric_values(runs, metric)
        metrics[metric] = {
            "mean": _round_optional(_safe_mean(values), 6),
            "stdev": _round_optional(_safe_stdev(values), 6),
            "min": _round_optional(min(values), 6) if values else None,
            "max": _round_optional(max(values), 6) if values else None,
        }
    summary["metrics"] = metrics

    bug_type_totals: dict[str, list[int]] = defaultdict(list)
    for run in runs:
        for bug_type, count in run.bug_type_totals.items():
            bug_type_totals[bug_type].append(int(count))
    summary["bug_type_totals"] = {
        bug_type: {
            "mean": _round_optional(_safe_mean([float(v) for v in counts]), 6),
            "stdev": _round_optional(_safe_stdev([float(v) for v in counts]), 6),
            "min": min(counts),
            "max": max(counts),
        }
        for bug_type, counts in sorted(bug_type_totals.items())
    }
    return summary


def _sample_steps(runs: list[RunData], x_key: str, point_count: int) -> list[float]:
    maxima = []
    for run in runs:
        if run.plot_rows:
            maxima.append(float(run.plot_rows[-1].get(x_key, 0.0)))
    max_x = max(maxima, default=0.0)
    if max_x <= 0:
        return [0.0]
    if point_count <= 1:
        return [max_x]
    step = max_x / float(point_count - 1)
    return [step * idx for idx in range(point_count)]


def _interpolate_value(rows: list[dict[str, float]], x_key: str, y_key: str, target_x: float) -> float:
    if not rows:
        return 0.0
    previous = rows[0]
    if target_x <= float(previous.get(x_key, 0.0)):
        return float(previous.get(y_key, 0.0))
    for row in rows[1:]:
        current_x = float(row.get(x_key, 0.0))
        if current_x >= target_x:
            prev_x = float(previous.get(x_key, 0.0))
            prev_y = float(previous.get(y_key, 0.0))
            curr_y = float(row.get(y_key, 0.0))
            if math.isclose(current_x, prev_x):
                return curr_y
            ratio = (target_x - prev_x) / (current_x - prev_x)
            return prev_y + ratio * (curr_y - prev_y)
        previous = row
    return float(rows[-1].get(y_key, 0.0))


def _write_curve_csv(
    output_dir: Path,
    target: str,
    mode: str,
    curve_name: str,
    x_key: str,
    y_key: str,
    runs: list[RunData],
    point_count: int,
) -> str:
    curve_dir = output_dir / "curves"
    curve_dir.mkdir(parents=True, exist_ok=True)
    curve_path = curve_dir / f"{target}__{mode}__{curve_name}.csv"
    xs = _sample_steps(runs, x_key, point_count)
    with curve_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            x_key,
            f"{y_key}_mean",
            f"{y_key}_stdev",
            "run_count",
        ])
        for x in xs:
            values = [
                _interpolate_value(run.plot_rows, x_key, y_key, x)
                for run in runs
                if run.plot_rows
            ]
            writer.writerow([
                f"{x:.6f}",
                "" if not values else f"{mean(values):.6f}",
                "" if len(values) < 2 else f"{stdev(values):.6f}",
                len(values),
            ])
    return str(curve_path)


def _build_report(runs: list[RunData], min_runs: int, point_count: int, output_dir: Path) -> dict[str, object]:
    groups = _group_runs(runs)
    grouped_payload: dict[str, dict[str, object]] = defaultdict(dict)

    for (target, mode), grouped_runs in groups.items():
        if len(grouped_runs) < min_runs:
            continue
        payload = _summarize_runs(grouped_runs)
        payload["curves"] = {
            curve_name: _write_curve_csv(
                output_dir,
                target,
                mode,
                curve_name,
                x_key,
                y_key,
                grouped_runs,
                point_count,
            )
            for curve_name, x_key, y_key in CURVE_SPECS
        }
        grouped_payload[target][mode] = payload

    baseline = {}
    stability = {}
    for target, modes in sorted(grouped_payload.items()):
        baseline[target] = {}
        stability[target] = {}
        for mode, payload in sorted(modes.items()):
            metrics = payload["metrics"]
            baseline[target][mode] = {
                "run_count": payload["run_count"],
                "unique_crashes_mean": metrics["unique_crashes"]["mean"],
                "unique_real_bugs_mean": metrics["unique_real_bugs"]["mean"],
                "interesting_test_cases_mean": metrics["interesting_test_cases"]["mean"],
                "coverage_percent_mean": metrics["coverage_percent"]["mean"],
                "time_to_first_real_bug_mean": metrics["time_to_first_real_bug"]["mean"],
                "avg_generation_time_ms_mean": metrics["avg_generation_time_ms"]["mean"],
                "avg_execution_time_ms_mean": metrics["avg_execution_time_ms"]["mean"],
            }
            stability[target][mode] = {
                "run_count": payload["run_count"],
                "unique_crashes_stdev": metrics["unique_crashes"]["stdev"],
                "interesting_test_cases_stdev": metrics["interesting_test_cases"]["stdev"],
                "coverage_percent_stdev": metrics["coverage_percent"]["stdev"],
            }

    return {
        "summary": {
            "discovered_runs": len(runs),
            "included_targets": sorted(grouped_payload.keys()),
            "minimum_runs_required": min_runs,
            "curve_points": point_count,
        },
        "targets": grouped_payload,
        "rq3_baseline_comparison": baseline,
        "rq4_stability": stability,
    }


def _fmt_stat_block(block: dict[str, object]) -> str:
    mean_val = block.get("mean")
    stdev_val = block.get("stdev")
    if mean_val is None:
        return "N/A"
    if stdev_val is None:
        return f"{mean_val}"
    return f"{mean_val} +/- {stdev_val}"


def _render_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Report Metrics",
        "",
        "Generated from finished fuzzing runs for the PDF's RQ1-RQ4 evaluation needs.",
        "",
    ]

    summary = report["summary"]
    lines.extend([
        "## Summary",
        "",
        f"- Discovered runs: {summary['discovered_runs']}",
        f"- Included targets: {', '.join(summary['included_targets']) if summary['included_targets'] else 'none'}",
        f"- Minimum runs required per group: {summary['minimum_runs_required']}",
        "",
    ])

    targets: dict[str, dict[str, object]] = report["targets"]
    for target, modes in sorted(targets.items()):
        lines.extend([f"## Target: {target}", ""])
        for mode, payload in sorted(modes.items()):
            metrics = payload["metrics"]
            lines.extend([
                f"### Mode: {mode}",
                "",
                f"- Runs: {payload['run_count']}",
                f"- Unique crashes: {_fmt_stat_block(metrics['unique_crashes'])}",
                f"- Unique real bugs: {_fmt_stat_block(metrics['unique_real_bugs'])}",
                f"- Interesting test cases: {_fmt_stat_block(metrics['interesting_test_cases'])}",
                f"- Coverage percent: {_fmt_stat_block(metrics['coverage_percent'])}",
                f"- Time-to-first-real-bug (s): {_fmt_stat_block(metrics['time_to_first_real_bug'])}",
                f"- Avg generation time (ms): {_fmt_stat_block(metrics['avg_generation_time_ms'])}",
                f"- Avg execution time (ms): {_fmt_stat_block(metrics['avg_execution_time_ms'])}",
                "",
                "Curve CSVs:",
            ])
            for curve_name, curve_path in sorted(payload["curves"].items()):
                lines.append(f"- `{curve_name}`: `{curve_path}`")
            lines.append("")

    lines.extend([
        "## Notes",
        "",
        "- Use the averaged curve CSVs for the PDF's wall-clock and #tests graphs.",
        "- For fair RQ3/RQ4 claims, collect at least five runs per target/mode before using the aggregated means.",
        "- Repro inputs remain in each run directory's `crashes/`, `queue/`, and `unique_bugs.json` outputs.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    runs = discover_runs(args.paths)
    report = _build_report(runs, args.min_runs, args.curve_points, output_dir)

    json_path = output_dir / "report_metrics.json"
    md_path = output_dir / "report_metrics.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
