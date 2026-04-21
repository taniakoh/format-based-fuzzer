"""Plot cumulative unique bugs discovered over wall-clock time.

This utility reconstructs a bugs-vs-time curve from existing run artifacts in
``results/<target>/``. It prefers canonical unique-bug entries from
``unique_bugs.json`` and maps each bug's ``first_seen_exec`` to a relative
timestamp using ``oracle_log.csv``. When those files are unavailable, it falls
back to ``plot_data`` if that already contains a usable ``unique_bugs`` series.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a cumulative unique-bugs-over-time CSV and SVG from an existing run directory."
    )
    parser.add_argument(
        "target_or_run_dir",
        help="Target name like 'ipv4' or a direct path to a run directory under results/.",
    )
    parser.add_argument(
        "--output",
        help="Output SVG path. Defaults to <run_dir>/bugs_over_time.svg.",
    )
    parser.add_argument(
        "--csv-output",
        help="Output CSV path. Defaults to <run_dir>/bugs_over_time.csv.",
    )
    return parser.parse_args()


def resolve_run_dir(target_or_run_dir: str) -> Path:
    candidate = Path(target_or_run_dir)
    results_candidate = RESULTS_DIR / target_or_run_dir

    def _looks_like_run_dir(path: Path) -> bool:
        return any(
            (path / name).exists()
            for name in ("unique_bugs.json", "oracle_log.csv", "plot_data", "bugs.jsonl")
        )

    if candidate.exists():
        if candidate.is_file():
            return candidate.parent
        if _looks_like_run_dir(candidate):
            return candidate
        if results_candidate.exists():
            return results_candidate
        return candidate

    return results_candidate


def load_plot_rows(run_dir: Path) -> list[dict[str, float]]:
    plot_path = run_dir / "plot_data"
    if not plot_path.exists():
        return []

    rows: list[dict[str, float]] = []
    with plot_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed: dict[str, float] = {}
            for key, value in row.items():
                if value is None or value == "":
                    continue
                parsed[key] = float(value)
            if "coverage_seen" not in parsed and "behaviors_seen" in parsed:
                parsed["coverage_seen"] = parsed["behaviors_seen"]
            rows.append(parsed)
    return rows


def load_oracle_exec_times(run_dir: Path) -> list[float]:
    oracle_path = run_dir / "oracle_log.csv"
    if not oracle_path.exists():
        return []

    times: list[float] = []
    with oracle_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            value = row.get("relative_time_sec")
            if value:
                times.append(float(value))
    return times


def interpolate_time_from_plot(exec_no: int, plot_rows: list[dict[str, float]]) -> float | None:
    if exec_no <= 0 or not plot_rows:
        return None

    previous = plot_rows[0]
    prev_exec = int(previous.get("total_execs", 0.0))
    prev_time = float(previous.get("relative_time_sec", 0.0))
    if exec_no <= prev_exec:
        return prev_time

    for row in plot_rows[1:]:
        curr_exec = int(row.get("total_execs", 0.0))
        curr_time = float(row.get("relative_time_sec", 0.0))
        if exec_no <= curr_exec:
            if curr_exec == prev_exec:
                return curr_time
            ratio = (exec_no - prev_exec) / float(curr_exec - prev_exec)
            return prev_time + ratio * (curr_time - prev_time)
        previous = row
        prev_exec = curr_exec
        prev_time = curr_time

    return float(plot_rows[-1].get("relative_time_sec", 0.0))


def infer_time_for_exec(exec_no: int, oracle_times: list[float], plot_rows: list[dict[str, float]]) -> float | None:
    if 1 <= exec_no <= len(oracle_times):
        return oracle_times[exec_no - 1]
    return interpolate_time_from_plot(exec_no, plot_rows)


def load_unique_bug_entries(run_dir: Path) -> list[dict[str, object]]:
    unique_path = run_dir / "unique_bugs.json"
    if not unique_path.exists():
        return []
    payload = json.loads(unique_path.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    return entries if isinstance(entries, list) else []


def build_curve_from_unique_bugs(
    run_dir: Path,
    plot_rows: list[dict[str, float]],
) -> tuple[list[dict[str, float]], dict[str, object]] | None:
    entries = load_unique_bug_entries(run_dir)
    if not entries:
        return None

    oracle_times = load_oracle_exec_times(run_dir)
    bug_points: list[dict[str, float]] = []
    bug_type_counts: Counter[str] = Counter()

    for entry in sorted(entries, key=lambda item: int(item.get("first_seen_exec", 0) or 0)):
        exec_no = int(entry.get("first_seen_exec", 0) or 0)
        if exec_no <= 0:
            continue
        timestamp = infer_time_for_exec(exec_no, oracle_times, plot_rows)
        if timestamp is None:
            continue
        bug_type = str(entry.get("bug_type", "unknown"))
        bug_type_counts[bug_type] += 1
        bug_points.append(
            {
                "relative_time_sec": float(timestamp),
                "unique_bugs": float(len(bug_points) + 1),
                "first_seen_exec": float(exec_no),
            }
        )

    if not bug_points:
        return None

    final_time = max(
        bug_points[-1]["relative_time_sec"],
        float(plot_rows[-1].get("relative_time_sec", 0.0)) if plot_rows else 0.0,
        oracle_times[-1] if oracle_times else 0.0,
    )

    curve = [{"relative_time_sec": 0.0, "unique_bugs": 0.0, "first_seen_exec": 0.0}]
    curve.extend(bug_points)
    if final_time > curve[-1]["relative_time_sec"]:
        curve.append(
            {
                "relative_time_sec": float(final_time),
                "unique_bugs": float(curve[-1]["unique_bugs"]),
                "first_seen_exec": float(curve[-1]["first_seen_exec"]),
            }
        )

    metadata = {
        "source": "unique_bugs.json + oracle_log.csv",
        "unique_bug_count": int(len(bug_points)),
        "bug_type_counts": dict(sorted(bug_type_counts.items())),
    }
    return curve, metadata


def build_curve_from_plot_data(plot_rows: list[dict[str, float]]) -> tuple[list[dict[str, float]], dict[str, object]] | None:
    if not plot_rows:
        return None
    if not any("unique_bugs" in row for row in plot_rows):
        return None

    curve = [
        {
            "relative_time_sec": float(row.get("relative_time_sec", 0.0)),
            "unique_bugs": float(row.get("unique_bugs", 0.0)),
            "first_seen_exec": float(row.get("total_execs", 0.0)),
        }
        for row in plot_rows
    ]
    if not curve:
        return None

    if curve[0]["relative_time_sec"] > 0.0 or curve[0]["unique_bugs"] > 0.0:
        curve.insert(0, {"relative_time_sec": 0.0, "unique_bugs": 0.0, "first_seen_exec": 0.0})

    metadata = {
        "source": "plot_data",
        "unique_bug_count": int(curve[-1]["unique_bugs"]),
        "bug_type_counts": {},
    }
    return curve, metadata


def build_bug_curve(run_dir: Path) -> tuple[list[dict[str, float]], dict[str, object]]:
    plot_rows = load_plot_rows(run_dir)
    from_unique = build_curve_from_unique_bugs(run_dir, plot_rows)
    if from_unique is not None:
        return from_unique

    from_plot = build_curve_from_plot_data(plot_rows)
    if from_plot is not None:
        return from_plot

    raise FileNotFoundError(
        f"Could not reconstruct bug curve from {run_dir}. "
        "Expected unique_bugs.json + oracle_log.csv or a populated plot_data file."
    )


def write_curve_csv(curve: list[dict[str, float]], csv_path: Path) -> None:
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["relative_time_sec", "unique_bugs", "first_seen_exec"])
        for row in curve:
            writer.writerow(
                [
                    f"{row['relative_time_sec']:.6f}",
                    int(row["unique_bugs"]),
                    int(row["first_seen_exec"]),
                ]
            )


def _format_bug_type_summary(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return " | ".join(f"{bug_type}: {count}" for bug_type, count in counts.items())


def _step_polyline_points(curve: list[dict[str, float]], width: int, height: int) -> str:
    left = 72
    right = width - 28
    top = 44
    bottom = height - 64
    plot_width = right - left
    plot_height = bottom - top

    max_time = max(float(row["relative_time_sec"]) for row in curve)
    max_bugs = max(float(row["unique_bugs"]) for row in curve)
    time_span = max(max_time, 1.0)
    bug_span = max(max_bugs, 1.0)

    def scale_x(value: float) -> float:
        return left + (value / time_span) * plot_width

    def scale_y(value: float) -> float:
        return bottom - (value / bug_span) * plot_height

    coords: list[tuple[float, float]] = []
    first = curve[0]
    coords.append((scale_x(float(first["relative_time_sec"])), scale_y(float(first["unique_bugs"]))))
    for prev, curr in zip(curve, curve[1:]):
        x_curr = scale_x(float(curr["relative_time_sec"]))
        y_prev = scale_y(float(prev["unique_bugs"]))
        y_curr = scale_y(float(curr["unique_bugs"]))
        coords.append((x_curr, y_prev))
        coords.append((x_curr, y_curr))
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)


def render_svg(run_name: str, curve: list[dict[str, float]], metadata: dict[str, object], svg_path: Path) -> None:
    width = 960
    height = 540
    left = 72
    right = width - 28
    top = 44
    bottom = height - 64
    plot_width = right - left
    plot_height = bottom - top

    max_time = max(float(row["relative_time_sec"]) for row in curve)
    max_bugs = max(float(row["unique_bugs"]) for row in curve)
    time_span = max(max_time, 1.0)
    bug_span = max(max_bugs, 1.0)

    polyline = _step_polyline_points(curve, width, height)
    bug_summary = _format_bug_type_summary(metadata.get("bug_type_counts", {}))

    y_ticks: list[str] = []
    for i in range(5):
        value = bug_span * i / 4.0
        y = bottom - (value / bug_span) * plot_height
        y_ticks.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{right}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1" />'
            f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="#475569">{int(round(value))}</text>'
        )

    x_ticks: list[str] = []
    for i in range(5):
        value = time_span * i / 4.0
        x = left + (value / time_span) * plot_width
        x_ticks.append(
            f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{bottom}" stroke="#f1f5f9" stroke-width="1" />'
            f'<text x="{x:.1f}" y="{bottom + 24}" text-anchor="middle" font-size="12" fill="#475569">{value:.1f}s</text>'
        )

    final_bugs = int(curve[-1]["unique_bugs"])
    final_time = float(curve[-1]["relative_time_sec"])
    subtitle = (
        f"Source: {metadata.get('source', 'unknown')} | "
        f"Final unique bugs: {final_bugs} | Final time: {final_time:.1f}s"
    )

    extra_line = f"<text x=\"36\" y=\"72\" font-size=\"12\" fill=\"#64748b\">{bug_summary}</text>" if bug_summary else ""

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">Unique bugs over time for {run_name}</title>
  <desc id="desc">Step chart showing cumulative unique bugs found over wall-clock time.</desc>
  <rect width="100%" height="100%" fill="#ffffff" />
  <text x="36" y="36" font-size="24" font-weight="700" fill="#0f172a">Unique bugs over time: {run_name}</text>
  <text x="36" y="54" font-size="13" fill="#475569">{subtitle}</text>
  {extra_line}
  <rect x="{left}" y="{top}" width="{plot_width}" height="{plot_height}" rx="8" fill="#f8fafc" stroke="#e2e8f0" />
  {''.join(y_ticks)}
  {''.join(x_ticks)}
  <line x1="{left}" y1="{bottom}" x2="{right}" y2="{bottom}" stroke="#0f172a" stroke-width="1.5" />
  <line x1="{left}" y1="{top}" x2="{left}" y2="{bottom}" stroke="#0f172a" stroke-width="1.5" />
  <polyline points="{polyline}" fill="none" stroke="#b91c1c" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" />
  <text x="{(left + right) / 2:.1f}" y="{height - 18}" text-anchor="middle" font-size="13" fill="#334155">Relative time (seconds)</text>
  <text x="18" y="{(top + bottom) / 2:.1f}" text-anchor="middle" font-size="13" fill="#334155" transform="rotate(-90 18 {(top + bottom) / 2:.1f})">Cumulative unique bugs</text>
</svg>
"""
    svg_path.write_text(svg, encoding="utf-8")


def main() -> None:
    args = parse_args()
    run_dir = resolve_run_dir(args.target_or_run_dir)
    if not run_dir.exists():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    curve, metadata = build_bug_curve(run_dir)
    csv_path = Path(args.csv_output) if args.csv_output else run_dir / "bugs_over_time.csv"
    svg_path = Path(args.output) if args.output else run_dir / "bugs_over_time.svg"

    write_curve_csv(curve, csv_path)
    render_svg(run_dir.name, curve, metadata, svg_path)

    print(f"Wrote {csv_path}")
    print(f"Wrote {svg_path}")


if __name__ == "__main__":
    main()
