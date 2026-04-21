"""Render a readable SVG dashboard from results/<target>/plot_data."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
SERIES = (
    ("coverage_percent", "#1d4ed8", "Coverage"),
    ("unique_bugs", "#b91c1c", "Unique bugs"),
    ("corpus_size", "#047857", "Corpus size"),
    ("unique_crashes", "#7c3aed", "Unique crashes"),
)
BUG_TYPE_SERIES = (
    ("validity_bugs", "#b91c1c", "Validity"),
    ("functional_bugs", "#d97706", "Functional"),
    ("bonus_bugs", "#7c3aed", "Bonus"),
)
DL_SERIES = (
    ("loss", "#d97706", "DL Training Loss"),
    ("misprediction_rate", "#db2777", "Misprediction Rate"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an SVG progress chart from a fuzzing plot_data CSV."
    )
    parser.add_argument(
        "target_or_plot_data",
        help="Target name like 'ipv4' or a direct path to a plot_data CSV file.",
    )
    parser.add_argument(
        "--output",
        help="Output SVG path. Defaults to results/<target>/progress.svg or plot_data.svg next to the CSV.",
    )
    return parser.parse_args()


def resolve_paths(target_or_plot_data: str, output: str | None) -> tuple[Path, Path]:
    target_path = Path(target_or_plot_data)
    results_candidate = RESULTS_DIR / target_or_plot_data

    def _looks_like_run_dir(path: Path) -> bool:
        return any(
            (path / name).exists()
            for name in ("plot_data", "unique_bugs.json", "oracle_log.csv", "bugs.jsonl")
        )

    if target_path.exists():
        if target_path.is_file():
            plot_path = target_path
            default_output = plot_path.with_suffix(".svg")
        elif _looks_like_run_dir(target_path):
            plot_path = target_path / "plot_data"
            default_output = target_path / "progress.svg"
        elif results_candidate.exists():
            plot_path = results_candidate / "plot_data"
            default_output = results_candidate / "progress.svg"
        else:
            plot_path = target_path
            default_output = plot_path.with_suffix(".svg")
    else:
        plot_path = results_candidate / "plot_data"
        default_output = results_candidate / "progress.svg"

    if not plot_path.exists():
        raise FileNotFoundError(f"Could not find plot data at {plot_path}")

    output_path = Path(output) if output else default_output
    return plot_path, output_path


def load_rows(plot_path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with plot_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed = {key: float(value) for key, value in row.items()}
            if "coverage_seen" not in parsed and "behaviors_seen" in parsed:
                parsed["coverage_seen"] = parsed["behaviors_seen"]
            # interesting_test_cases falls back to corpus_size (ISTD graphs)
            if "interesting_test_cases" not in parsed:
                parsed["interesting_test_cases"] = parsed.get("corpus_size", 0.0)
            # backward compat: older plot_data files lack these columns
            parsed.setdefault("validity_bugs", 0.0)
            parsed.setdefault("functional_bugs", 0.0)
            parsed.setdefault("bonus_bugs", 0.0)
            t = parsed.get("relative_time_sec", 0.0)
            parsed["execs_per_sec"] = parsed.get("total_execs", 0.0) / t if t > 0 else 0.0
            rows.append(parsed)
    return add_bitmap_coverage_percent(rows)


def add_bitmap_coverage_percent(rows: list[dict[str, float]]) -> list[dict[str, float]]:
    """Add percentage-of-bitmap coverage for fixed-size bitmap targets."""
    for row in rows:
        coverage = float(row.get("coverage_seen", 0.0))
        row["coverage_percent"] = (coverage / 65536.0) * 100.0
    return rows


def add_atheris_coverage_percent(rows: list[dict[str, float]]) -> list[dict[str, float]]:
    """Add percentage-of-final-observed coverage for Atheris targets.

    Atheris/libFuzzer logs expose ``cov`` as a raw count but do not report the
    total number of instrumentable units, so we normalize against the final
    observed ``cov`` from the current run instead of claiming an absolute total.
    """
    if not rows:
        return rows

    final_cov = max(float(rows[-1].get("coverage_seen", 0.0)), 1.0)
    for row in rows:
        coverage = float(row.get("coverage_seen", 0.0))
        row["coverage_percent"] = (coverage / final_cov) * 100.0
    return rows


def load_atheris_replay_coverage(results_dir: Path) -> dict | None:
    """Load saved coverage.py replay totals for an Atheris run if present."""
    coverage_path = results_dir / "coverage_replay.json"
    if not coverage_path.exists():
        return None
    return json.loads(coverage_path.read_text(encoding="utf-8"))


def apply_atheris_replay_coverage(
    rows: list[dict[str, float]],
    coverage_payload: dict | None,
) -> list[dict[str, float]]:
    """Replace relative Atheris coverage with replayed source coverage when available."""
    if not rows or not coverage_payload:
        return add_atheris_coverage_percent(rows)

    checkpoints = sorted(
        (
            int(entry.get("corpus_size", 0)),
            float(entry.get("percent_covered", 0.0)),
        )
        for entry in coverage_payload.get("rows", [])
        if int(entry.get("corpus_size", 0)) > 0
    )
    if not checkpoints:
        return add_atheris_coverage_percent(rows)

    checkpoint_idx = 0
    current_percent = checkpoints[0][1]
    for row in rows:
        corpus_size = int(row.get("corpus_size", 0))
        while checkpoint_idx + 1 < len(checkpoints) and checkpoints[checkpoint_idx + 1][0] <= corpus_size:
            checkpoint_idx += 1
            current_percent = checkpoints[checkpoint_idx][1]
        row["coverage_percent"] = current_percent
    return rows


def load_atheris_rows(results_dir: Path) -> list[dict[str, float]]:
    """Parse results/json/atheris.log into the same row format as plot_data.

    libFuzzer emits lines like:
        #2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 33Mb
        #1024   pulse  cov: 5 ft: 7 corp: 2/15b exec/s: 1024 rss: 40Mb
    Time is estimated by accumulating exec_count / exec_s deltas.
    Unique bugs and crashes are read from the results directory.
    """
    import re
    log_path = results_dir / "atheris.log"
    if not log_path.exists():
        return []

    line_re = re.compile(
        r"^#(\d+)\s+\S+\s+cov:\s*(\d+).*?corp:\s*(\d+)/.*?exec/s:\s*(\d+)",
    )

    crashes_dir = results_dir / "crashes"
    bug_csv = results_dir / "logs" / "bug_counts.csv"

    # Count unique crashes from the crashes directory
    unique_crashes = len(list(crashes_dir.glob("*"))) if crashes_dir.exists() else 0
    # Count unique bugs from bug_counts.csv
    unique_bugs = 0
    if bug_csv.exists():
        with bug_csv.open("r", encoding="utf-8") as f:
            unique_bugs = sum(1 for row in csv.DictReader(f))

    rows: list[dict[str, float]] = []
    rel_time = 0.0
    prev_execs = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = line_re.match(line.strip())
            if not m:
                continue
            execs = int(m.group(1))
            cov = int(m.group(2))
            corp = int(m.group(3))
            exec_s = int(m.group(4))

            delta = execs - prev_execs
            if exec_s > 0:
                rel_time += delta / exec_s
            prev_execs = execs

            rows.append({
                "relative_time_sec": rel_time,
                "total_execs": float(execs),
                "coverage_seen": float(cov),
                "corpus_size": float(corp),
                "interesting_test_cases": float(corp),
                "unique_bugs": float(unique_bugs),
                "unique_crashes": float(unique_crashes),
                "validity_bugs": 0.0,
                "functional_bugs": 0.0,
                "bonus_bugs": 0.0,
                "execs_per_sec": float(exec_s),
            })

    return apply_atheris_replay_coverage(rows, load_atheris_replay_coverage(results_dir))


def load_dl_rows(results_dir: Path) -> list[dict[str, float]]:
    """Load DL training events from dl_training.jsonl if present."""
    dl_path = results_dir / "dl_training.jsonl"
    if not dl_path.exists():
        return []
    rows = []
    with dl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entry = json.loads(line)
                rows.append({
                    "relative_time_sec": float(entry.get("relative_time_sec", 0)),
                    "loss": float(entry.get("loss", 0)),
                    "misprediction_rate": float(entry.get("misprediction_rate", 0)),
                })
    return rows


def load_oracle_exec_times(results_dir: Path) -> list[float]:
    oracle_path = results_dir / "oracle_log.csv"
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


def load_unique_bug_entries(results_dir: Path) -> list[dict[str, object]]:
    unique_path = results_dir / "unique_bugs.json"
    if not unique_path.exists():
        return []
    payload = json.loads(unique_path.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    return entries if isinstance(entries, list) else []


def interpolate_time_from_plot(exec_no: int, rows: list[dict[str, float]]) -> float | None:
    if exec_no <= 0 or not rows:
        return None

    previous = rows[0]
    prev_exec = int(previous.get("total_execs", 0.0))
    prev_time = float(previous.get("relative_time_sec", 0.0))
    if exec_no <= prev_exec:
        return prev_time

    for row in rows[1:]:
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

    return float(rows[-1].get("relative_time_sec", 0.0))


def infer_time_for_exec(exec_no: int, oracle_times: list[float], rows: list[dict[str, float]]) -> float | None:
    if 1 <= exec_no <= len(oracle_times):
        return oracle_times[exec_no - 1]
    return interpolate_time_from_plot(exec_no, rows)


def build_bug_curve(results_dir: Path, rows: list[dict[str, float]]) -> tuple[list[dict[str, float]], dict[str, object]] | None:
    entries = load_unique_bug_entries(results_dir)
    if entries:
        oracle_times = load_oracle_exec_times(results_dir)
        bug_points: list[dict[str, float]] = []
        bug_type_counts: Counter[str] = Counter()

        for entry in sorted(entries, key=lambda item: int(item.get("first_seen_exec", 0) or 0)):
            exec_no = int(entry.get("first_seen_exec", 0) or 0)
            if exec_no <= 0:
                continue
            timestamp = infer_time_for_exec(exec_no, oracle_times, rows)
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

        if bug_points:
            final_time = max(
                bug_points[-1]["relative_time_sec"],
                float(rows[-1].get("relative_time_sec", 0.0)) if rows else 0.0,
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
            return curve, {
                "source": "unique_bugs.json + oracle_log.csv",
                "bug_type_counts": dict(sorted(bug_type_counts.items())),
            }

    if rows and any("unique_bugs" in row for row in rows):
        curve = [
            {
                "relative_time_sec": float(row.get("relative_time_sec", 0.0)),
                "unique_bugs": float(row.get("unique_bugs", 0.0)),
                "first_seen_exec": float(row.get("total_execs", 0.0)),
            }
            for row in rows
        ]
        if curve and (curve[0]["relative_time_sec"] > 0.0 or curve[0]["unique_bugs"] > 0.0):
            curve.insert(0, {"relative_time_sec": 0.0, "unique_bugs": 0.0, "first_seen_exec": 0.0})
        return curve, {"source": "plot_data", "bug_type_counts": {}}

    return None


def apply_bug_curve_to_rows(results_dir: Path, rows: list[dict[str, float]]) -> tuple[list[dict[str, float]], dict[str, object] | None]:
    payload = build_bug_curve(results_dir, rows)
    if payload is None:
        return rows, None

    bug_curve, metadata = payload
    curve_idx = 0
    current_unique_bugs = 0.0

    if rows:
        enriched_rows = [dict(row) for row in rows]
        for row in enriched_rows:
            current_time = float(row.get("relative_time_sec", 0.0))
            while curve_idx + 1 < len(bug_curve) and float(bug_curve[curve_idx + 1]["relative_time_sec"]) <= current_time:
                curve_idx += 1
                current_unique_bugs = float(bug_curve[curve_idx]["unique_bugs"])
            row["unique_bugs"] = current_unique_bugs
        return enriched_rows, metadata

    synthetic_rows: list[dict[str, float]] = []
    for point in bug_curve:
        t = float(point["relative_time_sec"])
        synthetic_rows.append(
            {
                "relative_time_sec": t,
                "total_execs": float(point.get("first_seen_exec", 0.0)),
                "coverage_seen": 0.0,
                "coverage_percent": 0.0,
                "interesting_test_cases": 0.0,
                "corpus_size": 0.0,
                "unique_bugs": float(point["unique_bugs"]),
                "unique_crashes": 0.0,
                "validity_bugs": 0.0,
                "functional_bugs": 0.0,
                "bonus_bugs": 0.0,
                "execs_per_sec": (float(point.get("first_seen_exec", 0.0)) / t) if t > 0 else 0.0,
            }
        )
    return synthetic_rows, metadata


def svg_polyline(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def scale_x(times: list[float], x0: float, width: float) -> list[float]:
    plot_left = x0 + 44
    plot_right = x0 + width - 16
    plot_width = plot_right - plot_left
    if len(times) == 1 or times[-1] <= times[0]:
        return [plot_left + plot_width / 2 for _ in times]
    start = times[0]
    span = times[-1] - start
    return [plot_left + ((t - start) / span) * plot_width for t in times]


def scale_y(values: list[float], y0: float, height: float) -> tuple[list[float], float]:
    plot_top = y0 + 38
    plot_bottom = y0 + height - 28
    plot_height = plot_bottom - plot_top
    max_val = max(max(values), 1.0)
    return [plot_bottom - (value / max_val) * plot_height for value in values], max_val


def render_panel(
    rows: list[dict[str, float]],
    key: str,
    color: str,
    label: str,
    x0: float,
    y0: float,
    width: float,
    height: float,
    is_float: bool = False,
    final_note: str | None = None,
) -> str:
    times = [row["relative_time_sec"] for row in rows]
    values = [row[key] for row in rows]
    xs = scale_x(times, x0, width)
    ys, y_max = scale_y(values, y0, height)
    points = list(zip(xs, ys))
    mid_y = (y0 + 38 + y0 + height - 28) / 2
    end_x, end_y = points[-1]

    fmt = (lambda v: f"{v:.3f}") if is_float else (lambda v: str(int(v)))

    subtitle = final_note if final_note is not None else f"Final: {fmt(values[-1])}"

    parts = [
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{width:.1f}" height="{height:.1f}" rx="14" fill="#ffffff" stroke="#cbd5e1" />',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 28:.1f}" font-size="19" font-weight="700" fill="#0f172a">{label}</text>',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 50:.1f}" font-size="14" fill="#475569">{subtitle}</text>',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + 22:.1f}" x2="{x0 + 44:.1f}" y2="{y0 + height - 28:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + height - 28:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + height - 28:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + 38:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + 38:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<line x1="{x0 + 44:.1f}" y1="{mid_y:.1f}" x2="{x0 + width - 16:.1f}" y2="{mid_y:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + height - 28:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + height - 28:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<text x="{x0 + 10:.1f}" y="{y0 + 42:.1f}" font-size="12" fill="#64748b">{fmt(y_max)}</text>',
        f'<text x="{x0 + 10:.1f}" y="{mid_y + 4:.1f}" font-size="12" fill="#64748b">{fmt(y_max / 2)}</text>',
        f'<text x="{x0 + 18:.1f}" y="{y0 + height - 24:.1f}" font-size="12" fill="#64748b">0</text>',
        f'<text x="{x0 + 44:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[0]:.0f}s</text>',
        f'<text x="{x0 + width - 46:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[-1]:.0f}s</text>',
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{svg_polyline(points)}" />',
        f'<circle cx="{end_x:.1f}" cy="{end_y:.1f}" r="4" fill="{color}" />',
    ]
    return "".join(parts)


def render_multi_panel(
    rows: list[dict[str, float]],
    series_list: tuple,
    label: str,
    x0: float,
    y0: float,
    width: float,
    height: float,
) -> str:
    """Render a panel with multiple polylines sharing the same axes."""
    times = [row["relative_time_sec"] for row in rows]
    xs = scale_x(times, x0, width)

    # Shared y-axis: max across all series
    all_values = [row.get(key, 0.0) for key, _, _ in series_list for row in rows]
    y_max = max(max(all_values), 1.0)
    plot_top = y0 + 62
    plot_bottom = y0 + height - 28
    plot_height = plot_bottom - plot_top

    def to_y(v: float) -> float:
        return plot_bottom - (v / y_max) * plot_height

    mid_y = (plot_top + plot_bottom) / 2

    # Legend: colored dots + labels spaced across the top
    legend_parts = []
    legend_x = x0 + 16
    for key, color, sublabel in series_list:
        legend_parts.append(
            f'<circle cx="{legend_x:.1f}" cy="{y0 + 50:.1f}" r="5" fill="{color}" />'
            f'<text x="{legend_x + 9:.1f}" y="{y0 + 55:.1f}" font-size="13" fill="#475569">{sublabel}</text>'
        )
        legend_x += 90

    parts = [
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{width:.1f}" height="{height:.1f}" rx="14" fill="#ffffff" stroke="#cbd5e1" />',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 28:.1f}" font-size="19" font-weight="700" fill="#0f172a">{label}</text>',
        *legend_parts,
        f'<line x1="{x0 + 44:.1f}" y1="{plot_top - 16:.1f}" x2="{x0 + 44:.1f}" y2="{plot_bottom:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{plot_bottom:.1f}" x2="{x0 + width - 16:.1f}" y2="{plot_bottom:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{plot_top:.1f}" x2="{x0 + width - 16:.1f}" y2="{plot_top:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<line x1="{x0 + 44:.1f}" y1="{mid_y:.1f}" x2="{x0 + width - 16:.1f}" y2="{mid_y:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<text x="{x0 + 10:.1f}" y="{plot_top + 4:.1f}" font-size="12" fill="#64748b">{int(y_max)}</text>',
        f'<text x="{x0 + 10:.1f}" y="{mid_y + 4:.1f}" font-size="12" fill="#64748b">{int(y_max / 2)}</text>',
        f'<text x="{x0 + 18:.1f}" y="{plot_bottom - 4:.1f}" font-size="12" fill="#64748b">0</text>',
        f'<text x="{x0 + 44:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[0]:.0f}s</text>',
        f'<text x="{x0 + width - 46:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[-1]:.0f}s</text>',
    ]

    for key, color, _ in series_list:
        values = [row.get(key, 0.0) for row in rows]
        ys = [to_y(v) for v in values]
        points = list(zip(xs, ys))
        end_x, end_y = points[-1]
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{svg_polyline(points)}" />')
        parts.append(f'<circle cx="{end_x:.1f}" cy="{end_y:.1f}" r="4" fill="{color}" />')

    return "".join(parts)


def render_svg(
    rows: list[dict[str, float]],
    title: str,
    dl_rows: list[dict[str, float]] | None = None,
    coverage_label: str = "Coverage",
    coverage_note: str | None = None,
    bug_note: str | None = None,
) -> str:
    if not rows:
        return render_empty_svg(title)

    panel_width = 500
    panel_height = 300
    panel_left = 72
    panel_top = 110
    panel_gap_x = 56
    panel_gap_y = 38

    dl_section_height = 0
    if dl_rows:
        dl_section_height = 60 + panel_height + panel_gap_y

    width = 1200
    height = panel_top + 3 * (panel_height + panel_gap_y) + dl_section_height + 40
    header_x = 72
    final_execs_per_sec = rows[-1].get("execs_per_sec", 0.0)
    summary = (
        f"Samples: {len(rows)} | Final execs: {int(rows[-1]['total_execs'])} | "
        f"Final time: {rows[-1]['relative_time_sec']:.1f}s | "
        f"Execs/s: {final_execs_per_sec:.0f}"
    )

    panels = []
    for index, (key, color, label) in enumerate(SERIES):
        row_idx = index // 2
        col_idx = index % 2
        x0 = panel_left + col_idx * (panel_width + panel_gap_x)
        y0 = panel_top + row_idx * (panel_height + panel_gap_y)
        panel_label = coverage_label if key == "coverage_percent" else label
        if key == "coverage_percent":
            panel_note = coverage_note
        elif key == "unique_bugs":
            panel_note = bug_note
        else:
            panel_note = None
        panels.append(
            render_panel(
                rows,
                key,
                color,
                panel_label,
                x0,
                y0,
                panel_width,
                panel_height,
                final_note=panel_note,
            )
        )

    # Row 3: Bug types (multi-series) + Execs/sec
    row3_y = panel_top + 2 * (panel_height + panel_gap_y)
    panels.append(
        render_multi_panel(
            rows,
            BUG_TYPE_SERIES,
            "Bug types over time",
            panel_left,
            row3_y,
            panel_width,
            panel_height,
        )
    )
    panels.append(
        render_panel(
            rows,
            "execs_per_sec",
            "#0891b2",
            "Execs/sec",
            panel_left + panel_width + panel_gap_x,
            row3_y,
            panel_width,
            panel_height,
            is_float=False,
        )
    )

    dl_panels_html = ""
    if dl_rows:
        dl_section_y = panel_top + 3 * (panel_height + panel_gap_y) + 20
        dl_panels_html = (
            f'<text x="{header_x}" y="{dl_section_y - 8:.1f}" font-size="18" font-weight="700" fill="#0f172a">DL Surrogate Training</text>'
        )
        for col_idx, (key, color, label) in enumerate(DL_SERIES):
            x0 = panel_left + col_idx * (panel_width + panel_gap_x)
            y0 = dl_section_y + 10
            dl_panels_html += render_panel(dl_rows, key, color, label, x0, y0, panel_width, panel_height, is_float=True)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">{title}</title>
  <desc id="desc">Progress chart generated from fuzzing plot_data.</desc>
  <rect width="100%" height="100%" fill="#e2e8f0" />
  <rect x="18" y="18" width="{width - 36}" height="{height - 36}" rx="24" fill="#f8fafc" />
  <text x="{header_x}" y="58" font-size="30" font-weight="700" fill="#0f172a">{title}</text>
  <text x="{header_x}" y="84" font-size="15" fill="#475569">{summary}</text>
  {''.join(panels)}
  {dl_panels_html}
</svg>
"""


def render_istd_graph(
    *,
    title: str,
    subtitle: str,
    x_values: list[float],
    x_label: str,
    y_values: list[float],
    left: float,
    top: float,
    width: float,
    height: float,
    color: str,
) -> str:
    plot_left = left + 58
    plot_top = top + 56
    plot_width = width - 84
    plot_height = height - 100
    # scale x
    plot_right = plot_left + plot_width
    if len(x_values) <= 1 or (max(x_values) - min(x_values)) <= 0:
        xs = [plot_left + plot_width / 2 for _ in x_values]
    else:
        lo, hi = min(x_values), max(x_values)
        xs = [plot_left + ((v - lo) / (hi - lo)) * (plot_right - plot_left) for v in x_values]
    # scale y
    plot_bottom = plot_top + plot_height
    y_max = max(max(y_values), 1.0)
    ys = [plot_bottom - (v / y_max) * plot_height for v in y_values]
    points = list(zip(xs, ys))
    mid_y = plot_top + plot_height / 2
    x_min = min(x_values) if x_values else 0.0
    x_max = max(x_values) if x_values else 0.0

    return (
        f'<rect x="{left:.1f}" y="{top:.1f}" width="{width:.1f}" height="{height:.1f}" '
        f'rx="16" fill="#ffffff" stroke="#cbd5e1" />'
        f'<text x="{left + 18:.1f}" y="{top + 28:.1f}" font-size="18" font-weight="700" fill="#0f172a">{title}</text>'
        f'<text x="{left + 18:.1f}" y="{top + 48:.1f}" font-size="13" fill="#475569">{subtitle}</text>'
        f'<line x1="{plot_left:.1f}" y1="{plot_top:.1f}" x2="{plot_left:.1f}" y2="{plot_bottom:.1f}" stroke="#94a3b8" stroke-width="1.5" />'
        f'<line x1="{plot_left:.1f}" y1="{plot_bottom:.1f}" x2="{plot_left + plot_width:.1f}" y2="{plot_bottom:.1f}" stroke="#94a3b8" stroke-width="1.5" />'
        f'<line x1="{plot_left:.1f}" y1="{plot_top:.1f}" x2="{plot_left + plot_width:.1f}" y2="{plot_top:.1f}" stroke="#e2e8f0" stroke-width="1" />'
        f'<line x1="{plot_left:.1f}" y1="{mid_y:.1f}" x2="{plot_left + plot_width:.1f}" y2="{mid_y:.1f}" stroke="#e2e8f0" stroke-width="1" />'
        f'<text x="{left + 8:.1f}" y="{plot_top + 4:.1f}" font-size="12" fill="#64748b">{int(y_max)}</text>'
        f'<text x="{left + 8:.1f}" y="{mid_y + 4:.1f}" font-size="12" fill="#64748b">{int(y_max / 2)}</text>'
        f'<text x="{left + 18:.1f}" y="{plot_bottom + 4:.1f}" font-size="12" fill="#64748b">0</text>'
        f'<text x="{plot_left:.1f}" y="{plot_bottom + 22:.1f}" font-size="12" fill="#64748b">{int(x_min)}</text>'
        f'<text x="{plot_left + plot_width - 28:.1f}" y="{plot_bottom + 22:.1f}" font-size="12" fill="#64748b">{int(x_max)}</text>'
        f'<text x="{left + width / 2 - 70:.1f}" y="{top + height - 16:.1f}" font-size="12" fill="#475569">{x_label}</text>'
        f'<text x="{left + 8:.1f}" y="{top + 70:.1f}" font-size="12" fill="#475569">Interesting tests</text>'
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in points)}" />'
        f'<circle cx="{points[-1][0]:.1f}" cy="{points[-1][1]:.1f}" r="4" fill="{color}" />'
    )


def render_istd_svg(rows: list[dict[str, float]], title: str) -> str:
    if not rows:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="300">'
            '<rect width="100%" height="100%" fill="#f8fafc" />'
            f'<text x="48" y="80" font-size="28" font-weight="700" fill="#0f172a">{title}</text>'
            '<text x="48" y="130" font-size="18" fill="#475569">No plot_data samples found.</text>'
            '</svg>'
        )

    time_values = [row["relative_time_sec"] for row in rows]
    exec_values = [row["total_execs"] for row in rows]
    interesting_values = [row["interesting_test_cases"] for row in rows]
    final_interesting = int(interesting_values[-1])
    final_execs = int(exec_values[-1])
    final_time = int(time_values[-1])

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="520" viewBox="0 0 1200 520" role="img" aria-labelledby="istd-title istd-desc">
  <title id="istd-title">{title}</title>
  <desc id="istd-desc">Interesting test cases vs wall-clock time and total tests executed.</desc>
  <rect width="100%" height="100%" fill="#e2e8f0" />
  <rect x="18" y="18" width="1164" height="484" rx="24" fill="#f8fafc" />
  <text x="64" y="58" font-size="30" font-weight="700" fill="#0f172a">{title}</text>
  <text x="64" y="86" font-size="15" fill="#475569">Final interesting tests: {final_interesting} | Final tests: {final_execs} | Final wall-clock time: {final_time}s</text>
  {render_istd_graph(
      title="Graph 1.2",
      subtitle="Interesting test cases vs wall-clock time",
      x_values=time_values,
      x_label="Wall-clock time (seconds)",
      y_values=interesting_values,
      left=56,
      top=126,
      width=520,
      height=320,
      color="#047857",
  )}
  {render_istd_graph(
      title="Graph 1.3",
      subtitle="Interesting test cases vs total tests",
      x_values=exec_values,
      x_label="Total tests generated/executed",
      y_values=interesting_values,
      left=624,
      top=126,
      width=520,
      height=320,
      color="#1d4ed8",
  )}
</svg>
"""


def render_empty_svg(title: str) -> str:
    width = 1200
    height = 420
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">{title}</title>
  <desc id="desc">No plot data samples were available.</desc>
  <rect width="100%" height="100%" fill="#e2e8f0" />
  <rect x="24" y="24" width="{width - 48}" height="{height - 48}" rx="24" fill="#f8fafc" />
  <text x="72" y="94" font-size="30" font-weight="700" fill="#0f172a">{title}</text>
  <text x="72" y="144" font-size="22" fill="#334155">No samples found in plot_data yet.</text>
  <text x="72" y="186" font-size="16" fill="#475569">Run the fuzzer first, then rerun this script to render progress over time.</text>
</svg>
"""


def main() -> None:
    args = parse_args()

    # Check if this is an Atheris target (plot_data absent, atheris.log present)
    target_path = Path(args.target_or_plot_data)
    results_dir = (
        target_path if target_path.is_dir()
        else RESULTS_DIR / args.target_or_plot_data
    )
    atheris_log = results_dir / "atheris.log"
    plot_data = results_dir / "plot_data"

    if atheris_log.exists():
        rows = load_atheris_rows(results_dir)
        output_path = Path(args.output) if args.output else results_dir / "progress.svg"
        title = f"Fuzzer Progress (Atheris): {results_dir.name}"
        replay_payload = load_atheris_replay_coverage(results_dir)
        replay_final = replay_payload.get("final", {}) if replay_payload else {}
        if replay_final:
            coverage_label = "Coverage (% of buggy_json source)"
            final_pct = float(replay_final.get("percent_covered", 0.0))
            covered_items = int(replay_final.get("covered_items", 0))
            total_items = int(replay_final.get("total_items", 0))
            coverage_note = f"Final: {final_pct:.2f}% ({covered_items}/{total_items} lines+branches)"
        else:
            coverage_label = "Coverage (% of final observed cov)"
            final_cov = int(rows[-1]["coverage_seen"]) if rows else 0
            coverage_note = f"Final: 100.0% ({final_cov} cov)"
    else:
        plot_path, output_path = resolve_paths(args.target_or_plot_data, args.output)
        rows = load_rows(plot_path)
        title = f"Fuzzer Progress: {plot_path.parent.name}"
        results_dir = plot_path.parent
        coverage_label = "Coverage (% of 65536-slot bitmap)"
        final_cov = rows[-1]["coverage_seen"] if rows else 0.0
        final_pct = rows[-1]["coverage_percent"] if rows else 0.0
        coverage_note = f"Final: {final_pct:.3f}% ({int(final_cov)} slots)"

    rows, bug_curve_metadata = apply_bug_curve_to_rows(results_dir, rows)
    bug_note = None
    if bug_curve_metadata is not None:
        bug_note = f"Source: {bug_curve_metadata['source']}"

    dl_rows = load_dl_rows(results_dir)
    svg = render_svg(
        rows,
        title,
        dl_rows=dl_rows or None,
        coverage_label=coverage_label,
        coverage_note=coverage_note,
        bug_note=bug_note,
    )
    output_path.write_text(svg, encoding="utf-8")
    print(f"Wrote {output_path}")

    eval_path = output_path.with_name("eval_graphs.svg")
    eval_title = f"Evaluation Graphs: {results_dir.name}"
    eval_path.write_text(render_istd_svg(rows, eval_title), encoding="utf-8")
    print(f"Wrote {eval_path}")


if __name__ == "__main__":
    main()
