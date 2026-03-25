"""Render a readable SVG dashboard from results/<target>/plot_data."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
SERIES = (
    ("behaviors_seen", "#1d4ed8", "Behaviors seen"),
    ("unique_bugs", "#b91c1c", "Unique bugs"),
    ("corpus_size", "#047857", "Corpus size"),
    ("unique_crashes", "#7c3aed", "Unique crashes"),
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
    if target_path.exists():
        plot_path = target_path
        default_output = plot_path.with_suffix(".svg")
    else:
        plot_path = RESULTS_DIR / target_or_plot_data / "plot_data"
        default_output = RESULTS_DIR / target_or_plot_data / "progress.svg"

    if not plot_path.exists():
        raise FileNotFoundError(f"Could not find plot data at {plot_path}")

    output_path = Path(output) if output else default_output
    return plot_path, output_path


def load_rows(plot_path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with plot_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({key: float(value) for key, value in row.items()})
    return rows


def summarize_trend(values: list[float]) -> str:
    if len(values) < 2:
        return "not enough data yet"
    start = values[0]
    end = values[-1]
    prev = values[-2]
    if end == start:
        return "flat for the whole run"
    if end == prev:
        return "plateaued at the end"
    return "still rising at the end"


def svg_polyline(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def scale_x(times: list[float], x0: float, width: float) -> list[float]:
    if len(times) == 1 or times[-1] <= times[0]:
        return [x0 + width / 2 for _ in times]
    start = times[0]
    span = times[-1] - start
    return [x0 + ((t - start) / span) * width for t in times]


def scale_y(values: list[float], y0: float, height: float) -> tuple[list[float], float]:
    max_val = max(max(values), 1.0)
    return [y0 + height - (value / max_val) * height for value in values], max_val


def render_panel(
    rows: list[dict[str, float]],
    key: str,
    color: str,
    label: str,
    x0: float,
    y0: float,
    width: float,
    height: float,
) -> str:
    times = [row["relative_time_sec"] for row in rows]
    values = [row[key] for row in rows]
    xs = scale_x(times, x0, width)
    ys, y_max = scale_y(values, y0, height)
    points = list(zip(xs, ys))
    mid_y = y0 + height / 2
    end_x, end_y = points[-1]
    trend = summarize_trend(values)

    parts = [
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{width:.1f}" height="{height:.1f}" rx="14" fill="#ffffff" stroke="#cbd5e1" />',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 28:.1f}" font-size="19" font-weight="700" fill="#0f172a">{label}</text>',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 50:.1f}" font-size="14" fill="#475569">Final: {int(values[-1])} | Trend: {trend}</text>',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + 22:.1f}" x2="{x0 + 44:.1f}" y2="{y0 + height - 28:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + height - 28:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + height - 28:.1f}" stroke="#94a3b8" stroke-width="1.5" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + 38:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + 38:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<line x1="{x0 + 44:.1f}" y1="{mid_y:.1f}" x2="{x0 + width - 16:.1f}" y2="{mid_y:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<line x1="{x0 + 44:.1f}" y1="{y0 + height - 28:.1f}" x2="{x0 + width - 16:.1f}" y2="{y0 + height - 28:.1f}" stroke="#e2e8f0" stroke-width="1" />',
        f'<text x="{x0 + 10:.1f}" y="{y0 + 42:.1f}" font-size="12" fill="#64748b">{int(y_max)}</text>',
        f'<text x="{x0 + 10:.1f}" y="{mid_y + 4:.1f}" font-size="12" fill="#64748b">{int(round(y_max / 2))}</text>',
        f'<text x="{x0 + 18:.1f}" y="{y0 + height - 24:.1f}" font-size="12" fill="#64748b">0</text>',
        f'<text x="{x0 + 44:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[0]:.0f}s</text>',
        f'<text x="{x0 + width - 46:.1f}" y="{y0 + height - 8:.1f}" font-size="12" fill="#64748b">{times[-1]:.0f}s</text>',
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{svg_polyline(points)}" />',
        f'<circle cx="{end_x:.1f}" cy="{end_y:.1f}" r="4" fill="{color}" />',
    ]
    return "".join(parts)


def render_svg(rows: list[dict[str, float]], title: str) -> str:
    if not rows:
        return render_empty_svg(title)

    width = 1200
    height = 900
    header_x = 72
    summary = (
        f"Samples: {len(rows)} | Final execs: {int(rows[-1]['total_execs'])} | "
        f"Final time: {rows[-1]['relative_time_sec']:.1f}s"
    )
    insights = (
        f"Interpretation: behaviors={summarize_trend([row['behaviors_seen'] for row in rows])}, "
        f"bugs={summarize_trend([row['unique_bugs'] for row in rows])}, "
        f"corpus={summarize_trend([row['corpus_size'] for row in rows])}, "
        f"crashes={summarize_trend([row['unique_crashes'] for row in rows])}"
    )
    panel_width = 500
    panel_height = 300
    panel_left = 72
    panel_top = 130
    panel_gap_x = 56
    panel_gap_y = 38

    panels = []
    for index, (key, color, label) in enumerate(SERIES):
        row_idx = index // 2
        col_idx = index % 2
        x0 = panel_left + col_idx * (panel_width + panel_gap_x)
        y0 = panel_top + row_idx * (panel_height + panel_gap_y)
        panels.append(render_panel(rows, key, color, label, x0, y0, panel_width, panel_height))

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">{title}</title>
  <desc id="desc">Progress chart generated from fuzzing plot_data.</desc>
  <rect width="100%" height="100%" fill="#e2e8f0" />
  <rect x="18" y="18" width="{width - 36}" height="{height - 36}" rx="24" fill="#f8fafc" />
  <text x="{header_x}" y="58" font-size="30" font-weight="700" fill="#0f172a">{title}</text>
  <text x="{header_x}" y="84" font-size="15" fill="#475569">{summary}</text>
  <text x="{header_x}" y="106" font-size="15" fill="#475569">{insights}</text>
  {''.join(panels)}
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
    plot_path, output_path = resolve_paths(args.target_or_plot_data, args.output)
    rows = load_rows(plot_path)
    title = f"Fuzzer Progress: {plot_path.parent.name}"
    svg = render_svg(rows, title)
    output_path.write_text(svg, encoding="utf-8")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
