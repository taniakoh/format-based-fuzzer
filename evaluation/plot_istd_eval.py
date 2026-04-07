"""Render ISTD-style evaluation graphs from results/<target>/plot_data.

Produces a single SVG with:
  Graph 1.2: interesting test cases vs wall-clock time
  Graph 1.3: interesting test cases vs total tests

Older plot_data files that do not yet include an explicit
``interesting_test_cases`` column fall back to ``corpus_size``.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ISTD evaluation graphs from a fuzzing plot_data CSV."
    )
    parser.add_argument(
        "target_or_plot_data",
        help="Target name like 'ipv4' or a direct path to a plot_data CSV file.",
    )
    parser.add_argument(
        "--output",
        help="Output SVG path. Defaults to results/<target>/istd_eval.svg.",
    )
    return parser.parse_args()


def resolve_paths(target_or_plot_data: str, output: str | None) -> tuple[Path, Path]:
    candidate = Path(target_or_plot_data)
    if candidate.exists():
        plot_path = candidate
        default_output = plot_path.with_name("istd_eval.svg")
    else:
        plot_path = RESULTS_DIR / target_or_plot_data / "plot_data"
        default_output = RESULTS_DIR / target_or_plot_data / "istd_eval.svg"

    if not plot_path.exists():
        raise FileNotFoundError(f"Could not find plot data at {plot_path}")

    return plot_path, Path(output) if output else default_output


def load_rows(plot_path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with plot_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            interesting = row.get("interesting_test_cases")
            if interesting in (None, ""):
                interesting = row.get("corpus_size", "0")
            rows.append({
                "relative_time_sec": float(row["relative_time_sec"]),
                "total_execs": float(row["total_execs"]),
                "interesting_test_cases": float(interesting),
            })
    return rows


def svg_polyline(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def scale_x(values: list[float], left: float, width: float) -> list[float]:
    right = left + width
    if len(values) <= 1:
        return [left + width / 2 for _ in values]
    lo = min(values)
    hi = max(values)
    span = hi - lo
    if span <= 0:
        return [left + width / 2 for _ in values]
    return [left + ((value - lo) / span) * (right - left) for value in values]


def scale_y(values: list[float], top: float, height: float) -> tuple[list[float], float]:
    bottom = top + height
    max_value = max(max(values), 1.0)
    return [bottom - (value / max_value) * height for value in values], max_value


def render_graph(
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
    xs = scale_x(x_values, plot_left, plot_width)
    ys, y_max = scale_y(y_values, plot_top, plot_height)
    points = list(zip(xs, ys))
    x_min = min(x_values) if x_values else 0.0
    x_max = max(x_values) if x_values else 0.0
    mid_y = plot_top + plot_height / 2

    return (
        f'<rect x="{left:.1f}" y="{top:.1f}" width="{width:.1f}" height="{height:.1f}" '
        f'rx="16" fill="#ffffff" stroke="#cbd5e1" />'
        f'<text x="{left + 18:.1f}" y="{top + 28:.1f}" font-size="18" font-weight="700" fill="#0f172a">{title}</text>'
        f'<text x="{left + 18:.1f}" y="{top + 48:.1f}" font-size="13" fill="#475569">{subtitle}</text>'
        f'<line x1="{plot_left:.1f}" y1="{plot_top:.1f}" x2="{plot_left:.1f}" y2="{plot_top + plot_height:.1f}" stroke="#94a3b8" stroke-width="1.5" />'
        f'<line x1="{plot_left:.1f}" y1="{plot_top + plot_height:.1f}" x2="{plot_left + plot_width:.1f}" y2="{plot_top + plot_height:.1f}" stroke="#94a3b8" stroke-width="1.5" />'
        f'<line x1="{plot_left:.1f}" y1="{plot_top:.1f}" x2="{plot_left + plot_width:.1f}" y2="{plot_top:.1f}" stroke="#e2e8f0" stroke-width="1" />'
        f'<line x1="{plot_left:.1f}" y1="{mid_y:.1f}" x2="{plot_left + plot_width:.1f}" y2="{mid_y:.1f}" stroke="#e2e8f0" stroke-width="1" />'
        f'<line x1="{plot_left:.1f}" y1="{plot_top + plot_height:.1f}" x2="{plot_left + plot_width:.1f}" y2="{plot_top + plot_height:.1f}" stroke="#e2e8f0" stroke-width="1" />'
        f'<text x="{left + 8:.1f}" y="{plot_top + 4:.1f}" font-size="12" fill="#64748b">{int(y_max)}</text>'
        f'<text x="{left + 8:.1f}" y="{mid_y + 4:.1f}" font-size="12" fill="#64748b">{int(y_max / 2)}</text>'
        f'<text x="{left + 18:.1f}" y="{plot_top + plot_height + 4:.1f}" font-size="12" fill="#64748b">0</text>'
        f'<text x="{plot_left:.1f}" y="{plot_top + plot_height + 22:.1f}" font-size="12" fill="#64748b">{int(x_min)}</text>'
        f'<text x="{plot_left + plot_width - 28:.1f}" y="{plot_top + plot_height + 22:.1f}" font-size="12" fill="#64748b">{int(x_max)}</text>'
        f'<text x="{left + width / 2 - 70:.1f}" y="{top + height - 16:.1f}" font-size="12" fill="#475569">{x_label}</text>'
        f'<text x="{left + 8:.1f}" y="{top + 70:.1f}" font-size="12" fill="#475569">Interesting tests</text>'
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{svg_polyline(points)}" />'
        f'<circle cx="{points[-1][0]:.1f}" cy="{points[-1][1]:.1f}" r="4" fill="{color}" />'
    )


def render_svg(rows: list[dict[str, float]], title: str) -> str:
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
    final_interesting = int(interesting_values[-1]) if interesting_values else 0
    final_execs = int(exec_values[-1]) if exec_values else 0
    final_time = int(time_values[-1]) if time_values else 0

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="520" viewBox="0 0 1200 520" role="img" aria-labelledby="title desc">
  <title id="title">{title}</title>
  <desc id="desc">Interesting test cases plotted against wall-clock time and total tests.</desc>
  <rect width="100%" height="100%" fill="#e2e8f0" />
  <rect x="18" y="18" width="1164" height="484" rx="24" fill="#f8fafc" />
  <text x="64" y="58" font-size="30" font-weight="700" fill="#0f172a">{title}</text>
  <text x="64" y="86" font-size="15" fill="#475569">Final interesting tests: {final_interesting} | Final tests: {final_execs} | Final wall-clock time: {final_time}s</text>
  {render_graph(
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
  {render_graph(
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


def main() -> None:
    args = parse_args()
    plot_path, output_path = resolve_paths(args.target_or_plot_data, args.output)
    rows = load_rows(plot_path)
    title = f"ISTD Evaluation Graphs: {plot_path.parent.name}"
    output_path.write_text(render_svg(rows, title), encoding="utf-8")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
