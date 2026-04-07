"""Render a readable SVG dashboard from results/<target>/plot_data."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
SERIES = (
    ("behaviors_seen", "#1d4ed8", "Behaviors seen"),
    ("unique_bugs", "#b91c1c", "Unique bugs"),
    ("corpus_size", "#047857", "Corpus size"),
    ("unique_crashes", "#7c3aed", "Unique crashes"),
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
                "behaviors_seen": float(cov),
                "corpus_size": float(corp),
                "unique_bugs": float(unique_bugs),
                "unique_crashes": float(unique_crashes),
            })

    return rows


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
) -> str:
    times = [row["relative_time_sec"] for row in rows]
    values = [row[key] for row in rows]
    xs = scale_x(times, x0, width)
    ys, y_max = scale_y(values, y0, height)
    points = list(zip(xs, ys))
    mid_y = (y0 + 38 + y0 + height - 28) / 2
    end_x, end_y = points[-1]

    fmt = (lambda v: f"{v:.3f}") if is_float else (lambda v: str(int(v)))

    parts = [
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{width:.1f}" height="{height:.1f}" rx="14" fill="#ffffff" stroke="#cbd5e1" />',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 28:.1f}" font-size="19" font-weight="700" fill="#0f172a">{label}</text>',
        f'<text x="{x0 + 16:.1f}" y="{y0 + 50:.1f}" font-size="14" fill="#475569">Final: {fmt(values[-1])}</text>',
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


def render_svg(rows: list[dict[str, float]], title: str, dl_rows: list[dict[str, float]] | None = None) -> str:
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
    height = panel_top + 2 * (panel_height + panel_gap_y) + dl_section_height + 40
    header_x = 72
    summary = (
        f"Samples: {len(rows)} | Final execs: {int(rows[-1]['total_execs'])} | "
        f"Final time: {rows[-1]['relative_time_sec']:.1f}s"
    )

    panels = []
    for index, (key, color, label) in enumerate(SERIES):
        row_idx = index // 2
        col_idx = index % 2
        x0 = panel_left + col_idx * (panel_width + panel_gap_x)
        y0 = panel_top + row_idx * (panel_height + panel_gap_y)
        panels.append(render_panel(rows, key, color, label, x0, y0, panel_width, panel_height))

    dl_panels_html = ""
    if dl_rows:
        dl_section_y = panel_top + 2 * (panel_height + panel_gap_y) + 20
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
    else:
        plot_path, output_path = resolve_paths(args.target_or_plot_data, args.output)
        rows = load_rows(plot_path)
        title = f"Fuzzer Progress: {plot_path.parent.name}"
        results_dir = plot_path.parent

    dl_rows = load_dl_rows(results_dir)
    svg = render_svg(rows, title, dl_rows=dl_rows or None)
    output_path.write_text(svg, encoding="utf-8")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
