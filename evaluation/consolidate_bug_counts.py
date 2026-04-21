"""Rebuild a consolidated bug-count CSV from an existing run's CSV logs.

This is mainly useful for older JSON/XML Atheris results where ``bug_counts.csv``
may have been written as one row per artifact instead of one row per unique bug
site. The script groups rows by bug type, exception type, filename, and line
number, sums the counts, and keeps a representative non-empty exception message.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild a consolidated unique-bug CSV from an existing run directory."
    )
    parser.add_argument(
        "target_or_run_dir",
        help="Target name like 'json' or a direct path to a run directory under results/.",
    )
    parser.add_argument(
        "--input",
        help="Input CSV path. Defaults to <run_dir>/logs/bug_counts.csv.",
    )
    parser.add_argument(
        "--output",
        help="Output CSV path. Defaults to <run_dir>/logs/bug_counts_consolidated.csv.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help=(
            "Replace <run_dir>/logs/bug_counts.csv with the consolidated version and "
            "preserve the original as bug_counts_raw.csv when possible."
        ),
    )
    return parser.parse_args()


def resolve_run_dir(target_or_run_dir: str) -> Path:
    candidate = Path(target_or_run_dir)
    results_candidate = RESULTS_DIR / target_or_run_dir

    if candidate.exists():
        return candidate.parent if candidate.is_file() else candidate
    return results_candidate


def _lineno_sort_key(value: str) -> str:
    if value == "":
        return ""
    try:
        return f"{int(value):09d}"
    except ValueError:
        return value


def consolidate_bug_counts_csv(input_path: Path, output_path: Path) -> int:
    rows: dict[tuple[str, str, str, str], dict[str, object]] = {}

    with input_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            bug_type = str(row.get("bug_type", "") or "")
            exc_type = str(row.get("exc_type", "") or "")
            exc_message = str(row.get("exc_message", "") or "")
            filename = str(row.get("filename", "") or "")
            lineno = str(row.get("lineno", "") or "")
            count_text = str(row.get("count", "0") or "0")
            try:
                count = int(count_text)
            except ValueError:
                count = 0

            key = (bug_type, exc_type, filename, lineno)
            if key not in rows:
                rows[key] = {
                    "bug_type": bug_type,
                    "exc_type": exc_type,
                    "exc_message": exc_message,
                    "filename": filename,
                    "lineno": lineno,
                    "count": 0,
                }

            rows[key]["count"] = int(rows[key]["count"]) + count
            if not rows[key]["exc_message"] and exc_message:
                rows[key]["exc_message"] = exc_message

    ordered_rows = sorted(
        rows.values(),
        key=lambda item: (
            str(item["bug_type"]),
            str(item["filename"]),
            _lineno_sort_key(str(item["lineno"])),
            str(item["exc_type"]),
            str(item["exc_message"]),
        ),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        for row in ordered_rows:
            writer.writerow([
                row["bug_type"],
                row["exc_type"],
                row["exc_message"],
                row["filename"],
                row["lineno"],
                row["count"],
            ])
    return len(ordered_rows)


def main() -> None:
    args = parse_args()
    run_dir = resolve_run_dir(args.target_or_run_dir)
    logs_dir = run_dir / "logs"
    input_path = Path(args.input) if args.input else logs_dir / "bug_counts.csv"
    output_path = Path(args.output) if args.output else logs_dir / "bug_counts_consolidated.csv"

    if not input_path.exists():
        raise SystemExit(f"Input CSV not found: {input_path}")

    row_count = consolidate_bug_counts_csv(input_path, output_path)
    print(f"Wrote {output_path} ({row_count} rows)")

    if args.replace:
        replacement_path = logs_dir / "bug_counts.csv"
        raw_backup_path = logs_dir / "bug_counts_raw.csv"
        if input_path.resolve() == replacement_path.resolve():
            if not raw_backup_path.exists():
                raw_backup_path.write_bytes(input_path.read_bytes())
                print(f"Saved raw backup to {raw_backup_path}")
            replacement_path.write_bytes(output_path.read_bytes())
        else:
            if not raw_backup_path.exists():
                raw_backup_path.write_bytes(input_path.read_bytes())
                print(f"Saved raw backup to {raw_backup_path}")
            replacement_path.write_bytes(output_path.read_bytes())
        print(f"Replaced {replacement_path}")


if __name__ == "__main__":
    main()
