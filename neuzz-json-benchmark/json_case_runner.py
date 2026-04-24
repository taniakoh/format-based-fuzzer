from __future__ import annotations

import argparse
import os
from pathlib import Path

from json_benchmark_common import (
    DEFAULT_BUG_COUNTS_CSV,
    DEFAULT_COVERAGE_FILE,
    DEFAULT_RESULTS_DIR,
    analyze_json_input,
    append_bug_counts,
    load_input_bytes,
    log_full_traceback,
    maybe_create_coverage,
    print_outcome_summary,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one JSON input with output wording aligned to the existing JSON target.")
    parser.add_argument("--input-file", help="Path to a file containing the raw JSON bytes to test.")
    parser.add_argument("--str-json", help="JSON string to test directly.")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR), help="Directory to store bug logs and replay artifacts.")
    parser.add_argument("--coverage-file", default=DEFAULT_COVERAGE_FILE, help="Coverage data file path.")
    parser.add_argument("--show-coverage", action="store_true", help="Collect and display coverage after the run if coverage.py is installed.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    data = load_input_bytes(args)
    results_dir = Path(args.results_dir)
    logs_dir = results_dir / "logs"

    cov = maybe_create_coverage(args.coverage_file) if args.show_coverage else None
    if cov is not None:
        if os.path.exists(args.coverage_file):
            cov.load()
            print(f"Loading existing coverage data from {args.coverage_file}\n")
        cov.start()

    try:
        outcome = analyze_json_input(data, timeout_seconds=args.timeout_seconds)
    finally:
        if cov is not None:
            cov.stop()
            cov.save()

    bug_count = print_outcome_summary(outcome)
    if outcome.bug is not None and outcome.bug.exc is not None:
        log_full_traceback(outcome.bug.exc, outcome.bug.bug_type, logs_dir)

    csv_path = logs_dir / DEFAULT_BUG_COUNTS_CSV
    append_bug_counts(bug_count, csv_path)
    if not bug_count:
        print("No bugs found. Skipping CSV creation")
    print("Saved bug count report and tracebacks for the bugs encountered!")
    print(f"Final bug count: {bug_count}")

    if cov is not None:
        print(f"\nCoverage data saved to: {args.coverage_file}")
    else:
        print("\nCoverage data was not collected. Install coverage and pass --show-coverage if you want the replay summary.")


if __name__ == "__main__":
    main()
