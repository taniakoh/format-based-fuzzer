from __future__ import annotations

import argparse
from pathlib import Path

from cidrize_benchmark_common import (
    DEFAULT_BUG_COUNTS_CSV,
    DEFAULT_RESULTS_DIR,
    analyze_cidrize_input,
    append_bug_counts,
    load_input_bytes,
    log_full_traceback,
    print_outcome_summary,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one cidrize input with project-style wording.")
    parser.add_argument("--input-file", help="Path to a file containing the raw cidrize bytes to test.")
    parser.add_argument("--ipstr", help="cidrize input string to test directly.")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR), help="Directory to store bug logs and replay artifacts.")
    args = parser.parse_args()

    data = load_input_bytes(args)
    input_text = data.decode("latin-1", errors="replace")
    results_dir = Path(args.results_dir)
    logs_dir = results_dir / "logs"

    outcome = analyze_cidrize_input(data)
    bug_count = print_outcome_summary(input_text, outcome)
    if outcome.bug is not None and outcome.bug.exc is not None:
        log_full_traceback(outcome.bug.exc, outcome.bug.bug_type, logs_dir)

    csv_path = logs_dir / DEFAULT_BUG_COUNTS_CSV
    append_bug_counts(bug_count, csv_path)
    print("Saved bug count report and tracebacks for the bugs encountered!")
    print(f"Final bug count: {bug_count}")


if __name__ == "__main__":
    main()
