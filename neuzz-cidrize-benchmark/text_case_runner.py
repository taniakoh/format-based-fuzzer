from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from neuzz_text_benchmark_common import (
    DEFAULT_BUG_COUNTS_CSV,
    analyze_text_input,
    append_bug_counts,
    detect_workspace_target,
    load_input_bytes,
    log_full_traceback,
    print_outcome_summary,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one input with output wording aligned to the existing text targets.")
    parser.add_argument("--input-file", help="Path to a file containing the raw input bytes to test.")
    parser.add_argument("--str-input", help="Input string to test directly.")
    parser.add_argument("--results-dir", default=str(ROOT / "results"), help="Directory to store bug logs and replay artifacts.")
    parser.add_argument("--timeout-seconds", type=int, default=3, help="Per-input timeout.")
    args = parser.parse_args()

    data = load_input_bytes(args)
    results_dir = Path(args.results_dir)
    logs_dir = results_dir / "logs"
    target = detect_workspace_target(ROOT)

    outcome = analyze_text_input(target, data, timeout_seconds=args.timeout_seconds)
    bug_count = print_outcome_summary(outcome)
    if outcome.bug is not None and outcome.bug.exc is not None:
        log_full_traceback(outcome.bug.exc, outcome.bug.bug_type, logs_dir)

    csv_path = logs_dir / DEFAULT_BUG_COUNTS_CSV
    append_bug_counts(bug_count, csv_path)
    print("Saved bug count report and tracebacks for the bugs encountered!")
    print(f"Final bug count: {bug_count}")


if __name__ == "__main__":
    main()
