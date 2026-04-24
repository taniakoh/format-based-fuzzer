from __future__ import annotations

import os
import sys
from pathlib import Path

from json_benchmark_common import (
    DEFAULT_BUG_COUNTS_CSV,
    DEFAULT_RESULTS_DIR,
    analyze_json_input,
    append_bug_counts,
    log_full_traceback,
    write_unique_artifact,
)


RESULTS_DIR = Path(os.environ.get("NEUZZ_JSON_RESULTS_DIR", DEFAULT_RESULTS_DIR))
TIMEOUT_SECONDS = int(os.environ.get("NEUZZ_JSON_TIMEOUT_SECONDS", "3"))
EXIT_ON_BUG = os.environ.get("NEUZZ_JSON_EXIT_ON_BUG", "0") == "1"


class NeuzzBugFound(RuntimeError):
    pass


def process_one_input(data: bytes) -> int:
    outcome = analyze_json_input(data, timeout_seconds=TIMEOUT_SECONDS)
    if outcome.bug is None:
        return 0

    artifact_path = write_unique_artifact(data, RESULTS_DIR, outcome.bug.bug_type)
    bug_count = {}
    if outcome.bug.exc is not None:
        log_full_traceback(outcome.bug.exc, outcome.bug.bug_type, RESULTS_DIR / "logs")
        bug_count[(
            outcome.bug.bug_type,
            type(outcome.bug.exc),
            str(outcome.bug.exc),
            artifact_path.name,
            0,
        )] = 1
    else:
        bug_count[(
            outcome.bug.bug_type,
            RuntimeError,
            outcome.bug.message,
            artifact_path.name,
            0,
        )] = 1
    append_bug_counts(bug_count, RESULTS_DIR / "logs" / DEFAULT_BUG_COUNTS_CSV)
    if EXIT_ON_BUG:
        raise NeuzzBugFound(f"{outcome.bug.bug_type}: {outcome.bug.message}")
    return 1


def load_file_argument() -> bytes:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python neuzz_json_target.py <input-file>")
    return Path(sys.argv[-1]).read_bytes()


def main() -> None:
    try:
        import afl
    except ImportError:
        afl = None

    if afl is not None:
        afl.init()
    data = load_file_argument()
    bug_seen = process_one_input(data)
    if EXIT_ON_BUG and bug_seen:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
