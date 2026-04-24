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


RESULTS_DIR = Path(os.environ.get("AFL_JSON_RESULTS_DIR", DEFAULT_RESULTS_DIR))
TIMEOUT_SECONDS = int(os.environ.get("AFL_JSON_TIMEOUT_SECONDS", "3"))


class AFLBugFound(RuntimeError):
    pass


def process_one_input(data: bytes) -> None:
    outcome = analyze_json_input(data, timeout_seconds=TIMEOUT_SECONDS)
    if outcome.bug is None:
        return

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
    raise AFLBugFound(f"{outcome.bug.bug_type}: {outcome.bug.message}")


def main() -> None:
    if os.environ.get("PYTHON_AFL_PERSISTENT"):
        import afl

        while afl.loop(1000):
            sys.stdin.seek(0)
            data = sys.stdin.buffer.read()
            process_one_input(data)
    else:
        import afl

        afl.init()
        data = sys.stdin.buffer.read()
        process_one_input(data)
        os._exit(0)


if __name__ == "__main__":
    main()
