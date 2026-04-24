from __future__ import annotations

import os
import sys
from pathlib import Path

from cidrize_benchmark_common import (
    DEFAULT_BUG_COUNTS_CSV,
    DEFAULT_RESULTS_DIR,
    analyze_cidrize_input,
    append_bug_counts,
    log_full_traceback,
    write_unique_artifact,
)


RESULTS_DIR = Path(os.environ.get("AFL_CIDRIZE_RESULTS_DIR", DEFAULT_RESULTS_DIR))


class AFLBugFound(RuntimeError):
    pass


def process_one_input(data: bytes) -> None:
    outcome = analyze_cidrize_input(data)
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
    try:
        import afl  # type: ignore
    except ImportError as exc:
        raise SystemExit("python-afl is required to run the cidrize AFL harness.") from exc

    while afl.loop(1000):
        try:
            sys.stdin.seek(0)
        except (AttributeError, OSError):
            pass
        data = sys.stdin.buffer.read()
        process_one_input(data)

    os._exit(0)


if __name__ == "__main__":
    main()
