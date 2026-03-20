"""
Evaluation Harness — metrics collection.

Records coverage, crashes, unique behaviors, and time-to-first-bug.
Writes results to results/<target>/stats.txt and bugs.jsonl.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).parent.parent
RESULTS_DIR = _HERE / "results"


@dataclass
class FuzzMetrics:
    target: str
    behaviors_covered: int = 0
    unique_crashes: int = 0
    validity_bugs: int = 0
    bonus_bugs: int = 0
    invalidity_count: int = 0
    total_executions: int = 0
    time_to_first_bug: float | None = None
    wall_time_secs: float = 0.0
    crash_log: list[str] = field(default_factory=list)


class MetricsCollector:
    def __init__(self, target: str):
        self.target = target
        self.metrics = FuzzMetrics(target=target)
        self._start = time.time()
        self._out = RESULTS_DIR / target
        (self._out / "crashes").mkdir(parents=True, exist_ok=True)
        # Clear previous bugs.jsonl for this run
        bugs_file = self._out / "bugs.jsonl"
        bugs_file.write_text("", encoding="utf-8")

    def record_execution(self, input_data: bytes, result) -> None:
        """Record one fuzzer execution result."""
        self.metrics.total_executions += 1
        input_str = input_data.decode("latin-1", errors="replace")

        from fuzzer.executor import BugType
        if result.bug_type == BugType.PASS:
            return

        # Time-to-first-bug
        if self.metrics.time_to_first_bug is None:
            self.metrics.time_to_first_bug = time.time() - self._start

        entry = {
            "exec": self.metrics.total_executions,
            "input": input_str,
            "bug_type": result.bug_type,
            "exit_code": result.exit_code,
            "exception": result.exception_msg,
        }
        with open(self._out / "bugs.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        if result.bug_type == BugType.VALIDITY:
            self.metrics.validity_bugs += 1
        elif result.bug_type == BugType.BONUS:
            self.metrics.bonus_bugs += 1
        elif result.bug_type == BugType.INVALIDITY:
            self.metrics.invalidity_count += 1
        elif result.is_crash:
            self.metrics.unique_crashes += 1
            crash_id = self.metrics.unique_crashes
            crash_path = self._out / "crashes" / f"crash_{crash_id:06d}.txt"
            crash_path.write_text(input_str, encoding="utf-8", errors="replace")
            self.metrics.crash_log.append(str(crash_path))

    def update_coverage(self, behaviors_covered: int) -> None:
        self.metrics.behaviors_covered = behaviors_covered

    def finalize(self) -> FuzzMetrics:
        self.metrics.wall_time_secs = time.time() - self._start
        self._write_stats()
        return self.metrics

    def _write_stats(self) -> None:
        m = self.metrics
        lines = [
            f"Target          : {m.target}",
            f"Wall time       : {m.wall_time_secs:.1f}s",
            f"Total execs     : {m.total_executions}",
            f"Behaviors seen  : {m.behaviors_covered}",
            f"Validity bugs   : {m.validity_bugs}",
            f"Bonus bugs      : {m.bonus_bugs}",
            f"Invalidity count: {m.invalidity_count}",
            f"Unique crashes  : {m.unique_crashes}",
            f"Time-to-1st-bug : {m.time_to_first_bug:.1f}s" if m.time_to_first_bug else "Time-to-1st-bug : N/A",
        ]
        (self._out / "stats.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))
