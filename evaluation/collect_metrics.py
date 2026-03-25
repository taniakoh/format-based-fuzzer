"""
Evaluation Harness — metrics collection.

Records coverage, crashes, unique behaviors, and time-to-first-bug.
Writes results to results/<target>/stats.txt and bugs.jsonl.
"""

from __future__ import annotations

import csv
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
    unique_bug_count: int = 0
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
        self._bug_signatures: set[tuple[str, str]] = set()
        self._unique_bug_entries: dict[tuple[str, str], dict[str, object]] = {}
        self._crash_signatures: set[tuple[str, int | None, str]] = set()
        self._out = RESULTS_DIR / target
        (self._out / "crashes").mkdir(parents=True, exist_ok=True)
        (self._out / "queue").mkdir(parents=True, exist_ok=True)
        # Clear previous bugs.jsonl for this run
        bugs_file = self._out / "bugs.jsonl"
        bugs_file.write_text("", encoding="utf-8")
        self._unique_bugs_path = self._out / "unique_bugs.json"
        self._write_unique_bugs()
        self._plot_path = self._out / "plot_data"
        self._dl_training_path = self._out / "dl_training.jsonl"
        self._dl_summary_path = self._out / "dl_summary.json"
        with open(self._plot_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "relative_time_sec",
                "total_execs",
                "behaviors_seen",
                "corpus_size",
                "unique_bugs",
                "unique_crashes",
            ])
        self._dl_training_path.write_text("", encoding="utf-8")
        self._write_dl_summary(
            {
                "target": self.target,
                "dl_enabled": False,
                "checkpoint_loaded": False,
                "initial_metadata": {},
                "final_metadata": {},
                "training_rounds_this_run": 0,
                "latest_loss": None,
            }
        )

    def write_fuzzer_config(self, config: dict) -> None:
        """Write the effective run configuration for this fuzzing campaign."""
        (self._out / "fuzzer_config").write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_mutation_stats(self, stats: dict) -> None:
        """Persist learned mutation payoff statistics for post-run inspection."""
        (self._out / "mutation_stats.json").write_text(
            json.dumps(stats, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def record_dl_training_event(self, event: dict) -> None:
        """Append one DL training event for post-run analysis."""
        with open(self._dl_training_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def write_dl_summary(self, summary: dict) -> None:
        """Persist a concise DL run summary."""
        self._write_dl_summary(summary)

    def record_execution(self, input_data: bytes, result) -> None:
        """Record one fuzzer execution result."""
        self.metrics.total_executions += 1
        input_str = input_data.decode("latin-1", errors="replace")

        from fuzzer.executor import BugType
        if result.bug_type == BugType.PASS:
            return

        signature = (result.bug_type, result.exception_msg)
        self._bug_signatures.add(signature)
        self.metrics.unique_bug_count = len(self._bug_signatures)
        if signature not in self._unique_bug_entries:
            self._unique_bug_entries[signature] = {
                "bug_type": result.bug_type,
                "exception": result.exception_msg,
                "first_seen_exec": self.metrics.total_executions,
                "example_input": input_str,
                "exit_code": result.exit_code,
            }
            self._write_unique_bugs()

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
            crash_signature = (
                str(result.bug_type),
                result.exit_code if result.exit_code is None else int(result.exit_code),
                str(result.exception_msg),
            )
            if crash_signature not in self._crash_signatures:
                self._crash_signatures.add(crash_signature)
                self.metrics.unique_crashes = len(self._crash_signatures)
                crash_id = self.metrics.unique_crashes
                crash_path = self._out / "crashes" / f"crash_{crash_id:06d}.txt"
                crash_path.write_text(input_str, encoding="utf-8", errors="replace")
                self.metrics.crash_log.append(str(crash_path))

    def record_queue_entry(self, seed: bytes, exec_count: int, priority: float) -> None:
        """Persist an interesting seed in a queue/ directory similar to AFL/Neuzz."""
        queue_id = self.metrics.behaviors_covered
        queue_path = self._out / "queue" / f"id_{queue_id:06d}.txt"
        input_str = seed.decode("latin-1", errors="replace")
        content = (
            f"exec={exec_count}\n"
            f"behavior={queue_id}\n"
            f"priority={priority:.6f}\n"
            f"input={input_str}\n"
        )
        queue_path.write_text(content, encoding="utf-8", errors="replace")

    def record_plot_point(self, corpus_size: int) -> None:
        """Append one progress sample to plot_data."""
        with open(self._plot_path, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"{time.time() - self._start:.3f}",
                self.metrics.total_executions,
                self.metrics.behaviors_covered,
                corpus_size,
                self.metrics.unique_bug_count,
                self.metrics.unique_crashes,
            ])

    def update_coverage(self, behaviors_covered: int) -> None:
        self.metrics.behaviors_covered = behaviors_covered

    def finalize(self) -> FuzzMetrics:
        self.metrics.wall_time_secs = time.time() - self._start
        self._write_unique_bugs()
        self._write_stats()
        return self.metrics

    def _write_unique_bugs(self) -> None:
        entries = list(self._unique_bug_entries.values())
        entries.sort(key=lambda item: int(item["first_seen_exec"]))
        payload = {
            "target": self.target,
            "unique_bug_count": len(entries),
            "entries": entries,
        }
        self._unique_bugs_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def _write_dl_summary(self, payload: dict) -> None:
        self._dl_summary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def _write_stats(self) -> None:
        m = self.metrics
        lines = [
            f"Target          : {m.target}",
            f"Wall time       : {m.wall_time_secs:.1f}s",
            f"Total execs     : {m.total_executions}",
            f"Behaviors seen  : {m.behaviors_covered}",
            f"Unique bugs     : {m.unique_bug_count}",
            f"Validity bugs   : {m.validity_bugs}",
            f"Bonus bugs      : {m.bonus_bugs}",
            f"Invalidity count: {m.invalidity_count}",
            f"Unique crashes  : {m.unique_crashes}",
            f"Time-to-1st-bug : {m.time_to_first_bug:.1f}s" if m.time_to_first_bug else "Time-to-1st-bug : N/A",
        ]
        stats_text = "\n".join(lines) + "\n"
        (self._out / "stats.txt").write_text(stats_text, encoding="utf-8")
        (self._out / "fuzzer_stats").write_text(stats_text, encoding="utf-8")
        print("\n".join(lines))
