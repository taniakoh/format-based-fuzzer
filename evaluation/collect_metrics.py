"""
Evaluation Harness — metrics collection.

Records coverage, crashes, unique behaviors, and time-to-first-bug.
Writes results to results/<target>/stats.txt and bugs.jsonl.
"""

from __future__ import annotations

import csv
import hashlib
import json
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).parent.parent
RESULTS_DIR = _HERE / "results"


def _first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        cleaned = line.strip()
        if cleaned:
            return cleaned
    return ""


def _normalize_fragment(text: str, limit: int = 200) -> str:
    fragment = _first_nonempty_line(text)
    if not fragment:
        return ""
    if len(fragment) <= limit:
        return fragment
    return fragment[: limit - 3] + "..."


def _signal_name(exit_code: int | None) -> str | None:
    if exit_code is None or exit_code >= 0:
        return None
    try:
        return signal.Signals(-exit_code).name
    except ValueError:
        return f"SIG{-exit_code}"


def _bitmap_digest(bitmap: bytes | None) -> str:
    if not bitmap or not any(bitmap):
        return ""
    return hashlib.sha256(bitmap).hexdigest()[:16]


def _make_bug_signature(result, bitmap: bytes | None = None) -> dict[str, object]:
    signal_name = _signal_name(result.exit_code)
    output_summary = (
        _normalize_fragment(result.stderr)
        or _normalize_fragment(result.stdout)
        or _normalize_fragment(result.traceback)
    )
    signature = {
        "bug_type": str(result.bug_type),
        "exit_code": result.exit_code,
        "signal": signal_name,
        "exception": str(result.exception_msg),
        "output_summary": output_summary,
        "bitmap_digest": _bitmap_digest(bitmap),
    }
    signature["key"] = json.dumps(signature, sort_keys=True)
    return signature


@dataclass
class FuzzMetrics:
    target: str
    behaviors_covered: int = 0
    unique_bug_count: int = 0
    unique_crashes: int = 0
    validity_bugs: int = 0
    bonus_bugs: int = 0
    oracle_mismatches: int = 0
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
        self._bug_signatures: set[str] = set()
        self._unique_bug_entries: dict[str, dict[str, object]] = {}
        self._crash_signatures: set[str] = set()
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

    def record_execution(self, input_data: bytes, result, bitmap: bytes | None = None) -> None:
        """Record one fuzzer execution result."""
        self.metrics.total_executions += 1
        input_str = input_data.decode("latin-1", errors="replace")

        from fuzzer.executor import BugType
        if result.bug_type == BugType.PASS:
            return

        signature = _make_bug_signature(result, bitmap)
        signature_key = str(signature["key"])
        if result.is_real_bug:
            self._bug_signatures.add(signature_key)
            self.metrics.unique_bug_count = len(self._bug_signatures)
        if result.is_real_bug and signature_key not in self._unique_bug_entries:
            self._unique_bug_entries[signature_key] = {
                "bug_type": result.bug_type,
                "signature": {k: v for k, v in signature.items() if k != "key"},
                "exception": result.exception_msg,
                "first_seen_exec": self.metrics.total_executions,
                "example_input": input_str,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "traceback": result.traceback,
                "oracle": {
                    "supported": bool(getattr(result.oracle, "supported", False)),
                    "expected_valid": getattr(result.oracle, "expected_valid", None),
                    "reason": getattr(result.oracle, "reason", ""),
                },
            }
            self._write_unique_bugs()

        # Time-to-first-bug
        if self.metrics.time_to_first_bug is None:
            self.metrics.time_to_first_bug = time.time() - self._start

        entry = {
            "exec": self.metrics.total_executions,
            "input": input_str,
            "bug_type": result.bug_type,
            "signature": {k: v for k, v in signature.items() if k != "key"},
            "exit_code": result.exit_code,
            "exception": result.exception_msg,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "traceback": result.traceback,
        }
        with open(self._out / "bugs.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        if result.bug_type == BugType.VALIDITY:
            self.metrics.validity_bugs += 1
        elif result.bug_type == BugType.BONUS:
            self.metrics.bonus_bugs += 1
        elif result.bug_type == BugType.ORACLE_MISMATCH:
            self.metrics.oracle_mismatches += 1
        elif result.bug_type == BugType.INVALIDITY:
            self.metrics.invalidity_count += 1
        elif result.is_crash:
            crash_signature = signature_key
            if crash_signature not in self._crash_signatures:
                self._crash_signatures.add(crash_signature)
                self.metrics.unique_crashes = len(self._crash_signatures)
                crash_id = self.metrics.unique_crashes
                crash_path = self._out / "crashes" / f"crash_{crash_id:06d}.txt"
                crash_report = (
                    f"bug_type={result.bug_type}\n"
                    f"signature={json.dumps({k: v for k, v in signature.items() if k != 'key'}, sort_keys=True)}\n"
                    f"exit_code={result.exit_code}\n"
                    f"exception={result.exception_msg}\n"
                    f"input={input_str}\n"
                    f"stdout={result.stdout}\n"
                    f"stderr={result.stderr}\n"
                    f"traceback={result.traceback}\n"
                )
                crash_path.write_text(crash_report, encoding="utf-8", errors="replace")
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
            f"Oracle mismatch : {m.oracle_mismatches}",
            f"Invalidity count: {m.invalidity_count}",
            f"Unique crashes  : {m.unique_crashes}",
            f"Time-to-1st-bug : {m.time_to_first_bug:.1f}s" if m.time_to_first_bug else "Time-to-1st-bug : N/A",
        ]
        stats_text = "\n".join(lines) + "\n"
        (self._out / "stats.txt").write_text(stats_text, encoding="utf-8")
        (self._out / "fuzzer_stats").write_text(stats_text, encoding="utf-8")
        print("\n".join(lines))
