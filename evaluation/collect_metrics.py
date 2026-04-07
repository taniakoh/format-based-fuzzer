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
from collections import Counter
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


def _taxonomy_payload(result) -> dict[str, object]:
    from fuzzer.executor import result_taxonomy_tags

    return {
        "parser_reported_bug_type": getattr(result, "parser_reported_bug_type", None),
        "parser_reported_message": getattr(result, "parser_reported_message", ""),
        "taxonomy_tags": result_taxonomy_tags(result),
    }


@dataclass
class FuzzMetrics:
    target: str
    behaviors_covered: int = 0
    pass_count: int = 0
    unique_bug_count: int = 0
    traceback_unique_bugs: int = 0
    interesting_result_count: int = 0
    interesting_test_case_count: int = 0
    unique_crashes: int = 0
    validity_bugs: int = 0
    bonus_bugs: int = 0
    oracle_mismatches: int = 0
    invalidity_count: int = 0
    oracle_unknown_accepts: int = 0
    oracle_unknown_rejects: int = 0
    performance_bugs: int = 0
    total_executions: int = 0
    time_to_first_interesting_result: float | None = None
    exec_to_first_interesting_result: int | None = None
    time_to_first_real_bug: float | None = None
    exec_to_first_real_bug: int | None = None
    time_to_first_crash: float | None = None
    exec_to_first_crash: int | None = None
    total_generation_time_ms: float = 0.0
    total_execution_time_ms: float = 0.0
    wall_time_secs: float = 0.0
    crash_log: list[str] = field(default_factory=list)


class MetricsCollector:
    def __init__(self, target: str):
        self.target = target
        self.metrics = FuzzMetrics(target=target)
        self._start = time.time()
        self._bug_signatures: set[str] = set()
        self._traceback_signatures: set[str] = set()
        self._unique_bug_entries: dict[str, dict[str, object]] = {}
        self._unique_finding_entries: dict[str, dict[str, object]] = {}
        self._crash_signatures: set[str] = set()
        self._run_metadata: dict[str, object] = {}
        self._out = RESULTS_DIR / target
        (self._out / "crashes").mkdir(parents=True, exist_ok=True)
        (self._out / "queue").mkdir(parents=True, exist_ok=True)
        # Clear previous bugs.jsonl for this run
        bugs_file = self._out / "bugs.jsonl"
        bugs_file.write_text("", encoding="utf-8")
        self._unique_bugs_path = self._out / "unique_bugs.json"
        self._unique_findings_path = self._out / "unique_findings.json"
        self._bug_coverage_summary_path = self._out / "bug_coverage_summary.json"
        self._write_unique_bugs()
        self._write_unique_findings()
        self._write_bug_coverage_summary()
        self._plot_path = self._out / "plot_data"
        self._dl_training_path = self._out / "dl_training.jsonl"
        self._dl_summary_path = self._out / "dl_summary.json"
        self._energy_log_path = self._out / "energy_log.csv"
        self._oracle_log_path = self._out / "oracle_log.csv"
        with open(self._plot_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "relative_time_sec",
                "total_execs",
                "behaviors_seen",
                "interesting_test_cases",
                "corpus_size",
                "unique_bugs",
                "unique_crashes",
            ])
        with open(self._energy_log_path, "w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow(["relative_time_sec", "seed_id", "energy"])
        with open(self._oracle_log_path, "w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow(["relative_time_sec", "input_hash", "is_new_behavior", "bug_label", "latency_ms"])
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
        self._run_metadata = dict(config)
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
            self.metrics.pass_count += 1
            return

        self.metrics.interesting_result_count += 1
        if self.metrics.time_to_first_interesting_result is None:
            self.metrics.time_to_first_interesting_result = time.time() - self._start
            self.metrics.exec_to_first_interesting_result = self.metrics.total_executions

        signature = _make_bug_signature(result, bitmap)
        signature_key = str(signature["key"])
        if result.is_real_bug:
            self._bug_signatures.add(signature_key)
            self.metrics.unique_bug_count = len(self._bug_signatures)
            tb = getattr(result, "traceback", "")
            if tb:
                tb_key = hashlib.sha256(
                    f"{result.bug_type}|{tb.strip()}".encode("utf-8", errors="replace")
                ).hexdigest()[:32]
                self._traceback_signatures.add(tb_key)
                self.metrics.traceback_unique_bugs = len(self._traceback_signatures)
        if result.is_real_bug and signature_key not in self._unique_bug_entries:
            self._unique_bug_entries[signature_key] = {
                **self._finding_entry(result, signature, input_str),
                "bug_type": result.bug_type,
            }
            self._write_unique_bugs()

        if signature_key not in self._unique_finding_entries:
            self._unique_finding_entries[signature_key] = self._finding_entry(
                result,
                signature,
                input_str,
            )
            self._write_unique_findings()

        if result.is_real_bug and self.metrics.time_to_first_real_bug is None:
            self.metrics.time_to_first_real_bug = time.time() - self._start
            self.metrics.exec_to_first_real_bug = self.metrics.total_executions

        if result.is_crash and self.metrics.time_to_first_crash is None:
            self.metrics.time_to_first_crash = time.time() - self._start
            self.metrics.exec_to_first_crash = self.metrics.total_executions

        entry = {
            "exec": self.metrics.total_executions,
            "input": input_str,
            "bug_type": result.bug_type,
            "classification": _taxonomy_payload(result),
            "signature": {k: v for k, v in signature.items() if k != "key"},
            "exit_code": result.exit_code,
            "exception": result.exception_msg,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "traceback": result.traceback,
            "oracle": {
                "supported": bool(getattr(result.oracle, "supported", False)),
                "expected_valid": getattr(result.oracle, "expected_valid", None),
                "reason": getattr(result.oracle, "reason", ""),
                "shape": getattr(result.oracle, "shape", ""),
                "normalized": getattr(result.oracle, "normalized", None),
            },
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
        elif result.bug_type == BugType.ORACLE_UNKNOWN_ACCEPT:
            self.metrics.oracle_unknown_accepts += 1
        elif result.bug_type == BugType.ORACLE_UNKNOWN_REJECT:
            self.metrics.oracle_unknown_rejects += 1
        elif result.bug_type == BugType.PERFORMANCE:
            self.metrics.performance_bugs += 1
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
        self.metrics.interesting_test_case_count += 1
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

    def record_timing(self, generation_ms: float, execution_ms: float) -> None:
        """Accumulate separate candidate-generation and target-execution timings."""
        self.metrics.total_generation_time_ms += max(0.0, generation_ms)
        self.metrics.total_execution_time_ms += max(0.0, execution_ms)

    def record_plot_point(self, corpus_size: int) -> None:
        """Append one progress sample to plot_data."""
        with open(self._plot_path, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"{time.time() - self._start:.3f}",
                self.metrics.total_executions,
                self.metrics.behaviors_covered,
                self.metrics.interesting_test_case_count,
                corpus_size,
                self.metrics.unique_bug_count,
                self.metrics.unique_crashes,
            ])

    def record_energy(self, seed: bytes, energy: float) -> None:
        """Append one seed-energy sample to energy_log.csv (logged every cycle)."""
        seed_id = hashlib.sha256(seed).hexdigest()[:12]
        with open(self._energy_log_path, "a", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow([
                f"{time.time() - self._start:.3f}",
                seed_id,
                f"{energy:.6f}",
            ])

    def record_oracle_log(
        self,
        input_data: bytes,
        bug_type,
        is_new_behavior: bool,
        latency_ms: float,
    ) -> None:
        """Append one oracle verdict to oracle_log.csv (logged every execution)."""
        input_hash = hashlib.sha256(input_data).hexdigest()[:12]
        with open(self._oracle_log_path, "a", encoding="utf-8", newline="") as f:
            csv.writer(f).writerow([
                f"{time.time() - self._start:.3f}",
                input_hash,
                int(is_new_behavior),
                str(bug_type),
                f"{latency_ms:.2f}",
            ])

    def update_coverage(self, behaviors_covered: int) -> None:
        self.metrics.behaviors_covered = behaviors_covered

    def finalize(self) -> FuzzMetrics:
        self.metrics.wall_time_secs = time.time() - self._start
        self._write_unique_bugs()
        self._write_unique_findings()
        self._write_bug_coverage_summary()
        self._write_stats()
        return self.metrics

    def _finding_entry(
        self,
        result,
        signature: dict[str, object],
        input_str: str,
    ) -> dict[str, object]:
        return {
            "bug_type": result.bug_type,
            "classification": _taxonomy_payload(result),
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
                "shape": getattr(result.oracle, "shape", ""),
                "normalized": getattr(result.oracle, "normalized", None),
            },
        }

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

    def _write_unique_findings(self) -> None:
        entries = list(self._unique_finding_entries.values())
        entries.sort(key=lambda item: int(item["first_seen_exec"]))
        payload = {
            "target": self.target,
            "unique_finding_count": len(entries),
            "entries": entries,
        }
        self._unique_findings_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def _last_corpus_size(self) -> int | None:
        """Return the corpus_size from the last row of plot_data, or None."""
        try:
            with open(self._plot_path, "r", encoding="utf-8", newline="") as f:
                last_row = None
                for row in csv.DictReader(f):
                    last_row = row
            if last_row is not None:
                return int(float(last_row["corpus_size"]))
        except Exception:
            pass
        return None

    def _write_bug_coverage_summary(self) -> None:
        finding_entries = list(self._unique_finding_entries.values())
        total_by_bug_type = Counter()
        unique_by_bug_type = Counter()
        total_by_tag = Counter()
        unique_by_tag = Counter()
        parser_reported_totals = Counter()
        parser_reported_unique = Counter()

        bugs_path = self._out / "bugs.jsonl"
        if bugs_path.exists():
            for line in bugs_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                bug_type = str(entry.get("bug_type", "unknown"))
                total_by_bug_type[bug_type] += 1
                classification = entry.get("classification", {})
                parser_type = classification.get("parser_reported_bug_type") or "none"
                parser_reported_totals[str(parser_type)] += 1
                for tag in classification.get("taxonomy_tags", []):
                    total_by_tag[str(tag)] += 1

        for entry in finding_entries:
            bug_type = str(entry.get("bug_type", "unknown"))
            unique_by_bug_type[bug_type] += 1
            classification = entry.get("classification", {})
            parser_type = classification.get("parser_reported_bug_type") or "none"
            parser_reported_unique[str(parser_type)] += 1
            for tag in classification.get("taxonomy_tags", []):
                unique_by_tag[str(tag)] += 1

        wall_time = self.metrics.wall_time_secs
        total_execs = self.metrics.total_executions
        payload = {
            "target": self.target,
            "run_scalars": {
                "wall_time_secs": round(wall_time, 1),
                "total_executions": total_execs,
                "execs_per_sec": round(total_execs / max(1.0, wall_time), 4),
                "pass_count": self.metrics.pass_count,
                "pass_rate": round(self.metrics.pass_count / max(1, total_execs), 4),
                "behaviors_seen": self.metrics.behaviors_covered,
                "interesting_test_cases": self.metrics.interesting_test_case_count,
                "corpus_size": self._last_corpus_size(),
                "avg_generation_time_ms": round(
                    self.metrics.total_generation_time_ms / max(1, total_execs),
                    3,
                ),
                "avg_execution_time_ms": round(
                    self.metrics.total_execution_time_ms / max(1, total_execs),
                    3,
                ),
            },
            "totals": {
                "interesting_results": self.metrics.interesting_result_count,
                "unique_findings": len(finding_entries),
                "unique_real_bugs": self.metrics.unique_bug_count,
                "traceback_unique_bugs": self.metrics.traceback_unique_bugs,
                "unique_crashes": self.metrics.unique_crashes,
            },
            "by_bug_type": {
                "total": dict(sorted(total_by_bug_type.items())),
                "unique": dict(sorted(unique_by_bug_type.items())),
            },
            "by_parser_reported_type": {
                "total": dict(sorted(parser_reported_totals.items())),
                "unique": dict(sorted(parser_reported_unique.items())),
            },
            "by_taxonomy_tag": {
                "total": dict(sorted(total_by_tag.items())),
                "unique": dict(sorted(unique_by_tag.items())),
            },
        }
        self._bug_coverage_summary_path.write_text(
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
        execs_per_sec = m.total_executions / max(1.0, m.wall_time_secs)
        pass_rate = m.pass_count / max(1, m.total_executions)
        avg_generation_ms = m.total_generation_time_ms / max(1, m.total_executions)
        avg_execution_ms = m.total_execution_time_ms / max(1, m.total_executions)
        lines = [
            f"Target          : {m.target}",
            f"Eval mode req   : {self._run_metadata.get('evaluation_mode_requested', 'N/A')}",
            f"Eval mode used  : {self._run_metadata.get('evaluation_mode_resolved', 'N/A')}",
            f"Wall time       : {m.wall_time_secs:.1f}s",
            f"Total execs     : {m.total_executions}",
            f"Execs/sec       : {execs_per_sec:.4f}",
            f"Avg gen/test    : {avg_generation_ms:.3f} ms",
            f"Avg run/test    : {avg_execution_ms:.3f} ms",
            f"Pass (clean)    : {m.pass_count} ({pass_rate:.1%})",
            f"Behaviors seen  : {m.behaviors_covered}",
            f"Interesting tests: {m.interesting_test_case_count}",
            f"Interesting results: {m.interesting_result_count}",
            f"Unique bugs     : {m.unique_bug_count}",
            f"Traceback-unique: {m.traceback_unique_bugs}",
            f"Validity bugs   : {m.validity_bugs}",
            f"Bonus bugs      : {m.bonus_bugs}",
            f"Oracle mismatch : {m.oracle_mismatches}",
            f"Invalidity count: {m.invalidity_count}",
            f"Oracle unknown accept: {m.oracle_unknown_accepts}",
            f"Oracle unknown reject: {m.oracle_unknown_rejects}",
            f"Performance bugs: {m.performance_bugs}",
            f"Unique crashes  : {m.unique_crashes}",
            (
                f"Time-to-1st-interesting: {m.time_to_first_interesting_result:.1f}s"
                f" (exec {m.exec_to_first_interesting_result})"
            )
            if m.time_to_first_interesting_result is not None
            else "Time-to-1st-interesting: N/A",
            (
                f"Time-to-1st-real-bug: {m.time_to_first_real_bug:.1f}s"
                f" (exec {m.exec_to_first_real_bug})"
            )
            if m.time_to_first_real_bug is not None
            else "Time-to-1st-real-bug: N/A",
            (
                f"Time-to-1st-crash: {m.time_to_first_crash:.1f}s"
                f" (exec {m.exec_to_first_crash})"
            )
            if m.time_to_first_crash is not None
            else "Time-to-1st-crash: N/A",
        ]
        summary_path = self._out / "bug_coverage_summary.json"
        if summary_path.exists():
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            total_tags = payload.get("by_taxonomy_tag", {}).get("total", {})
            unique_tags = payload.get("by_taxonomy_tag", {}).get("unique", {})
            if total_tags:
                lines.append("Taxonomy totals : " + ", ".join(
                    f"{key}={value}" for key, value in sorted(total_tags.items())
                ))
            if unique_tags:
                lines.append("Taxonomy unique : " + ", ".join(
                    f"{key}={value}" for key, value in sorted(unique_tags.items())
                ))
        stats_text = "\n".join(lines) + "\n"
        (self._out / "stats.txt").write_text(stats_text, encoding="utf-8")
        (self._out / "fuzzer_stats").write_text(stats_text, encoding="utf-8")
        print("\n".join(lines))
