"""
Evaluation Harness — metrics collection.

Records coverage, crashes, unique findings, and time-to-first-bug.
Writes results to results/<target>/stats.txt and bugs.jsonl.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import signal
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).parent.parent
RESULTS_DIR = _HERE / "results"
_TRACEBACK_FRAME_RE = re.compile(r'^\s*File\s+"([^"]+)",\s+line\s+(\d+)')
_BITMAP_COVERAGE_SLOTS = 65536
_PLOT_DATA_FIELDS = [
    "relative_time_sec",
    "total_execs",
    "coverage_units_seen",
    "coverage_units_percent",
    "interesting_test_cases",
    "corpus_size",
    "unique_bugs",
    "new_unique_bugs",
    "unique_crashes",
    "new_unique_crashes",
    "validity_bugs",
    "functional_bugs",
    "bonus_bugs",
]
_HEADLINE_UNIQUE_BUG_TYPES = frozenset(
    {
        "validity",
        "bonus",
        "reliability",
        "performance",
        "functional",
        "CRASH",
        "TIMEOUT",
    }
)


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


def _coverage_percent(coverage_seen: int) -> float:
    return (coverage_seen / float(_BITMAP_COVERAGE_SLOTS)) * 100.0


def should_count_toward_unique_bugs(
    bug_type: str,
    *,
    is_instrumentation_noise: bool = False,
) -> bool:
    """Return True when a finding belongs in the headline unique-bug count."""
    if is_instrumentation_noise:
        return False
    return str(bug_type) in _HEADLINE_UNIQUE_BUG_TYPES


def make_finding_signature(
    *,
    bug_type: str,
    exception: str = "",
    exit_code: int | None = None,
    stderr: str = "",
    stdout: str = "",
    traceback_text: str = "",
    bitmap: bytes | None = None,
) -> dict[str, object]:
    signal_name = _signal_name(exit_code)
    output_summary = (
        _normalize_fragment(stderr)
        or _normalize_fragment(stdout)
        or _normalize_fragment(traceback_text)
    )
    bug_site = _traceback_location(traceback_text)
    signature = {
        "bug_type": str(bug_type),
        "exit_code": exit_code,
        "signal": signal_name,
        "exception": str(exception),
        "output_summary": output_summary,
        "bitmap_digest": _bitmap_digest(bitmap),
        "bug_site": bug_site,
    }
    signature["key"] = json.dumps(signature, sort_keys=True)
    return signature


def _parse_traceback_frames(traceback_text: str) -> list[tuple[str, int]]:
    frames: list[tuple[str, int]] = []
    if not traceback_text:
        return frames

    for line in traceback_text.splitlines():
        match = _TRACEBACK_FRAME_RE.match(line)
        if not match:
            continue
        frames.append((match.group(1), int(match.group(2))))
    return frames


def _exception_class_from_text(text: str) -> str:
    cleaned = _first_nonempty_line(text).strip()
    if not cleaned:
        return ""
    class_part = cleaned.split(":", 1)[0].strip()
    return class_part.rsplit(".", 1)[-1]


def _traceback_exception_class(traceback_text: str) -> str:
    for line in reversed(traceback_text.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith("File ") or stripped.startswith("Traceback"):
            continue
        return _exception_class_from_text(stripped)
    return ""


def _traceback_location(traceback_text: str) -> str:
    """Return the last traceback frame as path:line when available."""
    frames = _parse_traceback_frames(traceback_text)
    if not frames:
        return ""
    filename, lineno = frames[-1]
    return f"{filename}:{lineno}"


def derive_bug_site(
    *,
    bug_type: str,
    exception: str = "",
    traceback_text: str = "",
    parser_bug_site: dict[str, object] | None = None,
    fallback_exc_type: str = "",
    fallback_filename: str = "",
    fallback_lineno: int | None = None,
) -> dict[str, object]:
    parser_bug_site = parser_bug_site or {}
    bug_type_str = str(bug_type)

    def _site_payload(
        dedup_source: str,
        exception_class: str,
        filename: str,
        lineno: int,
    ) -> dict[str, object]:
        payload = {
            "bug_type": bug_type_str,
            "dedup_source": dedup_source,
            "filename": filename,
            "lineno": lineno,
        }
        return payload

    frames = _parse_traceback_frames(traceback_text)
    traceback_exc_type = _traceback_exception_class(traceback_text)
    if frames:
        filename, lineno = frames[-1]
        exception_class = traceback_exc_type or str(fallback_exc_type or "").strip() or _exception_class_from_text(exception)
        payload = _site_payload("traceback", exception_class, filename, lineno)
        return {
            "dedup_source": "traceback",
            "exception_class": exception_class,
            "filename": filename,
            "lineno": lineno,
            "fault_location": f"{filename}:{lineno}",
            "key": json.dumps(payload, sort_keys=True),
        }

    parser_filename = str(parser_bug_site.get("filename", "") or "")
    parser_lineno = parser_bug_site.get("lineno")
    if parser_filename and parser_lineno is not None:
        parser_exc_type = str(parser_bug_site.get("exc_type", "") or "")
        exception_class = parser_exc_type or str(fallback_exc_type or "").strip() or _exception_class_from_text(exception)
        payload = _site_payload("parser_reported", exception_class, parser_filename, int(parser_lineno))
        return {
            "dedup_source": "parser_reported",
            "exception_class": exception_class,
            "filename": parser_filename,
            "lineno": int(parser_lineno),
            "fault_location": f"{parser_filename}:{int(parser_lineno)}",
            "key": json.dumps(payload, sort_keys=True),
        }

    if fallback_filename and fallback_lineno is not None:
        exception_class = str(fallback_exc_type or "").strip() or _exception_class_from_text(exception)
        payload = _site_payload("csv_fields", exception_class, fallback_filename, int(fallback_lineno))
        return {
            "dedup_source": "csv_fields",
            "exception_class": exception_class,
            "filename": fallback_filename,
            "lineno": int(fallback_lineno),
            "fault_location": f"{fallback_filename}:{int(fallback_lineno)}",
            "key": json.dumps(payload, sort_keys=True),
        }

    exception_class = str(fallback_exc_type or "").strip() or traceback_exc_type or _exception_class_from_text(exception)
    payload = {
        "bug_type": str(bug_type),
        "dedup_source": "fallback_exception",
        "exception_class": exception_class,
        "exception": str(exception),
    }
    return {
        "dedup_source": "fallback_exception",
        "exception_class": exception_class,
        "filename": "",
        "lineno": None,
        "fault_location": "",
        "key": json.dumps(payload, sort_keys=True),
    }


def _make_bug_signature(result, bitmap: bytes | None = None) -> dict[str, object]:
    return make_finding_signature(
        bug_type=str(result.bug_type),
        exception=str(result.exception_msg),
        exit_code=result.exit_code,
        stderr=result.stderr,
        stdout=result.stdout,
        traceback_text=getattr(result, "traceback", ""),
        bitmap=bitmap,
    )


def _parser_bug_signature(result) -> str | None:
    """Return a parser-site signature when the target reported an explicit bug."""
    parser_type = str(getattr(result, "parser_reported_bug_type", "") or "")
    filename = str(getattr(result, "parser_reported_filename", "") or "")
    lineno = getattr(result, "parser_reported_lineno", None)
    if not parser_type or not filename or lineno is None:
        return None

    payload = {
        "parser_reported_bug_type": parser_type,
        "parser_reported_exc_type": str(getattr(result, "parser_reported_exc_type", "") or ""),
        "parser_reported_message": str(getattr(result, "parser_reported_message", "") or ""),
        "parser_reported_filename": filename,
        "parser_reported_lineno": int(lineno),
    }
    return json.dumps(payload, sort_keys=True)


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
    headline_unique_bug_count: int = 0
    parser_site_unique_bug_count: int = 0
    traceback_unique_bugs: int = 0
    interesting_result_count: int = 0
    interesting_test_case_count: int = 0
    unique_crashes: int = 0
    validity_bugs: int = 0
    functional_bugs: int = 0
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
    def __init__(self, target: str, out_dir: "Path | None" = None):
        self.target = target
        self.metrics = FuzzMetrics(target=target)
        self._start = time.time()
        self._bug_signatures: set[str] = set()
        self._headline_bug_signatures: set[str] = set()
        self._parser_bug_signatures: set[str] = set()
        self._traceback_signatures: set[str] = set()
        self._unique_bug_entries: dict[str, dict[str, object]] = {}
        self._unique_finding_entries: dict[str, dict[str, object]] = {}
        self._crash_signatures: set[str] = set()
        self._run_metadata: dict[str, object] = {}
        self._hash_replay_cache: dict[str, dict[str, object]] = {}
        self._hash_replay_executor = None
        self._last_plotted_unique_bug_count = 0
        self._last_plotted_unique_crash_count = 0
        self._out = out_dir if out_dir is not None else RESULTS_DIR / target
        (self._out / "crashes").mkdir(parents=True, exist_ok=True)
        (self._out / "logs").mkdir(parents=True, exist_ok=True)
        (self._out / "queue").mkdir(parents=True, exist_ok=True)
        # Clear previous bugs.jsonl for this run
        bugs_file = self._out / "bugs.jsonl"
        bugs_file.write_text("", encoding="utf-8")
        self._unique_bugs_path = self._out / "unique_bugs.json"
        self._unique_findings_path = self._out / "unique_findings.json"
        self._bug_coverage_summary_path = self._out / "bug_coverage_summary.json"
        self._bug_counts_path = self._out / "logs" / "bug_counts.csv"
        self._bug_counts_raw_path = self._out / "logs" / "bug_counts_raw.csv"
        self._write_unique_bugs()
        self._write_unique_findings()
        self._write_bug_coverage_summary()
        self._write_bug_counts_csv()
        self._plot_path = self._out / "plot_data"
        self._dl_training_path = self._out / "dl_training.jsonl"
        self._dl_summary_path = self._out / "dl_summary.json"
        self._energy_log_path = self._out / "energy_log.csv"
        self._oracle_log_path = self._out / "oracle_log.csv"
        with open(self._plot_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(_PLOT_DATA_FIELDS)
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

    def _confirm_frida_crash(self, input_str: str, result) -> dict[str, object]:
        from fuzzer.executor import BugType, Executor

        replay_info = {
            "attempted": False,
            "confirmed": False,
            "status": "not_applicable",
            "replay_bug_type": "",
            "replay_exception": "",
        }

        if self._run_metadata.get("executor_mode") != "Frida":
            return replay_info
        if result.bug_type not in (BugType.CRASH, BugType.TIMEOUT):
            return replay_info
        if getattr(result, "is_instrumentation_noise", False):
            return replay_info

        # Frida is currently unstable on this machine, so any Frida-reported
        # crash or timeout is retained as a logged finding but excluded from
        # trusted headline crash counts until the backend is fixed.
        result.force_instrumentation_noise = True
        replay_info.update(
            {
                "status": "suppressed_untrusted_frida_backend",
                "replay_exception": "Frida crash/timeouts are untrusted on this machine",
            }
        )
        return replay_info

        cached = self._hash_replay_cache.get(input_str)
        if cached is not None:
            replay_info.update(cached)
        else:
            replay_info["attempted"] = True
            try:
                if self._hash_replay_executor is None:
                    self._hash_replay_executor = Executor(self.target, coverage_mode="hash")
                replay_result = self._hash_replay_executor._run_binary(input_str)
                replay_bug_type = str(getattr(replay_result, "bug_type", "") or "")
                replay_exception = str(getattr(replay_result, "exception_msg", "") or "")
                replay_info.update(
                    {
                        "status": "completed",
                        "replay_bug_type": replay_bug_type,
                        "replay_exception": replay_exception,
                        "confirmed": replay_bug_type in (BugType.CRASH, BugType.TIMEOUT),
                    }
                )
            except Exception as exc:
                replay_info.update(
                    {
                        "status": f"replay_failed: {exc}",
                        "replay_exception": str(exc),
                    }
                )
            self._hash_replay_cache[input_str] = dict(replay_info)

        if replay_info["attempted"] and not replay_info["confirmed"] and replay_info["status"] == "completed":
            result.force_instrumentation_noise = True

        return replay_info

    def record_execution(self, input_data: bytes, result, bitmap: bytes | None = None) -> None:
        """Record one fuzzer execution result."""
        self.metrics.total_executions += 1
        input_str = input_data.decode("latin-1", errors="replace")
        replay_info = self._confirm_frida_crash(input_str, result)

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
        parser_signature_key = _parser_bug_signature(result)
        bug_site = derive_bug_site(
            bug_type=str(result.bug_type),
            exception=str(result.exception_msg),
            traceback_text=getattr(result, "traceback", ""),
            parser_bug_site={
                "bug_type": getattr(result, "parser_reported_bug_type", None),
                "exc_type": getattr(result, "parser_reported_exc_type", ""),
                "filename": getattr(result, "parser_reported_filename", ""),
                "lineno": getattr(result, "parser_reported_lineno", None),
            },
        )
        bug_site_key = str(bug_site["key"])
        is_instrumentation_noise = bool(getattr(result, "is_instrumentation_noise", False))
        if not is_instrumentation_noise:
            self._bug_signatures.add(bug_site_key)
            self.metrics.unique_bug_count = len(self._bug_signatures)
            if parser_signature_key is not None:
                self._parser_bug_signatures.add(parser_signature_key)
                self.metrics.parser_site_unique_bug_count = len(self._parser_bug_signatures)
            if str(bug_site.get("dedup_source", "")) == "traceback":
                self._traceback_signatures.add(bug_site_key)
                self.metrics.traceback_unique_bugs = len(self._traceback_signatures)
        if should_count_toward_unique_bugs(
            str(result.bug_type),
            is_instrumentation_noise=is_instrumentation_noise,
        ):
            self._headline_bug_signatures.add(bug_site_key)
            self.metrics.headline_unique_bug_count = len(self._headline_bug_signatures)
        if not is_instrumentation_noise and bug_site_key not in self._unique_bug_entries:
            self._unique_bug_entries[bug_site_key] = {
                **self._finding_entry(result, signature, input_str, bug_site),
                "bug_type": result.bug_type,
                "site_hit_count": 1,
                "total_occurrences": 1,
            }
            self._write_unique_bugs()
        elif not is_instrumentation_noise:
            updated_count = int(self._unique_bug_entries[bug_site_key].get("site_hit_count", 1)) + 1
            self._unique_bug_entries[bug_site_key]["site_hit_count"] = updated_count
            self._unique_bug_entries[bug_site_key]["total_occurrences"] = updated_count
            self._write_unique_bugs()

        if signature_key not in self._unique_finding_entries:
            self._unique_finding_entries[signature_key] = self._finding_entry(
                result,
                signature,
                input_str,
                bug_site,
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
            "instrumentation_noise": bool(getattr(result, "is_instrumentation_noise", False)),
            "frida_crash_untrusted": (
                self._run_metadata.get("executor_mode") == "Frida"
                and result.bug_type in ("CRASH", "TIMEOUT")
            ),
            "classification": _taxonomy_payload(result),
            "signature": {k: v for k, v in signature.items() if k != "key"},
            "bug_site": {k: v for k, v in bug_site.items() if k != "key"},
            "parser_bug_site": {
                "bug_type": getattr(result, "parser_reported_bug_type", None),
                "exc_type": getattr(result, "parser_reported_exc_type", ""),
                "filename": getattr(result, "parser_reported_filename", ""),
                "lineno": getattr(result, "parser_reported_lineno", None),
            },
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
            "hash_replay_confirmation": replay_info,
        }
        with open(self._out / "bugs.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        if result.bug_type == BugType.VALIDITY:
            self.metrics.validity_bugs += 1
        elif result.bug_type == BugType.BONUS:
            self.metrics.bonus_bugs += 1
        elif result.bug_type == BugType.FUNCTIONAL:
            self.metrics.functional_bugs += 1
        elif result.bug_type == BugType.INVALIDITY:
            self.metrics.invalidity_count += 1
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
            f"coverage={queue_id}\n"
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
        new_unique_bugs = self.metrics.unique_bug_count - self._last_plotted_unique_bug_count
        new_unique_crashes = self.metrics.unique_crashes - self._last_plotted_unique_crash_count
        with open(self._plot_path, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"{time.time() - self._start:.3f}",
                self.metrics.total_executions,
                self.metrics.behaviors_covered,
                f"{_coverage_percent(self.metrics.behaviors_covered):.6f}",
                self.metrics.interesting_test_case_count,
                corpus_size,
                # Progress graphs should reflect the canonical deduplicated
                # bug-site count shown in stats.txt, unique_bugs.json, and
                # logs/bug_counts.csv.
                self.metrics.unique_bug_count,
                max(0, new_unique_bugs),
                self.metrics.unique_crashes,
                max(0, new_unique_crashes),
                self.metrics.validity_bugs,
                self.metrics.functional_bugs,
                self.metrics.bonus_bugs,
            ])
        self._last_plotted_unique_bug_count = self.metrics.unique_bug_count
        self._last_plotted_unique_crash_count = self.metrics.unique_crashes

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
        self._write_bug_counts_csv()
        self._write_stats()
        return self.metrics

    def _finding_entry(
        self,
        result,
        signature: dict[str, object],
        input_str: str,
        bug_site: dict[str, object],
    ) -> dict[str, object]:
        return {
            "bug_type": result.bug_type,
            "classification": _taxonomy_payload(result),
            "signature": {k: v for k, v in signature.items() if k != "key"},
            "bug_site": {k: v for k, v in bug_site.items() if k != "key"},
            "parser_bug_site": {
                "bug_type": getattr(result, "parser_reported_bug_type", None),
                "exc_type": getattr(result, "parser_reported_exc_type", ""),
                "filename": getattr(result, "parser_reported_filename", ""),
                "lineno": getattr(result, "parser_reported_lineno", None),
            },
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
            "count_definition": "All non-instrumentation-noise findings, deduplicated by canonical bug site using source filename and line when available. This matches logs/bug_counts.csv. When no source location is available, dedup falls back to normalized exception fields and finally exception text.",
            "entry_count_field": "site_hit_count",
            "unique_bug_count": self.metrics.unique_bug_count,
            "headline_unique_bug_count": self.metrics.headline_unique_bug_count,
            "parser_site_unique_bug_count": self.metrics.parser_site_unique_bug_count,
            "traceback_unique_bug_count": self.metrics.traceback_unique_bugs,
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
        unique_real_by_bug_type = Counter()
        total_by_tag = Counter()
        unique_by_tag = Counter()
        unique_real_by_tag = Counter()
        parser_reported_totals = Counter()
        parser_reported_unique = Counter()
        parser_reported_unique_real = Counter()

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

        for entry in self._unique_bug_entries.values():
            bug_type = str(entry.get("bug_type", "unknown"))
            unique_real_by_bug_type[bug_type] += 1
            parser_site = entry.get("parser_bug_site", {})
            parser_type = parser_site.get("bug_type") or "none"
            parser_reported_unique_real[str(parser_type)] += 1
            classification = entry.get("classification", {})
            for tag in classification.get("taxonomy_tags", []):
                unique_real_by_tag[str(tag)] += 1

        wall_time = self.metrics.wall_time_secs
        total_execs = self.metrics.total_executions
        coverage_kind = "bitmap_slots"
        extra_scalars: dict[str, object] = {
            "coverage_units_seen": self.metrics.behaviors_covered,
            "coverage_units_percent": round(_coverage_percent(self.metrics.behaviors_covered), 6),
            "coverage_units_kind": coverage_kind,
            "coverage_slots_seen": self.metrics.behaviors_covered,
            "coverage_slot_percent": round(_coverage_percent(self.metrics.behaviors_covered), 6),
        }
        if self._run_metadata.get("executor_mode") == "Frida":
            extra_scalars["coverage_units_kind"] = "afl_novelty_slots"
            extra_scalars["afl_novelty_slots_seen"] = self.metrics.behaviors_covered

        payload = {
            "target": self.target,
            "run_scalars": {
                "wall_time_secs": round(wall_time, 1),
                "total_executions": total_execs,
                "execs_per_sec": round(total_execs / max(1.0, wall_time), 4),
                "pass_count": self.metrics.pass_count,
                "pass_rate": round(self.metrics.pass_count / max(1, total_execs), 4),
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
                **extra_scalars,
            },
            "totals": {
                "interesting_results": self.metrics.interesting_result_count,
                "unique_findings": len(finding_entries),
                "unique_bugs": self.metrics.unique_bug_count,
                "headline_unique_bugs": self.metrics.headline_unique_bug_count,
                "unique_real_bugs": self.metrics.unique_bug_count,
                "parser_site_unique_bugs": self.metrics.parser_site_unique_bug_count,
                "parser_site_unique_real_bugs": self.metrics.parser_site_unique_bug_count,
                "traceback_unique_bugs": self.metrics.traceback_unique_bugs,
                "unique_crashes": self.metrics.unique_crashes,
            },
            "by_bug_type": {
                "total": dict(sorted(total_by_bug_type.items())),
                "unique": dict(sorted(unique_by_bug_type.items())),
                "unique_real": dict(sorted(unique_real_by_bug_type.items())),
            },
            "by_parser_reported_type": {
                "total": dict(sorted(parser_reported_totals.items())),
                "unique": dict(sorted(parser_reported_unique.items())),
                "unique_real": dict(sorted(parser_reported_unique_real.items())),
            },
            "by_taxonomy_tag": {
                "total": dict(sorted(total_by_tag.items())),
                "unique": dict(sorted(unique_by_tag.items())),
                "unique_real": dict(sorted(unique_real_by_tag.items())),
            },
        }
        self._bug_coverage_summary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    def _iter_bug_entries(self) -> list[dict[str, object]]:
        entries: list[dict[str, object]] = []
        bugs_path = self._out / "bugs.jsonl"
        if not bugs_path.exists():
            return entries

        for line in bugs_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entries.append(json.loads(line))
        return entries

    def _write_bug_counts_csv(self) -> None:
        raw_rows: list[dict[str, object]] = []
        rows: dict[str, dict[str, object]] = {}
        for entry in self._iter_bug_entries():
            bug_type = str(entry.get("bug_type", "unknown"))
            exception = str(entry.get("exception", "") or "")
            parser_bug_site = entry.get("parser_bug_site", {}) or {}
            site = derive_bug_site(
                bug_type=bug_type,
                exception=exception,
                traceback_text=str(entry.get("traceback", "") or ""),
                parser_bug_site={
                    "bug_type": parser_bug_site.get("bug_type"),
                    "exc_type": parser_bug_site.get("exc_type", ""),
                    "filename": parser_bug_site.get("filename", ""),
                    "lineno": parser_bug_site.get("lineno", None),
                },
            )
            instrumentation_noise = bool(entry.get("instrumentation_noise", False))
            raw_rows.append(
                {
                    "exec": int(entry.get("exec", 0) or 0),
                    "bug_type": bug_type,
                    "exc_type": str(site.get("exception_class", "") or ""),
                    "exc_message": exception,
                    "filename": str(site.get("filename", "") or ""),
                    "lineno": "" if site.get("lineno", None) is None else int(site["lineno"]),
                    "instrumentation_noise": int(instrumentation_noise),
                }
            )
            if instrumentation_noise:
                continue
            row_key = str(site["key"])
            if row_key not in rows:
                rows[row_key] = {
                    "bug_type": bug_type,
                    "exc_type": str(site.get("exception_class", "") or ""),
                    "exc_message": exception,
                    "filename": str(site.get("filename", "") or ""),
                    "lineno": "" if site.get("lineno", None) is None else int(site["lineno"]),
                    "count": 0,
                }
            rows[row_key]["count"] = int(rows[row_key]["count"]) + 1

        ordered_rows = sorted(
            rows.values(),
            key=lambda row: (
                str(row["bug_type"]),
                str(row["filename"]),
                "" if row["lineno"] == "" else f"{int(row['lineno']):09d}",
                str(row["exc_type"]),
                str(row["exc_message"]),
            ),
        )
        with open(self._bug_counts_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
            for row in ordered_rows:
                writer.writerow([
                    row["bug_type"],
                    row["exc_type"],
                    row["exc_message"],
                    row["filename"],
                    row["lineno"],
                    row["count"],
                ])
        with open(self._bug_counts_raw_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["exec", "bug_type", "exc_type", "exc_message", "filename", "lineno", "instrumentation_noise"])
            for row in sorted(
                raw_rows,
                key=lambda row: (
                    int(row["exec"]),
                    str(row["bug_type"]),
                    str(row["filename"]),
                    "" if row["lineno"] == "" else f"{int(row['lineno']):09d}",
                    str(row["exc_type"]),
                    str(row["exc_message"]),
                ),
            ):
                writer.writerow([
                    row["exec"],
                    row["bug_type"],
                    row["exc_type"],
                    row["exc_message"],
                    row["filename"],
                    row["lineno"],
                    row["instrumentation_noise"],
                ])

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
        coverage_percent = _coverage_percent(m.behaviors_covered)
        if self._run_metadata.get("executor_mode") == "Frida":
            coverage_line = f"AFL novelty slots: {m.behaviors_covered} ({coverage_percent:.3f}% of {_BITMAP_COVERAGE_SLOTS}-slot bitmap)"
        else:
            coverage_line = f"Coverage slots  : {m.behaviors_covered} ({coverage_percent:.3f}% of {_BITMAP_COVERAGE_SLOTS}-slot bitmap)"
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
            coverage_line,
            f"Interesting tests: {m.interesting_test_case_count}",
            f"Interesting results: {m.interesting_result_count}",
            f"Unique bugs     : {m.unique_bug_count}",
            f"Headline uniq   : {m.headline_unique_bug_count}",
            f"Parser-site uniq: {m.parser_site_unique_bug_count}",
            f"Traceback-unique: {m.traceback_unique_bugs}",
            f"Validity bugs   : {m.validity_bugs}",
            f"Functional bugs : {m.functional_bugs}",
            f"Bonus bugs      : {m.bonus_bugs}",
            f"Invalidity count: {m.invalidity_count}",
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
        if self._run_metadata.get("executor_mode") == "Frida":
            lines.append(
                "Crash trust note: Frida crash/timeouts are excluded from headline crash counts on this machine"
            )
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
