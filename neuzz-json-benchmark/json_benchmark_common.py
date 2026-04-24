from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import signal
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET_ROOT = ROOT / "target"
if str(TARGET_ROOT) not in sys.path:
    sys.path.insert(0, str(TARGET_ROOT))

from buggy_json import loads
from buggy_json.decoder_stv import InvalidityBug, JSONDecodeError, PerformanceBug

try:
    import coverage
except ImportError:  # pragma: no cover - environment-dependent
    coverage = None


DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_TRACEBACK_LOG = "tracebacks.log"
DEFAULT_BUG_COUNTS_CSV = "bug_counts.csv"
DEFAULT_COVERAGE_FILE = ".coverage_buggy_json_neuzz"


@dataclass(frozen=True)
class RunBug:
    bug_type: str
    message: str
    exc: Exception | None = None


@dataclass(frozen=True)
class RunOutcome:
    decoded_value: object | None
    decoded_type: str | None
    bug: RunBug | None


class InputTimeoutError(Exception):
    pass


def _sigalrm_handler(signum, frame):  # pragma: no cover - signal-driven
    raise InputTimeoutError("buggy_json timed out")


def safe_json_loads(data: bytes):
    try:
        return True, json.loads(data), None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        return False, None, exc


def normalize_json_value(value):
    if isinstance(value, dict):
        return {str(key): normalize_json_value(subvalue) for key, subvalue in value.items()}
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
    return value


def analyze_json_input(data: bytes, timeout_seconds: int = 3) -> RunOutcome:
    ref_ok, ref_value, ref_exc = safe_json_loads(data)
    has_sigalrm = hasattr(signal, "SIGALRM") and timeout_seconds > 0
    previous_handler = None
    if has_sigalrm:
        previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, _sigalrm_handler)
        signal.alarm(timeout_seconds)
    try:
        candidate_value = loads(data)
    except InputTimeoutError as exc:
        return RunOutcome(None, None, RunBug("TIMEOUT", "Buggy JSON decoder timed out", exc))
    except PerformanceBug as exc:
        return RunOutcome(None, None, RunBug("performance", str(exc), exc))
    except (JSONDecodeError, InvalidityBug, UnicodeDecodeError, ValueError) as exc:
        if ref_ok:
            return RunOutcome(None, None, RunBug("validity", str(exc), exc))
        if isinstance(exc, InvalidityBug):
            return RunOutcome(None, None, RunBug("wrong_exception_type", str(exc), exc))
        return RunOutcome(None, None, None)
    except Exception as exc:
        return RunOutcome(None, None, RunBug("bonus", str(exc), exc))
    finally:
        if has_sigalrm:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    if not ref_ok:
        message = str(ref_exc) if ref_exc is not None else "Reference JSON decoder rejected input"
        return RunOutcome(None, None, RunBug("oracle_mismatch", message, None))

    normalized_candidate = normalize_json_value(candidate_value)
    normalized_reference = normalize_json_value(ref_value)
    if normalized_candidate != normalized_reference:
        return RunOutcome(None, None, RunBug("oracle_mismatch", "Decoded values differ", None))

    return RunOutcome(candidate_value, str(type(candidate_value)), None)


def track_exception(exc: Exception):
    tb = exc.__traceback__
    if tb is None:
        return (type(exc), str(exc), "<no traceback>", 0)
    last_frame = traceback.extract_tb(tb)[-1]
    return (
        type(exc),
        str(exc),
        last_frame.filename,
        last_frame.lineno,
    )


def log_full_traceback(exc: Exception, bug_type: str, log_dir: Path, filename: str = DEFAULT_TRACEBACK_LOG) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / filename
    timestamp = datetime.now(UTC)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("=" * 80 + "\n")
        handle.write(f"Timestamp : {timestamp}\n")
        handle.write(f"Bug Type  : {bug_type}\n")
        handle.write(f"Exception: {type(exc).__name__}: {exc}\n\n")
        handle.write("Traceback:\n")
        handle.write("".join(traceback.format_exception(exc)))
        handle.write("\n\n")


def append_bug_counts(bug_count: dict, csv_path: Path) -> None:
    if not bug_count:
        return
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        for key, count in bug_count.items():
            bug_type, exc_type, exc_message, filename, lineno = key
            writer.writerow([bug_type, exc_type.__name__, exc_message, filename, lineno, count])


def write_unique_artifact(data: bytes, results_dir: Path, bug_type: str) -> Path:
    crashes_dir = results_dir / "crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha1(data).hexdigest()
    artifact_path = crashes_dir / f"{bug_type}-{digest}"
    if not artifact_path.exists():
        artifact_path.write_bytes(data)
    return artifact_path


def print_traceback_block(exc: Exception) -> None:
    print("=" * 60)
    print("TRACEBACK")
    print("=" * 60)
    traceback.print_exception(exc)
    print("=" * 60)


def print_outcome_summary(outcome: RunOutcome) -> dict:
    bug_count = defaultdict(int)
    if outcome.bug is None:
        print(f"Output decoded data: {outcome.decoded_value} of type {outcome.decoded_type}")
        return bug_count

    bug_type = outcome.bug.bug_type
    message = outcome.bug.message
    exc = outcome.bug.exc
    if bug_type == "performance":
        print(f"A performance bug has been triggered: {message}")
    elif bug_type in {"validity", "wrong_exception_type"}:
        print(f"An invalidity bug has been triggered: {message}")
    elif bug_type == "oracle_mismatch":
        print(f"An oracle mismatch bug has been triggered: {message}")
    elif bug_type == "TIMEOUT":
        print(f"A timeout bug has been triggered: {message}")
    else:
        print(f"An unknown exception has been triggered. {message}")

    if exc is not None:
        print_traceback_block(exc)
        bug_id = track_exception(exc)
        bug_count[(bug_type, *bug_id)] += 1
    else:
        bug_count[(bug_type, RuntimeError, message, "<oracle>", 0)] += 1
    return bug_count


def maybe_create_coverage(coverage_file: str):
    if coverage is None:
        return None
    return coverage.Coverage(
        data_file=coverage_file,
        source=["buggy_json"],
        branch=True,
    )


def print_full_coverage_summary(cov) -> None:
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        json_path = tmp.name

    try:
        cov.json_report(outfile=json_path)
        with open(json_path, encoding="utf-8") as handle:
            report = json.load(handle)

        totals = report["totals"]
        statements = totals["num_statements"]
        covered_lines = totals["covered_lines"]
        branches = totals.get("num_branches", 0)
        covered_branches = totals.get("covered_branches", 0)

        line_cov = (covered_lines / statements * 100) if statements else 100.0
        branch_cov = (covered_branches / branches * 100) if branches else 100.0
        combined_cov = (
            ((covered_lines + covered_branches) / (statements + branches) * 100)
            if (statements + branches)
            else 100.0
        )

        print("\n" + "=" * 60)
        print("detailed coverage summary")
        print("=" * 60)
        print(f"line coverage     : {line_cov:.2f}% ({covered_lines}/{statements})")
        print(f"branch coverage   : {branch_cov:.2f}% ({covered_branches}/{branches})")
        print(f"combined coverage : {combined_cov:.2f}%")
        print("=" * 60)
    finally:
        os.remove(json_path)


def print_missing_branches(cov) -> None:
    print("\n" + "=" * 60)
    print("uncovered branches")
    print("=" * 60)
    data = cov.get_data()
    for filename in sorted(data.measured_files()):
        if "buggy_json" not in filename:
            continue
        try:
            (_, _statements, _excluded, _missing_lines, missing_branches) = cov.analysis2(filename)
        except coverage.CoverageException:
            continue
        if not missing_branches:
            continue
        print(f"\nfile: {filename}")
        by_line = {}
        print("missing_branches", missing_branches)
        for from_to_line in missing_branches.split(","):
            from_to_line = from_to_line.strip()
            if "-" in from_to_line:
                from_line, to_line = from_to_line.split("-")
                by_line.setdefault(int(from_line), []).append(int(to_line))
            else:
                from_line = from_to_line
                by_line.setdefault(int(from_line), []).append(-1)

        for from_line, targets in sorted(by_line.items()):
            targets_str = ", ".join("exit" if t < 0 else f"line {t}" for t in targets)
            print(f" line {from_line}: missing branch to {targets_str}")


def load_input_bytes(args: argparse.Namespace) -> bytes:
    if args.input_file:
        return Path(args.input_file).read_bytes()
    if args.str_json is not None:
        return args.str_json.encode("utf-8")
    raise SystemExit("Provide either --input-file or --str-json")
