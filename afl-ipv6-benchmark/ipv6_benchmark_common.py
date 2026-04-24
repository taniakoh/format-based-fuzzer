from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pyparsing  # type: ignore

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTRACTED_DIR = REPO_ROOT / "linux-ipv6-parser_extracted" / "PYZ.pyz_extracted"
if not EXTRACTED_DIR.exists():
    raise SystemExit(
        f"Expected extracted IPv6 payload at {EXTRACTED_DIR}. "
        "Run pyinstxtractor against ipv4ipv6/linux-ipv6-parser first."
    )
if str(EXTRACTED_DIR) not in sys.path:
    sys.path.insert(0, str(EXTRACTED_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from buggy_ipyparse.ipv6_mstv import IPv6, InvalidHexLength, InvalidIPLength, InvalidityBug  # type: ignore
from fuzzer.oracle import evaluate_target_input


ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_TRACEBACK_LOG = "tracebacks.log"
DEFAULT_BUG_COUNTS_CSV = "bug_counts.csv"
EXPECTED_INVALID_EXCEPTIONS = (pyparsing.ParseException, InvalidHexLength, InvalidIPLength, InvalidityBug)


@dataclass(frozen=True)
class RunBug:
    bug_type: str
    message: str
    exc: Exception | None = None


@dataclass(frozen=True)
class RunOutcome:
    parsed_value: object | None
    bug: RunBug | None
    oracle_reason: str


def parser_instance():
    return IPv6


def analyze_ipv6_input(data: bytes) -> RunOutcome:
    text = data.decode("latin-1", errors="replace")
    oracle = evaluate_target_input("ipv6", text)
    parser_obj = parser_instance()

    try:
        parsed = parser_obj.parse_string(text)
    except EXPECTED_INVALID_EXCEPTIONS as exc:
        if oracle.supported and oracle.expected_valid is True:
            return RunOutcome(None, RunBug("validity", str(exc), exc), oracle.reason)
        return RunOutcome(None, None, oracle.reason)
    except Exception as exc:
        return RunOutcome(None, RunBug("bonus", str(exc), exc), oracle.reason)

    if oracle.supported and oracle.expected_valid is False:
        return RunOutcome(parsed, RunBug("oracle_mismatch", "Parser accepted invalid IPv6 input", None), oracle.reason)

    return RunOutcome(parsed, None, oracle.reason)


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


def print_outcome_summary(input_text: str, outcome: RunOutcome) -> dict:
    bug_count = defaultdict(int)
    print(f"Running the IPV6 parser with ipstr: {input_text}")
    if outcome.bug is None:
        print(f"Output: {outcome.parsed_value}")
        print("No bugs found. Skipping CSV creation")
        return bug_count

    if outcome.bug.bug_type == "validity":
        print(f"An invalidity bug has been triggered: {outcome.bug.message}")
    elif outcome.bug.bug_type == "oracle_mismatch":
        print(f"An oracle mismatch bug has been triggered: {outcome.bug.message}")
    else:
        print(f"An unknown exception has been triggered. {outcome.bug.message}")

    if outcome.bug.exc is not None:
        print_traceback_block(outcome.bug.exc)
        bug_id = track_exception(outcome.bug.exc)
        bug_count[(outcome.bug.bug_type, *bug_id)] += 1
    else:
        bug_count[(outcome.bug.bug_type, RuntimeError, outcome.bug.message, "<oracle>", 0)] += 1
    return bug_count


def load_input_bytes(args: argparse.Namespace) -> bytes:
    if args.input_file:
        return Path(args.input_file).read_bytes()
    if args.ipstr is not None:
        return args.ipstr.encode("utf-8")
    raise SystemExit("Provide either --input-file or --ipstr")
