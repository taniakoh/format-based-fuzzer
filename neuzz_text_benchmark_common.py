from __future__ import annotations

import argparse
import csv
import hashlib
import inspect
import json
import os
import signal
import subprocess
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_TRACEBACK_LOG = "tracebacks.log"
DEFAULT_BUG_COUNTS_CSV = "bug_counts.csv"
BITMAP_SIZE = 65536


def detect_workspace_target(workspace: Path) -> str:
    name = workspace.resolve().name
    prefix = "neuzz-"
    suffix = "-benchmark"
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix) : -len(suffix)]
    raise ValueError(f"Cannot infer benchmark target from workspace name: {name}")


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
    raise InputTimeoutError("target timed out")


def _ensure_import_path(path: Path) -> None:
    resolved = str(path.resolve())
    if resolved not in sys.path:
        sys.path.insert(0, resolved)


def _load_ipv4_parser():
    _ensure_import_path(REPO_ROOT / "linux-ipv4-parser_extracted" / "PYZ.pyz_extracted")
    import pyparsing  # type: ignore
    from buggy_ipyparse.ipv4_stv import IPv4, IPv4ParsingError, InvalidityBug  # type: ignore

    expected = (pyparsing.ParseException, IPv4ParsingError, InvalidityBug)
    return IPv4.parse_string, expected


def _load_ipv6_parser():
    _ensure_import_path(REPO_ROOT / "linux-ipv6-parser_extracted" / "PYZ.pyz_extracted")
    import pyparsing  # type: ignore
    from buggy_ipyparse.ipv6_mstv import (  # type: ignore
        IPv6,
        InvalidHexLength,
        InvalidIPLength,
        InvalidityBug,
    )

    expected = (
        pyparsing.ParseException,
        InvalidHexLength,
        InvalidIPLength,
        InvalidityBug,
    )
    return IPv6.parse_string, expected


def _load_cidrize_parser():
    _ensure_import_path(REPO_ROOT / "linux-cidrize-runner_extracted" / "PYZ.pyz_extracted")
    from buggy_cidrize.cidrize_stv import cidrize  # type: ignore

    expected: list[type[BaseException]] = [ValueError, TypeError]
    try:
        from netaddr.core import AddrFormatError  # type: ignore

        expected.append(AddrFormatError)
    except Exception:
        pass

    sig = inspect.signature(cidrize)

    def run(text: str):
        kwargs: dict[str, object] = {}
        if "strict" in sig.parameters:
            kwargs["strict"] = False
        if "raise_errors" in sig.parameters:
            kwargs["raise_errors"] = True
        return cidrize(text, **kwargs)

    return run, tuple(expected)


def load_parser(target: str):
    normalized = target.lower()
    if normalized == "ipv4":
        return _load_ipv4_parser()
    if normalized == "ipv6":
        return _load_ipv6_parser()
    if normalized == "cidrize":
        return _load_cidrize_parser()
    raise ValueError(f"Unsupported benchmark target: {target}")


def analyze_text_input(target: str, data: bytes, timeout_seconds: int = 3) -> RunOutcome:
    from fuzzer.oracle import evaluate_target_input

    text = data.decode("latin-1", errors="replace")
    oracle = evaluate_target_input(target, text)
    parser_fn, expected_exceptions = load_parser(target)

    has_sigalrm = hasattr(signal, "SIGALRM") and timeout_seconds > 0
    previous_handler = None
    if has_sigalrm:
        previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, _sigalrm_handler)
        signal.alarm(timeout_seconds)

    try:
        result = parser_fn(text)
    except InputTimeoutError as exc:
        return RunOutcome(None, None, RunBug("TIMEOUT", f"{target} target timed out", exc))
    except expected_exceptions as exc:
        if oracle.supported and oracle.expected_valid is True:
            return RunOutcome(None, None, RunBug("validity", str(exc), exc))
        return RunOutcome(None, None, None)
    except Exception as exc:
        bug_type = "functional" if oracle.supported else "bonus"
        return RunOutcome(None, None, RunBug(bug_type, str(exc), exc))
    finally:
        if has_sigalrm:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    if oracle.supported and oracle.expected_valid is False:
        return RunOutcome(None, None, RunBug("validity", f"{target} parser accepted invalid input", None))

    return RunOutcome(result, type(result).__name__, None)


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
        print(f"Output: {outcome.decoded_value}")
        print("No bugs found. Skipping CSV creation")
        return bug_count

    bug_type = outcome.bug.bug_type
    message = outcome.bug.message
    exc = outcome.bug.exc
    if bug_type == "validity":
        print(f"A validity bug has been triggered: {message}")
    elif bug_type in {"functional", "TIMEOUT"}:
        print(f"A functional bug has been triggered: {message}")
    else:
        print(f"An unknown exception has been triggered. {message}")

    if exc is not None:
        print_traceback_block(exc)
        bug_id = track_exception(exc)
        bug_count[(bug_type, *bug_id)] += 1
    else:
        bug_count[(bug_type, RuntimeError, message, "<oracle>", 0)] += 1
    return bug_count


def iter_neuzz_inputs(root: Path, include_vari_seeds: bool) -> list[Path]:
    directories = ["crashes", "seeds"]
    if include_vari_seeds:
        directories.append("vari_seeds")

    inputs: list[Path] = []
    for directory in directories:
        path = root / directory
        if not path.exists():
            continue
        for child in sorted(path.iterdir()):
            if child.is_file() and not child.name.startswith(".") and not child.name.startswith("README"):
                inputs.append(child)
    return inputs


def parse_run_log(log_path: Path) -> dict[str, str]:
    import re

    stats: dict[str, str] = {}
    if not log_path.exists():
        return stats

    total_execs = None
    edge_coverages: list[str] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"total execs\s+(\d+)\s+edge coverage\s+(\d+)", line)
        if match:
            total_execs = match.group(1)
            edge_coverages.append(match.group(2))
            continue
        match = re.search(r"edge num\s+(\d+)", line)
        if match:
            edge_coverages.append(match.group(1))

    if total_execs is not None:
        stats["neuzz_execs"] = total_execs
    if edge_coverages:
        stats["max_edge_coverage"] = str(max(int(value) for value in edge_coverages))
    return stats


def replay_showmap_edges(target_script: Path, input_path: Path, python_bin: str, timeout_ms: int = 1000) -> set[int]:
    showmap_bin = os.environ.get("NEUZZ_AFL_SHOWMAP", "afl-showmap")
    env = os.environ.copy()
    env.setdefault("AFL_QUIET", "1")
    proc = subprocess.run(
        [
            showmap_bin,
            "-q",
            "-e",
            "-o",
            "/dev/stdout",
            "-m",
            "512",
            "-t",
            str(timeout_ms),
            python_bin,
            str(target_script),
            str(input_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    edges: set[int] = set()
    for stream_text in (proc.stdout, proc.stderr):
        for line in stream_text.splitlines():
            if ":" not in line:
                continue
            edge = line.split(":", 1)[0].strip()
            if edge.isdigit():
                edges.add(int(edge))
    return edges


def load_input_bytes(args: argparse.Namespace) -> bytes:
    if args.input_file:
        return Path(args.input_file).read_bytes()
    if args.str_input is not None:
        return args.str_input.encode("latin-1", errors="replace")
    raise SystemExit("Provide either --input-file or --str-input.")


def load_seed_lines(workspace: Path) -> list[bytes]:
    config_path = workspace / "config" / f"{detect_workspace_target(workspace)}_format.json"
    corpus_path = workspace / "corpus_src" / f"{detect_workspace_target(workspace)}_seeds.txt"

    seeds: list[bytes] = []
    seen: set[bytes] = set()

    if config_path.exists():
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for example in config.get("valid_examples", []):
            encoded = str(example).encode("utf-8")
            if encoded not in seen:
                seeds.append(encoded)
                seen.add(encoded)

    if corpus_path.exists():
        for line in corpus_path.read_text(encoding="utf-8").splitlines():
            candidate = line.strip().encode("utf-8")
            if not candidate or candidate in seen:
                continue
            seeds.append(candidate)
            seen.add(candidate)

    return seeds
