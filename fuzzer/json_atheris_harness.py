"""Atheris harness for the bundled JSON decoder target."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
import signal
import sys
from pathlib import Path

try:
    import atheris
except ImportError as exc:  # pragma: no cover - environment-dependent
    print(
        "Atheris is not installed. Install it in a supported environment "
        "(Linux/macOS, Python 3.11 or earlier per the official README).",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

if sys.platform == "win32":  # pragma: no cover - environment-dependent
    print(
        "Atheris does not document Windows support. Run the JSON target in "
        "Linux or macOS.",
        file=sys.stderr,
    )
    raise SystemExit(2)

if sys.version_info >= (3, 12):  # pragma: no cover - environment-dependent
    print(
        "Atheris officially documents support through Python 3.11. "
        "Use Python 3.11 or earlier for this target.",
        file=sys.stderr,
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
CRASHES_DIR = ROOT / "results" / "json" / "crashes"
LOGS_DIR = ROOT / "results" / "json" / "logs"
BUG_COUNTS_CSV = LOGS_DIR / "bug_counts.csv"

# In-memory dedup set so we only write new unique bugs to the CSV
_seen_crash_hashes: set[str] = set()

# Byte patterns that are known to trigger the infinite-loop timeout bug.
# Any input containing one of these is skipped immediately instead of
# burning 3 seconds on the alarm.
_KNOWN_TIMEOUT_PATTERNS: list[bytes] = []

# N-gram frequency counter: patterns that appear repeatedly across timeout
# inputs are promoted to _KNOWN_TIMEOUT_PATTERNS automatically.
from collections import Counter as _Counter
_timeout_ngram_counts: _Counter = _Counter()
_TIMEOUT_NGRAM_SIZE = 4
_TIMEOUT_PATTERN_THRESHOLD = 3   # promote after appearing in this many timeouts
_MAX_SKIP_PATTERNS = 64


def _write_bug_counts_csv(bug_type: str, exc_message: str, filename: str) -> None:
    """Append one entry to logs/bug_counts.csv, matching the ipv4/ipv6 binary format."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    write_header = not BUG_COUNTS_CSV.exists()
    with open(BUG_COUNTS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        writer.writerow([bug_type, "", exc_message, filename, "", 1])
JSON_TARGET_ROOT = ROOT / "json-decoder-main"
if str(JSON_TARGET_ROOT) not in sys.path:
    sys.path.insert(0, str(JSON_TARGET_ROOT))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fuzzer.format_loader import load_format
from fuzzer.mutation.tier2_semantic import get_mutator
from fuzzer.mutation.tier3_havoc import HavocMutator

with atheris.instrument_imports(include=["buggy_json"]):
    from buggy_json import loads
    from buggy_json.decoder_stv import InvalidityBug, JSONDecodeError


FMT = load_format("json")
SEMANTIC_MUTATOR = get_mutator("json", FMT)
BASE_WEIGHTS = FMT.get(
    "havoc_operators",
    {
        "bit_flip": 0.2,
        "byte_substitute": 0.2,
        "arithmetic": 0.15,
        "splice": 0.1,
        "delete_range": 0.1,
        "insert_random": 0.1,
        "interesting_byte": 0.15,
    },
)
SEED_BYTES = [example.encode("utf-8") for example in FMT.get("valid_examples", [])] or [b"{}"]

# DL weights file path (set by main.py via env var when DL is enabled)
_DL_WEIGHTS_PATH = os.environ.get("ATHERIS_DL_WEIGHTS")
_dl_weights_reload_counter = 0
_DL_WEIGHTS_RELOAD_EVERY = 500  # reload from file every N mutator calls


def _maybe_reload_dl_weights() -> None:
    """Reload operator weights from the DL monitor file if available."""
    global BASE_WEIGHTS, _dl_weights_reload_counter
    _dl_weights_reload_counter += 1
    if _DL_WEIGHTS_PATH is None or _dl_weights_reload_counter % _DL_WEIGHTS_RELOAD_EVERY != 0:
        return
    try:
        updated = json.loads(Path(_DL_WEIGHTS_PATH).read_text(encoding="utf-8"))
        if updated:
            BASE_WEIGHTS = updated
    except Exception:
        pass


def _trim(mutated: bytes, max_size: int) -> bytes:
    if max_size <= 0 or len(mutated) <= max_size:
        return mutated
    return mutated[:max_size]


def custom_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    """Bias libFuzzer mutations toward valid-ish JSON fragments."""
    _maybe_reload_dl_weights()
    random.seed(seed)

    current = data or random.choice(SEED_BYTES)
    if random.random() < 0.75:
        current = SEMANTIC_MUTATOR.mutate(current)

    havoc = HavocMutator(BASE_WEIGHTS)
    havoc_iters = max(2, min(12, len(current) // 8 + 2))
    current = havoc.mutate(current, iterations=havoc_iters)

    if not current:
        current = random.choice(SEED_BYTES)
    return _trim(current, max_size)


def _safe_json_loads(data: bytes):
    try:
        return True, json.loads(data), None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError) as exc:
        return False, None, exc


def _normalize_json_value(value):
    if isinstance(value, dict):
        return {str(key): _normalize_json_value(subvalue) for key, subvalue in value.items()}
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
    return value


def _sigalrm_handler(signum, frame):
    raise TimeoutError("buggy_json timed out")


def _record_oracle_mismatch(data: bytes, bug_type: str, exc_message: str) -> None:
    """Write a unique oracle mismatch and save a reproducer without stopping fuzzing."""
    digest = hashlib.sha1(data).hexdigest()
    if digest not in _seen_crash_hashes:
        _seen_crash_hashes.add(digest)
        CRASHES_DIR.mkdir(parents=True, exist_ok=True)
        artifact_path = CRASHES_DIR / f"{bug_type}-{digest}"
        artifact_path.write_bytes(data)
        _write_bug_counts_csv(bug_type, exc_message, artifact_path.name)


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    # Skip inputs that contain a learned timeout-triggering pattern
    for pattern in _KNOWN_TIMEOUT_PATTERNS:
        if pattern in data:
            return

    ref_ok, ref_value, ref_exc = _safe_json_loads(data)

    # Use an internal 3s timeout so we return before libFuzzer's 5s external
    # timer fires — prevents the fuzzer from exiting on the known slow-path bug.
    signal.signal(signal.SIGALRM, _sigalrm_handler)
    signal.alarm(3)
    try:
        candidate_value = loads(data)
    except TimeoutError:
        digest = hashlib.sha1(data).hexdigest()
        if digest not in _seen_crash_hashes:
            _seen_crash_hashes.add(digest)
            CRASHES_DIR.mkdir(parents=True, exist_ok=True)
            crash_path = CRASHES_DIR / f"timeout-{digest}"
            crash_path.write_bytes(data)
            _write_bug_counts_csv("TIMEOUT", "Buggy JSON decoder timed out", f"timeout-{digest}")

        # Learn n-grams from this timeout input; promote frequent ones to
        # skip patterns so the known bug stops consuming the budget.
        ngrams = {data[i:i + _TIMEOUT_NGRAM_SIZE]
                  for i in range(len(data) - _TIMEOUT_NGRAM_SIZE + 1)}
        for ng in ngrams:
            _timeout_ngram_counts[ng] += 1
            if (
                _timeout_ngram_counts[ng] >= _TIMEOUT_PATTERN_THRESHOLD
                and ng not in _KNOWN_TIMEOUT_PATTERNS
                and len(_KNOWN_TIMEOUT_PATTERNS) < _MAX_SKIP_PATTERNS
            ):
                _KNOWN_TIMEOUT_PATTERNS.append(ng)

        return  # return cleanly so libFuzzer keeps running
    except (JSONDecodeError, InvalidityBug, UnicodeDecodeError, ValueError) as exc:
        if ref_ok:
            _record_oracle_mismatch(data, "validity", str(exc))
            return
        # Both rejected — but if buggy_json raised the wrong exception type
        # (e.g. InvalidityBug instead of JSONDecodeError) that is itself a bug.
        if isinstance(exc, InvalidityBug):
            _record_oracle_mismatch(data, "wrong_exception_type", str(exc))
            return
        return
    finally:
        signal.alarm(0)

    if not ref_ok:
        _record_oracle_mismatch(data, "oracle_mismatch", str(ref_exc))
        return

    normalized_candidate = _normalize_json_value(candidate_value)
    normalized_reference = _normalize_json_value(ref_value)
    if normalized_candidate != normalized_reference:
        _record_oracle_mismatch(data, "oracle_mismatch", "Decoded values differ")
        return


def main() -> None:
    os.chdir(ROOT)
    atheris.Setup(sys.argv, test_one_input, custom_mutator=custom_mutator)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
