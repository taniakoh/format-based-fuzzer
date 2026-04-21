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
import traceback
from collections import Counter as _Counter
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
_INTERNAL_TIMEOUT_SECS = 11

# In-memory dedup set so we only write new unique bugs to the CSV.
_seen_crash_hashes: set[str] = set()
# Record one invalidity artifact per distinct parser rejection site and message.
_seen_invalidity_sites: set[tuple[str, str, int]] = set()

# Byte patterns that repeatedly trigger the known infinite-loop bug.
# We only skip them after the harness has already recorded the bug.
_KNOWN_TIMEOUT_PATTERNS: list[bytes] = []

# N-gram frequency counter: patterns that appear repeatedly across timeout
# inputs are promoted to _KNOWN_TIMEOUT_PATTERNS automatically.
_timeout_ngram_counts: _Counter = _Counter()
_TIMEOUT_NGRAM_SIZE = 4
_TIMEOUT_PATTERN_THRESHOLD = 3
_MAX_SKIP_PATTERNS = 64


def _write_bug_counts_csv(
    bug_type: str,
    exc_message: str,
    filename: str,
    *,
    exc_type: str = "",
    lineno: int | str = "",
) -> None:
    """Append one entry to logs/bug_counts.csv, matching the ipv4/ipv6 binary format."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    write_header = not BUG_COUNTS_CSV.exists()
    with open(BUG_COUNTS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        writer.writerow([bug_type, exc_type, exc_message, filename, lineno, 1])


JSON_TARGET_ROOT = ROOT / "json-decoder-main"
if str(JSON_TARGET_ROOT) not in sys.path:
    sys.path.insert(0, str(JSON_TARGET_ROOT))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fuzzer.bootstrap import load_seed_inputs
from fuzzer.format_loader import load_format
from fuzzer.mutation.tier2_semantic import get_mutator
from fuzzer.mutation.tier3_havoc import HavocMutator
from fuzzer.seed_generator import get_seed_generator

with atheris.instrument_imports(include=["buggy_json"]):
    from buggy_json import loads
    from buggy_json.decoder_stv import InvalidityBug, JSONDecodeError, PerformanceBug


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
SEED_BYTES = load_seed_inputs("json", FMT, allow_bootstrap=True) or [b"{}"]
GENERATED_SEED_BYTES = get_seed_generator("json", FMT).generate_corpus(64)
SEED_BYTES = list(dict.fromkeys([*SEED_BYTES, *GENERATED_SEED_BYTES]))

# DL weights file path (set by main.py via env var when DL is enabled)
_DL_WEIGHTS_PATH = os.environ.get("ATHERIS_DL_WEIGHTS")
_dl_weights_reload_counter = 0
_DL_WEIGHTS_RELOAD_EVERY = 500


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
    if random.random() < 0.12:
        current = random.choice(SEED_BYTES)
    if random.random() < 0.75:
        current = SEMANTIC_MUTATOR.mutate(current)

    havoc = HavocMutator(BASE_WEIGHTS)
    havoc_iters = max(2, min(12, len(current) // 8 + 2))
    current = havoc.mutate(current, iterations=havoc_iters)

    if not current:
        current = random.choice(SEED_BYTES)
    return _trim(current, max_size)


def _select_mode(data: bytes) -> str:
    """Choose a small set of decoder modes without exploding the search space."""
    if not data:
        return "default"
    selector = data[0] % 10
    if selector <= 5:
        return "default"
    if selector <= 7:
        return "strict_false"
    if selector == 8:
        return "string_numbers"
    return "pairs_hook"


def _candidate_loads(data: bytes, mode: str):
    if mode == "strict_false":
        return loads(data, strict=False)
    if mode == "string_numbers":
        return loads(data, parse_int=str, parse_float=str)
    if mode == "pairs_hook":
        return loads(data, object_pairs_hook=list)
    return loads(data)


def _safe_json_loads_with_mode(data: bytes, mode: str):
    try:
        if mode == "strict_false":
            return True, json.loads(data, strict=False), None
        if mode == "string_numbers":
            return True, json.loads(data, parse_int=str, parse_float=str), None
        if mode == "pairs_hook":
            return True, json.loads(data, object_pairs_hook=list), None
        return True, json.loads(data), None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
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


def _traceback_site(exc: BaseException) -> tuple[str, int]:
    """Return the deepest traceback location for CSV logging and dedup."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return "", 0
    last_frame = frames[-1]
    return last_frame.filename, last_frame.lineno


def _record_oracle_mismatch(
    data: bytes,
    bug_type: str,
    exc_message: str,
    *,
    exc_type: str = "",
    source_filename: str | None = None,
    source_lineno: int | str = "",
) -> None:
    """Write a unique oracle mismatch and save a reproducer without stopping fuzzing."""
    digest = hashlib.sha1(data).hexdigest()
    if digest not in _seen_crash_hashes:
        _seen_crash_hashes.add(digest)
        CRASHES_DIR.mkdir(parents=True, exist_ok=True)
        artifact_path = CRASHES_DIR / f"{bug_type}-{digest}"
        artifact_path.write_bytes(data)
        _write_bug_counts_csv(
            bug_type,
            exc_message,
            source_filename or artifact_path.name,
            exc_type=exc_type,
            lineno=source_lineno,
        )


def _learn_timeout_patterns(data: bytes) -> None:
    """Promote frequent n-grams from real performance reproducers."""
    ngrams = {
        data[i:i + _TIMEOUT_NGRAM_SIZE]
        for i in range(len(data) - _TIMEOUT_NGRAM_SIZE + 1)
    }
    for ng in ngrams:
        _timeout_ngram_counts[ng] += 1
        if (
            _timeout_ngram_counts[ng] >= _TIMEOUT_PATTERN_THRESHOLD
            and ng not in _KNOWN_TIMEOUT_PATTERNS
            and len(_KNOWN_TIMEOUT_PATTERNS) < _MAX_SKIP_PATTERNS
        ):
            _KNOWN_TIMEOUT_PATTERNS.append(ng)


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    # Skip repeated variants only after we have already saved reproducer
    # inputs for the known slow-path bug.
    for pattern in _KNOWN_TIMEOUT_PATTERNS:
        if pattern in data:
            return

    mode = _select_mode(data)
    ref_ok, ref_value, ref_exc = _safe_json_loads_with_mode(data, mode)

    # Give the seeded slow path enough time to raise PerformanceBug before
    # libFuzzer's outer timeout fires, while still bounding true hangs.
    signal.signal(signal.SIGALRM, _sigalrm_handler)
    signal.alarm(_INTERNAL_TIMEOUT_SECS)
    try:
        candidate_value = _candidate_loads(data, mode)
    except TimeoutError:
        digest = hashlib.sha1(data).hexdigest()
        if digest not in _seen_crash_hashes:
            _seen_crash_hashes.add(digest)
            CRASHES_DIR.mkdir(parents=True, exist_ok=True)
            crash_path = CRASHES_DIR / f"timeout-{digest}"
            crash_path.write_bytes(data)
            _write_bug_counts_csv("TIMEOUT", "Buggy JSON decoder timed out", f"timeout-{digest}")

        return  # return cleanly so libFuzzer keeps running
    except PerformanceBug as exc:
        filename, lineno = _traceback_site(exc)
        _record_oracle_mismatch(
            data,
            "performance_bug",
            str(exc),
            exc_type=type(exc).__name__,
            source_filename=filename,
            source_lineno=lineno,
        )
        _learn_timeout_patterns(data)
        return
    except (JSONDecodeError, InvalidityBug, UnicodeDecodeError, ValueError, RecursionError) as exc:
        filename, lineno = _traceback_site(exc)
        if ref_ok:
            _record_oracle_mismatch(
                data,
                "validity",
                str(exc),
                exc_type=type(exc).__name__,
                source_filename=filename,
                source_lineno=lineno,
            )
            return
        # Both rejected, but InvalidityBug means buggy_json used the wrong
        # exception type instead of the expected JSONDecodeError.
        if isinstance(exc, InvalidityBug):
            _record_oracle_mismatch(
                data,
                "wrong_exception_type",
                str(exc),
                exc_type=type(exc).__name__,
                source_filename=filename,
                source_lineno=lineno,
            )
            return
        # Record one invalidity per distinct parser rejection site so the CSV
        # mirrors direct-run traceback ownership more closely.
        if isinstance(exc, JSONDecodeError):
            msg = getattr(exc, "msg", str(exc).split(":")[0])
            dedup_key = (msg, filename, lineno)
            if dedup_key not in _seen_invalidity_sites:
                _seen_invalidity_sites.add(dedup_key)
                _record_oracle_mismatch(
                    data,
                    "invalidity",
                    str(exc),
                    exc_type=type(exc).__name__,
                    source_filename=filename,
                    source_lineno=lineno,
                )
        return
    finally:
        signal.alarm(0)

    if not ref_ok:
        ref_exc_type = type(ref_exc).__name__ if ref_exc is not None else ""
        _record_oracle_mismatch(data, "oracle_mismatch", str(ref_exc), exc_type=ref_exc_type)
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
