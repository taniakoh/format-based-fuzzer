"""Atheris harness for the bundled JSON decoder target."""

from __future__ import annotations

import os
import random
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


def _trim(mutated: bytes, max_size: int) -> bytes:
    if max_size <= 0 or len(mutated) <= max_size:
        return mutated
    return mutated[:max_size]


def custom_mutator(data: bytes, max_size: int, seed: int) -> bytes:
    """Bias libFuzzer mutations toward valid-ish JSON fragments."""
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


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    try:
        loads(data)
    except (JSONDecodeError, InvalidityBug, UnicodeDecodeError, ValueError):
        return


def main() -> None:
    os.chdir(ROOT)
    atheris.Setup(sys.argv, test_one_input, custom_mutator=custom_mutator)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
