"""Atheris harness for the XML target using stdlib parsers."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import sys
from pathlib import Path
from xml.dom import Node
from xml.dom import minidom
from xml.etree import ElementTree as ET
from xml.parsers.expat import ExpatError

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
        "Atheris does not document Windows support. Run the XML target in "
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
CRASHES_DIR = ROOT / "results" / "xml" / "crashes"
LOGS_DIR = ROOT / "results" / "xml" / "logs"
BUG_COUNTS_CSV = LOGS_DIR / "bug_counts.csv"

_seen_artifacts: set[str] = set()
_DL_WEIGHTS_PATH = os.environ.get("ATHERIS_DL_WEIGHTS")
_dl_weights_reload_counter = 0
_DL_WEIGHTS_RELOAD_EVERY = 500

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fuzzer.bootstrap import load_seed_inputs
from fuzzer.format_loader import load_format
from fuzzer.mutation.tier2_semantic import get_mutator
from fuzzer.mutation.tier3_havoc import HavocMutator


FMT = load_format("xml")
SEMANTIC_MUTATOR = get_mutator("xml", FMT)
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
SEED_BYTES = load_seed_inputs("xml", FMT, allow_bootstrap=True) or [b"<root/>"]


def _maybe_reload_dl_weights() -> None:
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
    """Bias libFuzzer mutations toward XML-like structure."""
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


def _write_bug_counts_csv(bug_type: str, exc_message: str, filename: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    write_header = not BUG_COUNTS_CSV.exists()
    with open(BUG_COUNTS_CSV, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        writer.writerow([bug_type, "", exc_message, filename, "", 1])


def _subset_supported(data: bytes) -> bool:
    lowered = data.lower()
    return b"<!doctype" not in lowered and b"<!entity" not in lowered


def _local_name(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag.split(":", 1)[-1]


def _elementtree_summary(root: ET.Element) -> tuple[str, int, int, tuple[str, ...]]:
    names = [_local_name(node.tag) for node in root.iter() if isinstance(node.tag, str)]
    attr_count = sum(len(node.attrib) for node in root.iter() if isinstance(node.tag, str))
    return _local_name(root.tag), len(names), attr_count, tuple(names[:32])


def _semantic_dom_attr_count(node: Node) -> int:
    attributes = getattr(node, "attributes", None)
    if not attributes:
        return 0
    count = 0
    for idx in range(attributes.length):
        attr = attributes.item(idx)
        if attr is None:
            continue
        attr_name = getattr(attr, "name", "") or ""
        if attr_name == "xmlns" or attr_name.startswith("xmlns:"):
            continue
        count += 1
    return count


def _minidom_summary(doc: minidom.Document) -> tuple[str, int, int, tuple[str, ...]]:
    names: list[str] = []
    attr_count = 0

    def walk(node: Node) -> None:
        nonlocal attr_count
        if node.nodeType == Node.ELEMENT_NODE:
            names.append(node.nodeName.split(":", 1)[-1])
            attr_count += _semantic_dom_attr_count(node)
        for child in getattr(node, "childNodes", []):
            walk(child)

    walk(doc.documentElement)
    root_name = names[0] if names else "unknown"
    return root_name, len(names), attr_count, tuple(names[:32])


def _safe_reference_parse(data: bytes):
    try:
        return True, ET.fromstring(data), None
    except (ET.ParseError, UnicodeDecodeError, ValueError) as exc:
        return False, None, exc


def _safe_candidate_parse(data: bytes):
    try:
        return True, minidom.parseString(data), None
    except (ExpatError, UnicodeDecodeError, ValueError) as exc:
        return False, None, exc


def _record_oracle_mismatch(data: bytes, bug_type: str, exc_message: str) -> None:
    digest = hashlib.sha1(data).hexdigest()
    if digest in _seen_artifacts:
        return
    _seen_artifacts.add(digest)
    CRASHES_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = CRASHES_DIR / f"{bug_type}-{digest}"
    artifact_path.write_bytes(data)
    _write_bug_counts_csv(bug_type, exc_message, artifact_path.name)


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    if not data or not _subset_supported(data):
        return

    ref_ok, ref_root, ref_exc = _safe_reference_parse(data)
    candidate_ok, candidate_doc, candidate_exc = _safe_candidate_parse(data)

    if ref_ok and not candidate_ok:
        _record_oracle_mismatch(
            data,
            "validity",
            f"ElementTree accepted, minidom rejected: {candidate_exc}",
        )
        return

    if not ref_ok and candidate_ok:
        _record_oracle_mismatch(
            data,
            "oracle_mismatch",
            f"ElementTree rejected, minidom accepted: {ref_exc}",
        )
        return

    if not ref_ok and not candidate_ok:
        return

    ref_summary = _elementtree_summary(ref_root)
    candidate_summary = _minidom_summary(candidate_doc)
    if ref_summary != candidate_summary:
        _record_oracle_mismatch(
            data,
            "oracle_mismatch",
            "ElementTree and minidom produced different structural summaries",
        )

    try:
        candidate_doc.unlink()
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input, custom_mutator=custom_mutator)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
