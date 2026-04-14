"""Focused regression checks for bootstrap profiles and generic unknown-format support.

Run with:
    python evaluation/bootstrap_checks.py
"""

from __future__ import annotations

import random
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from fuzzer.bootstrap import (
    build_manual_bootstrap_profile,
    decode_bootstrap_seed_examples,
    load_bootstrap_profile,
    load_seed_inputs,
    save_bootstrap_profile,
)
from fuzzer.mutation.tier2_semantic import GenericSemanticMutator


def _run_manual_pdf_profile_checks() -> None:
    profile = build_manual_bootstrap_profile("pdf", {}, examples_limit=6)
    assert profile["format_kind"] == "container", profile
    assert profile["seed_encoding"] == "base64", profile
    assert profile["source"] == "manual", profile
    decoded = decode_bootstrap_seed_examples(profile)
    assert decoded, profile
    assert decoded[0].startswith(b"%PDF-"), decoded[0][:8]


def _run_cached_profile_loading_checks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "config").mkdir()
        profile = build_manual_bootstrap_profile("pdf", {}, examples_limit=4)
        save_bootstrap_profile("pdf", profile, project_root=root)
        loaded = load_bootstrap_profile("pdf", project_root=root)
        assert loaded["format_kind"] == "container", loaded
        seeds = load_seed_inputs("pdf", loaded, allow_bootstrap=True, project_root=root)
        assert seeds and seeds[0].startswith(b"%PDF-"), seeds


def _run_corpus_precedence_checks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "config").mkdir()
        seed_dir = root / "corpus" / "demo_seeds"
        seed_dir.mkdir(parents=True)
        (seed_dir / "seed1.bin").write_bytes(b"from-corpus")

        profile = build_manual_bootstrap_profile("demo", {"valid_examples": ["from-bootstrap"]}, examples_limit=2)
        save_bootstrap_profile("demo", profile, project_root=root)

        seeds = load_seed_inputs("demo", {"valid_examples": ["from-config"]}, allow_bootstrap=True, project_root=root)
        assert seeds == [b"from-corpus"], seeds


def _run_binary_mutator_checks() -> None:
    data = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 12 >>\nstream\nhello world!\nendstream\nendobj\n%%EOF\n"
    )
    mutator = GenericSemanticMutator(
        fmt_config={
            "format_kind": "container",
            "token_hints": {
                "magic_bytes": ["%PDF-"],
                "section_markers": ["obj", "endobj", "stream", "endstream", "%%EOF"],
                "length_fields": ["Length"],
                "delimiters": ["/", "<<", ">>"],
            },
            "mutation_hints": {
                "prefer_operations": ["length_field_stress", "marker_duplicate", "chunk_truncate"],
                "avoid_operations": [],
                "preserve_magic_bytes": True,
                "avoid_magic_prefix_damage": True,
            },
        }
    )
    random.seed(7)
    mutated = mutator.mutate(data)
    trace = mutator.consume_last_trace()
    assert mutated != data, (mutated, trace)
    assert isinstance(mutated, bytes), type(mutated)
    assert trace.get("applied") is True, trace


def main() -> None:
    _run_manual_pdf_profile_checks()
    _run_cached_profile_loading_checks()
    _run_corpus_precedence_checks()
    _run_binary_mutator_checks()
    print("bootstrap checks passed")


if __name__ == "__main__":
    main()
