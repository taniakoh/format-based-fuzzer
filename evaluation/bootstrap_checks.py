"""Focused regression checks for bootstrap profiles and generic unknown-format support.

Run with:
    python evaluation/bootstrap_checks.py
"""

from __future__ import annotations

import json
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
from fuzzer.mutation.tier2_semantic import GenericSemanticMutator, IPv6SemanticMutator, get_mutator
from fuzzer.seed_generator import get_seed_generator


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


def _run_ipv6_seed_and_mutator_checks() -> None:
    generator = get_seed_generator("ipv6")
    seeds = [seed.decode("latin-1") for seed in generator.generate_corpus(80)]
    assert "None" in seeds, seeds[:20]
    assert "::" in seeds, seeds[:10]
    assert "::1" in seeds, seeds[:10]
    assert any(seed.endswith("::") for seed in seeds), seeds[:20]
    assert any("." in seed and ":" in seed for seed in seeds), seeds[:20]
    assert "::ffff:192.168.0.1" in seeds, seeds[:20]
    assert "1:2:3:4:5:6:7::8" in seeds, seeds[:20]
    assert any(":::" in seed and seed.count(":") >= 8 for seed in seeds), seeds[:30]

    ipv6_config = json.loads((_HERE / "config" / "ipv6_format.json").read_text(encoding="utf-8"))
    configured_ops = set(ipv6_config.get("semantic_rules", []))
    expected_ops = {
        "replace_with_valid_example",
        "embedded_ipv4_boundary",
        "triple_colon",
        "triple_colon_full_width",
        "compressed_overflow",
        "dangling_compression_tail",
        "invalid_mixed_suffix",
        "whitespace_injection",
    }
    missing_ops = expected_ops - configured_ops
    assert not missing_ops, f"ipv6 semantic_rules missing directed ops: {sorted(missing_ops)}"

    mutator = IPv6SemanticMutator(operations=["compressed_valid_form"])

    random.seed(11)
    compressed = mutator.mutate(b"2001:db8:1:2:3:4:5:6")
    compressed_text = compressed.decode("latin-1")
    compressed_trace = mutator.consume_last_trace()
    assert "::" in compressed_text, compressed_text
    assert compressed_trace.get("operation") == "compressed_valid_form", compressed_trace

    mutator = IPv6SemanticMutator(operations=["embedded_ipv4_valid_form"])
    random.seed(17)
    embedded = mutator.mutate(b"2001:db8::1")
    embedded_text = embedded.decode("latin-1")
    embedded_trace = mutator.consume_last_trace()
    assert "." in embedded_text and ":" in embedded_text, embedded_text
    assert embedded_trace.get("operation") == "embedded_ipv4_valid_form", embedded_trace

    mutator = IPv6SemanticMutator(operations=["triple_colon_full_width"])
    random.seed(23)
    triple = mutator.mutate(b"2001:db8:1:2:3:4:5:6")
    triple_text = triple.decode("latin-1")
    triple_trace = mutator.consume_last_trace()
    assert ":::" in triple_text, triple_text
    assert triple_text.count(":") >= 8, triple_text
    assert triple_trace.get("operation") == "triple_colon_full_width", triple_trace


def _run_json_seed_and_mutator_checks() -> None:
    generator = get_seed_generator("json")
    seeds = generator.generate_corpus(64)
    assert b"null" in seeds or b'{"key":null}' in seeds or b"[null]" in seeds, seeds[:12]
    assert b"None" in seeds, seeds[:12]
    assert any(b'"\\t"' in seed or b'"\\b"' in seed or b'"\\f"' in seed for seed in seeds), seeds[:12]
    assert any(b"\\u12345" in seed or b"\\uABCDE" in seed for seed in seeds), seeds[:12]
    assert any(seed.isdigit() and len(seed) > 4300 for seed in seeds), len(max(seeds, key=len))
    assert any(seed.count(b"[") >= 64 and seed.count(b"]") >= 64 for seed in seeds), seeds[:12]

    mutator = get_mutator("json", {"semantic_rules": ["escape_injection"]})
    random.seed(19)
    escaped = mutator.mutate(b'"x"')
    escaped_trace = mutator.consume_last_trace()
    assert any(token in escaped for token in (b"\\t", b"\\b", b"\\f", b"\\u0000")), escaped
    assert escaped_trace.get("operation") == "escape_injection", escaped_trace

    mutator = get_mutator("json", {"semantic_rules": ["unicode_escape_damage"]})
    random.seed(23)
    damaged = mutator.mutate(b'"x"')
    damaged_trace = mutator.consume_last_trace()
    assert b"\\u" in damaged, damaged
    assert damaged_trace.get("operation") == "unicode_escape_damage", damaged_trace

    mutator = get_mutator("json", {"semantic_rules": ["nesting_wrap"]})
    random.seed(29)
    nested = mutator.mutate(b"0")
    nested_trace = mutator.consume_last_trace()
    assert nested.count(b"[") >= 8 or nested.count(b"{") >= 8, nested[:64]
    assert nested_trace.get("operation") == "nesting_wrap", nested_trace

    mutator = get_mutator("json", {"semantic_rules": ["number_stress"]})
    random.seed(31)
    stressed = mutator.mutate(b"0")
    stressed_trace = mutator.consume_last_trace()
    assert len(stressed) > 4300, len(stressed)
    assert stressed_trace.get("operation") == "number_stress", stressed_trace


def _run_cidrize_seed_and_mutator_checks() -> None:
    generator = get_seed_generator("cidrize")
    seeds = [seed.decode("latin-1") for seed in generator.generate_corpus(96)]
    assert any(seed in {"0.0.0.0/0", "::", "::/0"} for seed in seeds), seeds[:24]
    assert any("," in seed for seed in seeds), seeds[:24]
    assert any(", " in seed or ",\t" in seed or ",\n" in seed for seed in seeds), seeds[:24]
    assert any(seed.endswith(".ai") or seed.endswith(".museum") or ".museum" in seed for seed in seeds), seeds[:24]
    assert any(
        "." in seed and len(seed.rsplit(".", 1)[1].strip()) in {1, 2, 5, 6, 7}
        for seed in seeds
    ), seeds[:24]

    cidrize_config = json.loads((_HERE / "config" / "cidrize_format.json").read_text(encoding="utf-8"))
    configured_ops = set(cidrize_config.get("semantic_rules", []))
    expected_ops = {
        "scope_alias",
        "hostname_tld_edge",
        "list_separator_variation",
        "separator_repeat",
        "stacked_prefix",
        "wildcard_repeat",
        "adjacent_mask",
    }
    missing_ops = expected_ops - configured_ops
    assert not missing_ops, f"cidrize semantic_rules missing directed ops: {sorted(missing_ops)}"

    mutator = get_mutator("cidrize", {"semantic_rules": ["scope_alias"]})
    random.seed(59)
    aliased = mutator.mutate(b"192.0.2.33")
    aliased_text = aliased.decode("latin-1")
    aliased_trace = mutator.consume_last_trace()
    assert aliased_text in {"0.0.0.0/0", "::", "::/0"}, aliased_text
    assert aliased_trace.get("operation") == "scope_alias", aliased_trace

    mutator = get_mutator("cidrize", {"semantic_rules": ["list_separator_variation"]})
    random.seed(61)
    listed = mutator.mutate(b"192.0.2.33")
    listed_text = listed.decode("latin-1")
    listed_trace = mutator.consume_last_trace()
    assert "," in listed_text, listed_text
    assert listed_trace.get("operation") == "list_separator_variation", listed_trace

    mutator = get_mutator("cidrize", {"semantic_rules": ["hostname_tld_edge"]})
    random.seed(67)
    host = mutator.mutate(b"svc.example.dev")
    host_text = host.decode("latin-1")
    host_trace = mutator.consume_last_trace()
    assert "." in host_text, host_text
    assert host_trace.get("operation") == "hostname_tld_edge", host_trace


def _run_xml_bootstrap_and_mutator_checks() -> None:
    # Verify the saved xml_bootstrap.json loads and decodes correctly.
    profile = load_bootstrap_profile("xml")
    assert profile, "xml_bootstrap.json missing or empty"
    assert profile.get("source") == "llm_bootstrap", profile.get("source")
    assert profile.get("format_kind") == "text", profile.get("format_kind")
    assert profile.get("seed_encoding") == "utf-8", profile.get("seed_encoding")

    seeds = decode_bootstrap_seed_examples(profile)
    assert seeds, "no seeds decoded from xml bootstrap profile"
    valid_seeds = [s.decode("utf-8") for s in seeds if s.startswith(b"<")]
    assert valid_seeds, "no XML-looking seeds in bootstrap profile"
    assert any("<root" in s for s in valid_seeds), valid_seeds[:5]

    # bootstrap invalid examples should include known-malformed shapes
    invalid_raw = profile.get("seed_examples_invalid", [])
    assert invalid_raw, "xml_bootstrap.json has no invalid examples"
    invalid_texts = [e if isinstance(e, str) else "" for e in invalid_raw]
    assert any("<root>" in s for s in invalid_texts), invalid_texts[:5]

    # load_seed_inputs: corpus/xml_seeds.txt exists, so it should take precedence
    corpus_seeds = load_seed_inputs("xml", profile, allow_bootstrap=True)
    assert corpus_seeds, "load_seed_inputs returned nothing for xml"
    assert all(isinstance(s, bytes) for s in corpus_seeds), corpus_seeds[:3]
    assert any(b"<root" in s for s in corpus_seeds), corpus_seeds[:5]
    assert any(s in {b"None", b"<null/>"} or b'xsi:nil="true"' in s for s in corpus_seeds), corpus_seeds[:8]

    # Verify the XML semantic mutator runs without error on a valid seed.
    mutator = get_mutator("xml", {"semantic_rules": ["tag_rename"]})
    random.seed(37)
    result = mutator.mutate(b"<root><child>text</child></root>")
    trace = mutator.consume_last_trace()
    assert isinstance(result, bytes), type(result)
    assert trace.get("operation") == "tag_rename", trace

    # close_tag_mismatch should produce a structurally broken input.
    mutator = get_mutator("xml", {"semantic_rules": ["close_tag_mismatch"]})
    random.seed(41)
    mismatched = mutator.mutate(b"<root><child>text</child></root>")
    mismatch_trace = mutator.consume_last_trace()
    assert isinstance(mismatched, bytes), type(mismatched)
    assert mismatch_trace.get("operation") == "close_tag_mismatch", mismatch_trace

    # attribute_inject should add an attribute.
    mutator = get_mutator("xml", {"semantic_rules": ["attribute_inject"]})
    random.seed(53)
    injected = mutator.mutate(b"<root/>")
    inject_trace = mutator.consume_last_trace()
    assert isinstance(injected, bytes), type(injected)
    assert inject_trace.get("operation") == "attribute_inject", inject_trace


def main() -> None:
    _run_manual_pdf_profile_checks()
    _run_cached_profile_loading_checks()
    _run_corpus_precedence_checks()
    _run_binary_mutator_checks()
    _run_ipv6_seed_and_mutator_checks()
    _run_json_seed_and_mutator_checks()
    _run_cidrize_seed_and_mutator_checks()
    _run_xml_bootstrap_and_mutator_checks()
    print("bootstrap checks passed")


if __name__ == "__main__":
    main()
