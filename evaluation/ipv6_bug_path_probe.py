"""
Directed probe for the repo-local IPv6 parser behavior in the extracted payload.

This script exercises a small set of handpicked IPv6 strings against the source
override under ``linux-ipv6-parser_extracted/PYZ.pyz_extracted`` so we can
confirm the fixed parser accepts valid IPv6 forms and turns malformed inputs
into ordinary parse failures instead of surfacing custom bug exceptions.

Usage:
  python evaluation/ipv6_bug_path_probe.py
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACTED_DIR = REPO_ROOT / "linux-ipv6-parser_extracted" / "PYZ.pyz_extracted"


def _load_parser():
    if not EXTRACTED_DIR.exists():
        raise FileNotFoundError(
            f"Expected extracted parser payload at {EXTRACTED_DIR}. "
            "Run pyinstxtractor against the Linux parser binary first."
        )
    sys.path.insert(0, str(EXTRACTED_DIR))
    from buggy_ipyparse.ipv6_mstv import IPv6  # type: ignore

    return IPv6


CASES = [
    {
        "label": "valid_all_zero_shorthand",
        "input": "::",
        "expected": "PASS",
        "note": "RFC-valid all-zero shorthand should parse",
    },
    {
        "label": "reject_overlong_hextet",
        "input": "12345::",
        "expected": "ParseException",
        "note": "five-digit hextet should be rejected as malformed",
    },
    {
        "label": "reject_too_many_hextets",
        "input": "1:2:3:4:5:6:7:8:9",
        "expected": "ParseException",
        "note": "too many hextets should be rejected",
    },
    {
        "label": "reject_triple_colon",
        "input": "1:::2",
        "expected": "ParseException",
        "note": "triple-colon form should not reach a custom reliability error",
    },
    {
        "label": "reject_multiple_compressions",
        "input": "1::2::3",
        "expected": "ParseException",
        "note": "multiple :: markers are invalid",
    },
    {
        "label": "reject_dangling_compressed_tail",
        "input": "2001:db8::1::",
        "expected": "ParseException",
        "note": "dangling compressed tail is invalid",
    },
    {
        "label": "reject_bad_ipv4_suffix",
        "input": "::ffff:192.0.2.999",
        "expected": "ParseException",
        "note": "embedded IPv4 suffix octets must stay in range",
    },
    {
        "label": "generic_parse_rejection",
        "input": "g::1",
        "expected": "ParseException",
        "note": "non-hex input should be rejected cleanly",
    },
    {
        "label": "valid_normal_address",
        "input": "2001:db8::1",
        "expected": "PASS",
        "note": "ordinary compressed IPv6 should parse",
    },
]


def main() -> int:
    parser = _load_parser()
    print("label\tinput\texpected\tobserved\tstatus\tnote")
    failures = 0

    for case in CASES:
        observed = "PASS"
        try:
            parser.parse_string(case["input"])
        except Exception as exc:  # noqa: BLE001
            observed = type(exc).__name__

        ok = observed == case["expected"]
        if not ok:
            failures += 1

        print(
            f"{case['label']}\t{case['input']}\t{case['expected']}\t"
            f"{observed}\t{'OK' if ok else 'MISMATCH'}\t{case['note']}"
        )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
