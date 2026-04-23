"""
Directed probe for the repo-local cidrize behavior in the extracted payload.

This script exercises a small set of handpicked cidrize strings against the
source override under ``win-cidrize-runner.exe_extracted/PYZ.pyz_extracted`` so
we can confirm which deterministic bug paths are reachable without relying on
the mutational fuzzer schedule.

Usage:
  python evaluation/cidrize_bug_path_probe.py
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACTED_DIR = REPO_ROOT / "win-cidrize-runner.exe_extracted"
PYZ_DIR = EXTRACTED_DIR / "PYZ.pyz_extracted"


def _load_cidrize():
    if not PYZ_DIR.exists():
        raise FileNotFoundError(
            f"Expected extracted cidrize payload at {PYZ_DIR}. "
            "Extract the runner bundle first."
        )
    if str(EXTRACTED_DIR) not in sys.path:
        sys.path.insert(0, str(EXTRACTED_DIR))
    if str(PYZ_DIR) not in sys.path:
        sys.path.insert(0, str(PYZ_DIR))

    from buggy_cidrize.cidrize_stv import cidrize  # type: ignore

    return cidrize


CASES = [
    {
        "label": "performance_whole_ipv4_space",
        "input": "0.0.0.0/0",
        "expected": "PerformanceBug",
        "note": "whole-space IPv4 CIDR should hit the known slow-path bug",
    },
    {
        "label": "pass_whole_ipv6_space",
        "input": "::/0",
        "expected": "PASS",
        "note": "whole-space IPv6 CIDR should parse cleanly in the current build",
    },
    {
        "label": "pass_plain_ipv4",
        "input": "1.2.3.4",
        "expected": "PASS",
        "note": "ordinary IPv4 address should parse",
    },
    {
        "label": "functional_two_digit_bracket",
        "input": "192.0.2.[56]",
        "expected": "FunctionalBug",
        "note": "two-digit bracket form should hit the dedicated functional bug",
    },
    {
        "label": "reliability_comma_space",
        "input": "192.0.2.33, 192.0.2.34",
        "expected": "ReliabilityBug",
        "note": "comma-plus-space list should hit the whitespace reliability bug",
    },
]


def main() -> int:
    cidrize = _load_cidrize()
    print("label\tinput\texpected\tobserved\tstatus\tnote")
    failures = 0

    for case in CASES:
        observed = "PASS"
        try:
            cidrize(case["input"], raise_errors=True)
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
