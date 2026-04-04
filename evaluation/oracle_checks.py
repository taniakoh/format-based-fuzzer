"""Focused regression checks for the structured oracle.

Run with:
    python evaluation/oracle_checks.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from fuzzer.executor import BugType, Executor, RunResult, _result_to_bitmap
from fuzzer.oracle import evaluate_target_input


def _assert_verdict(
    target: str,
    value: str,
    *,
    supported: bool,
    expected_valid: bool | None,
    shape: str,
) -> None:
    verdict = evaluate_target_input(target, value)
    assert verdict.supported is supported, (target, value, verdict)
    assert verdict.expected_valid is expected_valid, (target, value, verdict)
    assert verdict.shape == shape, (target, value, verdict)


def _run_oracle_shape_checks() -> None:
    _assert_verdict("ipv4", "001.002.003.004", supported=True, expected_valid=True, shape="plain_ipv4")
    _assert_verdict("ipv4", "999.0.0.1", supported=True, expected_valid=False, shape="plain_ipv4")
    _assert_verdict("ipv6", "::ffff:192.0.2.33", supported=True, expected_valid=True, shape="plain_ipv6")
    _assert_verdict("ipv6", "2001:db8:::1", supported=True, expected_valid=False, shape="plain_ipv6")

    _assert_verdict("cidrize", "1.2.3.4", supported=True, expected_valid=True, shape="plain_ipv4")
    _assert_verdict("cidrize", "2001:db8::/64", supported=True, expected_valid=True, shape="network")
    _assert_verdict("cidrize", "192.0.2.64/33", supported=True, expected_valid=False, shape="network")
    _assert_verdict("cidrize", "192.0.2.80-192.0.2.85", supported=True, expected_valid=True, shape="ipv4_range")
    _assert_verdict("cidrize", "192.0.2.85-192.0.2.80", supported=True, expected_valid=False, shape="ipv4_range")
    _assert_verdict("cidrize", "192.0.2.170-175", supported=True, expected_valid=True, shape="ipv4_partial_range")
    _assert_verdict("cidrize", "192.0.2.170-999", supported=True, expected_valid=False, shape="ipv4_partial_range")
    _assert_verdict("cidrize", "192.0.2.[5678]", supported=True, expected_valid=True, shape="ipv4_wildcard_set")
    _assert_verdict("cidrize", "192.0.2.8[0-5]", supported=True, expected_valid=True, shape="ipv4_wildcard_range")
    _assert_verdict("cidrize", "192.0.2.[5-0]", supported=True, expected_valid=False, shape="ipv4_wildcard_range")
    _assert_verdict("cidrize", "192.0.2.[5-]", supported=True, expected_valid=False, shape="malformed")
    _assert_verdict("cidrize", "hostname", supported=False, expected_valid=None, shape="unsupported")


def _run_family_variation_checks() -> None:
    for base in ("10.0.0", "192.0.2", "255.255.255"):
        for digit_set in ("0123", "5678", "89"):
            verdict = evaluate_target_input("cidrize", f"{base}.[{digit_set}]")
            assert verdict.supported is True, verdict
            assert verdict.expected_valid is True, verdict
            assert verdict.shape == "ipv4_wildcard_set", verdict

        for low, high in (("0", "5"), ("10", "25"), ("100", "155")):
            verdict = evaluate_target_input("cidrize", f"{base}.[{low}-{high}]")
            assert verdict.supported is True, verdict
            assert verdict.shape == "ipv4_wildcard_range", verdict

    for prefix in ("0", "8", "24", "32"):
        verdict = evaluate_target_input("cidrize", f"192.0.2.0/{prefix}")
        assert verdict.supported is True, verdict
        assert verdict.expected_valid is True, verdict
        assert verdict.shape == "network", verdict

    for prefix in ("33", "129", "999"):
        verdict = evaluate_target_input("cidrize", f"192.0.2.0/{prefix}")
        assert verdict.supported is True, verdict
        assert verdict.expected_valid is False, verdict
        assert verdict.shape == "network", verdict


def _run_executor_integration_checks() -> None:
    stub = object.__new__(Executor)
    stub.target = "cidrize"

    rejected_valid = RunResult(
        input_str="1.2.3.4",
        bug_type=BugType.PASS,
        exit_code=1,
        stdout="",
        stderr="",
        exception_msg="ParseException: no",
        traceback="Traceback\nParseException: no",
    )
    result = Executor._apply_oracle(stub, rejected_valid)
    assert result.bug_type == BugType.VALIDITY, result

    accepted_invalid = RunResult(
        input_str="192.0.2.85-192.0.2.80",
        bug_type=BugType.PASS,
        exit_code=0,
        stdout="",
        stderr="",
    )
    result = Executor._apply_oracle(stub, accepted_invalid)
    assert result.bug_type == BugType.ORACLE_MISMATCH, result

    stub_unknown = object.__new__(Executor)
    stub_unknown.target = "mystery"
    unknown = RunResult(
        input_str="hostname",
        bug_type=BugType.PASS,
        exit_code=0,
        stdout="",
        stderr="",
    )
    result = Executor._apply_oracle(stub_unknown, unknown)
    assert result.bug_type == BugType.ORACLE_UNKNOWN_ACCEPT, result

    timeout_bitmap = _result_to_bitmap(
        RunResult(
            input_str="x",
            bug_type=BugType.TIMEOUT,
            exit_code=None,
            stdout="",
            stderr="",
            exception_msg="Process timed out",
        )
    )
    assert any(timeout_bitmap)


def main() -> None:
    _run_oracle_shape_checks()
    _run_family_variation_checks()
    _run_executor_integration_checks()
    print("oracle checks passed")


if __name__ == "__main__":
    main()
