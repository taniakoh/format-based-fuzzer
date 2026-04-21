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

import fuzzer.executor as executor_mod
from fuzzer.coverage import CoverageAnalyzer
from fuzzer.executor import (
    BITMAP_SIZE,
    BugType,
    Executor,
    RunResult,
    _edge_slots_to_bitmap,
    _result_to_bitmap,
)
from fuzzer.oracle import evaluate_target_input


def _run_json_decoder_depth_checks() -> None:
    json_root = _HERE / "json-decoder-main"
    if str(json_root) not in sys.path:
        sys.path.insert(0, str(json_root))

    from buggy_json import loads as buggy_json_loads
    from buggy_json.decoder_stv import JSONDecodeError

    nested_array = "[" * 700 + "0" + "]" * 700
    try:
        buggy_json_loads(nested_array)
    except JSONDecodeError as exc:
        assert "Maximum nesting depth exceeded" in str(exc), exc
    else:
        raise AssertionError("buggy_json should reject excessively nested arrays")


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
    _assert_verdict("cidrize", "192.0.2.170--175", supported=True, expected_valid=False, shape="ipv4_range")
    _assert_verdict("cidrize", "192.0.2.64/24/25", supported=True, expected_valid=False, shape="network")
    _assert_verdict("cidrize", "192.0.2.**", supported=True, expected_valid=False, shape="plain_address")
    _assert_verdict("cidrize", "192.0.2.-192.0.2.85", supported=True, expected_valid=False, shape="ipv4_range")
    _assert_verdict("cidrize", "192.0.2.0 255.255.255.0", supported=True, expected_valid=False, shape="plain_address")
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
    assert result.oracle is not None, result

    accepted_invalid = RunResult(
        input_str="192.0.2.85-192.0.2.80",
        bug_type=BugType.PASS,
        exit_code=0,
        stdout="",
        stderr="",
    )
    result = Executor._apply_oracle(stub, accepted_invalid)
    assert result.bug_type == BugType.ORACLE_MISMATCH, result
    assert result.oracle is not None, result

    reported_functional = RunResult(
        input_str="hostname",
        bug_type=BugType.PASS,
        exit_code=0,
        stdout="",
        stderr="",
        parser_reported_bug_type=BugType.FUNCTIONAL,
        parser_reported_message="accepted malformed mixed-family input",
    )
    result = Executor._apply_oracle(stub, reported_functional)
    assert result.bug_type == BugType.FUNCTIONAL, result
    assert result.exception_msg == "accepted malformed mixed-family input", result
    assert result.oracle is not None, result

    traced_bonus = RunResult(
        input_str="2001:db8:::1",
        bug_type=BugType.PASS,
        exit_code=0,
        stdout="",
        stderr="",
        exception_msg="ReliabilityBug: malformed compression",
        traceback="Traceback\nReliabilityBug: malformed compression",
    )
    result = Executor._apply_oracle(stub, traced_bonus)
    assert result.bug_type == BugType.BONUS, result
    assert result.oracle is not None, result

    parser_invalidity_on_valid = RunResult(
        input_str="::",
        bug_type=BugType.PASS,
        exit_code=1,
        stdout="",
        stderr="",
        parser_reported_bug_type=BugType.INVALIDITY,
        parser_reported_message="rejected all-zero shorthand",
    )
    result = Executor._apply_oracle(stub, parser_invalidity_on_valid)
    assert result.bug_type == BugType.VALIDITY, result
    assert result.oracle is not None, result

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


def _run_frida_coverage_checks() -> None:
    coverage = CoverageAnalyzer(use_afl_hit_count_buckets=True)

    first_hit = bytearray(BITMAP_SIZE)
    first_hit[7] = 1
    first_obs = coverage.observe(bytes(first_hit))
    assert first_obs["is_interesting"] is True
    assert first_obs["rarity_score"] > 0.0
    assert coverage.edge_count == 1

    same_bucket = bytearray(BITMAP_SIZE)
    same_bucket[7] = 1
    same_obs = coverage.observe(bytes(same_bucket))
    assert same_obs["is_interesting"] is False
    assert same_obs["rarity_score"] < first_obs["rarity_score"]
    assert coverage.edge_count == 1

    new_count_bucket = bytearray(BITMAP_SIZE)
    new_count_bucket[7] = 3
    bucket_obs = coverage.observe(bytes(new_count_bucket))
    assert bucket_obs["is_interesting"] is True
    assert coverage.edge_count == 2

    new_edge = bytearray(BITMAP_SIZE)
    new_edge[9] = 1
    edge_obs = coverage.observe(bytes(new_edge))
    assert edge_obs["is_interesting"] is True
    assert edge_obs["new_slots"] == 1
    assert coverage.edge_count == 3

    bitmap = _edge_slots_to_bitmap([0x1000, 0x1000, 0x2000])
    assert bitmap.count(0) < len(bitmap), "expected hashed block coverage"


def _run_frida_agent_flush_checks() -> None:
    source = executor_mod._frida_agent_source(Path("/tmp/linux-ipv4-parser"))
    assert "Stalker.flush();" in source, "agent should force pending stalker events out of Frida buffers"
    assert "rpc.exports.dispose" in source, "agent should flush buffered edges during teardown"
    assert 'trigger: "dispose"' in source, "teardown flush should be observable in debug logs"
    assert "DebugSymbol.fromAddress" in source, "agent should prefer symbolicated file/line coverage when available"
    assert "fallbackEdgeSlot" in source, "agent should keep block-hash coverage as a fallback when symbolication is absent"


def _run_frida_mode_selection_checks() -> None:
    original_frida = executor_mod._FRIDA_MODULE
    original_linux = executor_mod._LINUX_BINARIES.get("ipv4")
    original_is_linux = executor_mod._IS_LINUX
    try:
        executor_mod._FRIDA_MODULE = object()
        executor_mod._IS_LINUX = True
        executor_mod._LINUX_BINARIES["ipv4"] = _HERE / "evaluation" / "oracle_checks.py"
        executor = Executor("ipv4")
        assert executor.mode == "Frida", executor.mode
        assert executor.binary == Path(sys.executable), executor.binary
    finally:
        executor_mod._FRIDA_MODULE = original_frida
        executor_mod._IS_LINUX = original_is_linux
        if original_linux is not None:
            executor_mod._LINUX_BINARIES["ipv4"] = original_linux


def _run_missing_frida_checks() -> None:
    original_frida = executor_mod._FRIDA_MODULE
    original_linux = executor_mod._LINUX_BINARIES.get("ipv4")
    original_is_linux = executor_mod._IS_LINUX
    try:
        executor_mod._FRIDA_MODULE = None
        executor_mod._IS_LINUX = True
        executor_mod._LINUX_BINARIES["ipv4"] = _HERE / "evaluation" / "oracle_checks.py"

        import builtins

        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "frida":
                raise ImportError("missing frida")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = fake_import
        try:
            try:
                Executor("ipv4")
            except RuntimeError as exc:
                assert "pip install frida frida-tools" in str(exc), exc
            else:
                raise AssertionError("Executor() should fail when Frida is missing")
        finally:
            builtins.__import__ = original_import
    finally:
        executor_mod._FRIDA_MODULE = original_frida
        executor_mod._IS_LINUX = original_is_linux
        if original_linux is not None:
            executor_mod._LINUX_BINARIES["ipv4"] = original_linux


def main() -> None:
    _run_json_decoder_depth_checks()
    _run_oracle_shape_checks()
    _run_family_variation_checks()
    _run_executor_integration_checks()
    _run_frida_coverage_checks()
    _run_frida_agent_flush_checks()
    _run_frida_mode_selection_checks()
    _run_missing_frida_checks()
    print("oracle checks passed")


if __name__ == "__main__":
    main()
