"""Lightweight expected-validity oracles for parser targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class OracleVerdict:
    supported: bool
    expected_valid: bool | None
    reason: str


_IPV4_OCTET_RE = re.compile(r"^[0-9]{1,3}$")
_CIDRIZE_WILDCARD_RE = re.compile(r"^(.+\.)\[(\d+)\]$")
_CIDRIZE_WILDCARD_RANGE_RE = re.compile(r"^(.+\.)(\d+)\[(\d+)-(\d+)\]$")


def evaluate_target_input(target: str, input_str: str) -> OracleVerdict:
    target_name = target.lower()
    if target_name == "ipv4":
        return _ipv4_oracle(input_str)
    if target_name == "ipv6":
        return _ipv6_oracle(input_str)
    if target_name == "cidrize":
        return _cidrize_oracle(input_str)
    return OracleVerdict(False, None, "no_oracle_for_target")


def _ipv4_oracle(value: str) -> OracleVerdict:
    parts = value.split(".")
    if len(parts) != 4:
        return OracleVerdict(True, False, "ipv4_requires_4_octets")

    for part in parts:
        if not _IPV4_OCTET_RE.fullmatch(part):
            return OracleVerdict(True, False, "ipv4_non_decimal_octet")
        octet = int(part, 10)
        if not 0 <= octet <= 255:
            return OracleVerdict(True, False, "ipv4_octet_out_of_range")

    return OracleVerdict(True, True, "ipv4_valid")


def _ipv6_oracle(value: str) -> OracleVerdict:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return OracleVerdict(True, False, "ipv6_invalid")
    return OracleVerdict(True, True, "ipv6_valid")


def _cidrize_oracle(value: str) -> OracleVerdict:
    for oracle in (
        _cidrize_plain_address,
        _cidrize_network,
        _cidrize_range,
        _cidrize_wildcard,
    ):
        verdict = oracle(value)
        if verdict is not None:
            return verdict
    return OracleVerdict(False, None, "cidrize_oracle_unsupported_shape")


def _cidrize_plain_address(value: str) -> OracleVerdict | None:
    if "/" in value or "-" in value or "[" in value or "]" in value:
        return None
    ipv4 = _ipv4_oracle(value)
    if ipv4.expected_valid:
        return OracleVerdict(True, True, "cidrize_plain_ipv4")
    ipv6 = _ipv6_oracle(value)
    if ipv6.expected_valid:
        return OracleVerdict(True, True, "cidrize_plain_ipv6")
    return OracleVerdict(True, False, "cidrize_plain_address_invalid")


def _cidrize_network(value: str) -> OracleVerdict | None:
    if "/" not in value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return OracleVerdict(True, False, "cidrize_network_invalid")
    family = "ipv4" if network.version == 4 else "ipv6"
    return OracleVerdict(True, True, f"cidrize_{family}_network")


def _cidrize_range(value: str) -> OracleVerdict | None:
    if "-" not in value:
        return None
    left, right = value.split("-", 1)
    if not left or not right:
        return OracleVerdict(True, False, "cidrize_range_missing_endpoint")

    left_ipv4 = _ipv4_oracle(left)
    if left_ipv4.expected_valid:
        right_ipv4 = _expand_ipv4_shorthand(left, right)
        if right_ipv4 is None:
            verdict = _ipv4_oracle(right)
            right_ipv4 = right if verdict.expected_valid else None
        if right_ipv4 is None:
            return OracleVerdict(True, False, "cidrize_ipv4_range_invalid_end")
        if int(ipaddress.IPv4Address(left)) > int(ipaddress.IPv4Address(right_ipv4)):
            return OracleVerdict(True, False, "cidrize_ipv4_range_descending")
        return OracleVerdict(True, True, "cidrize_ipv4_range")

    left_ipv6 = _ipv6_oracle(left)
    if left_ipv6.expected_valid:
        right_ipv6 = _ipv6_oracle(right)
        if not right_ipv6.expected_valid:
            return OracleVerdict(True, False, "cidrize_ipv6_range_invalid_end")
        if int(ipaddress.IPv6Address(left)) > int(ipaddress.IPv6Address(right)):
            return OracleVerdict(True, False, "cidrize_ipv6_range_descending")
        return OracleVerdict(True, True, "cidrize_ipv6_range")

    return OracleVerdict(True, False, "cidrize_range_invalid_start")


def _expand_ipv4_shorthand(start: str, end_fragment: str) -> str | None:
    if not _IPV4_OCTET_RE.fullmatch(end_fragment):
        return None
    end_octet = int(end_fragment, 10)
    if not 0 <= end_octet <= 255:
        return None
    start_parts = start.split(".")
    return ".".join([*start_parts[:3], str(end_octet)])


def _cidrize_wildcard(value: str) -> OracleVerdict | None:
    range_match = _CIDRIZE_WILDCARD_RANGE_RE.fullmatch(value)
    if range_match:
        prefix, fixed_prefix, low, high = range_match.groups()
        base = f"{prefix}{fixed_prefix}"
        left = f"{base}{low}"
        right = f"{base}{high}"
        left_verdict = _ipv4_oracle(left)
        right_verdict = _ipv4_oracle(right)
        if left_verdict.expected_valid and right_verdict.expected_valid and int(low) <= int(high):
            return OracleVerdict(True, True, "cidrize_ipv4_wildcard_range")
        return OracleVerdict(True, False, "cidrize_ipv4_wildcard_range_invalid")

    match = _CIDRIZE_WILDCARD_RE.fullmatch(value)
    if match:
        prefix, digits = match.groups()
        options = [f"{prefix}{digit}" for digit in digits]
        if options and all(_ipv4_oracle(option).expected_valid for option in options):
            return OracleVerdict(True, True, "cidrize_ipv4_wildcard_set")
        return OracleVerdict(True, False, "cidrize_ipv4_wildcard_set_invalid")

    if "[" in value or "]" in value:
        return OracleVerdict(True, False, "cidrize_malformed_wildcard")
    return None
