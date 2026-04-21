"""Structured expected-validity oracles for parser targets.

The oracle is shape-driven rather than example-driven:

1. Recognize the input family (plain address, network, range, wildcard, ...)
2. Validate that family with generic semantic rules

This keeps the oracle from overfitting to the current hand-written examples.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class OracleVerdict:
    supported: bool
    expected_valid: bool | None
    reason: str
    shape: str = "unknown"
    normalized: str | None = None


@dataclass(frozen=True)
class _CidrizeShape:
    shape: str
    values: dict[str, str]


_IPV4_OCTET_RE = re.compile(r"^[0-9]{1,3}$")
_DECIMAL_RE = re.compile(r"^[0-9]+$")
_IPV4_LIKE_RE = re.compile(r"^[0-9.\s]+$")
_IPV6_LIKE_RE = re.compile(r"^[0-9A-Fa-f:.]+$")


def evaluate_target_input(target: str, input_str: str) -> OracleVerdict:
    target_name = target.lower()
    if target_name == "ipv4":
        return _ipv4_oracle(input_str)
    if target_name == "ipv6":
        return _ipv6_oracle(input_str)
    if target_name == "cidrize":
        return _cidrize_oracle(input_str)
    if target_name in ("json", "json_direct", "cjson"):
        return _json_oracle(input_str)
    if target_name == "xml":
        return _xml_oracle(input_str)
    return OracleVerdict(False, None, "no_oracle_for_target", shape="unsupported")


def _verdict(
    *,
    supported: bool,
    expected_valid: bool | None,
    reason: str,
    shape: str,
    normalized: str | None = None,
) -> OracleVerdict:
    return OracleVerdict(
        supported=supported,
        expected_valid=expected_valid,
        reason=reason,
        shape=shape,
        normalized=normalized,
    )


def _ipv4_oracle(value: str) -> OracleVerdict:
    parts = value.split(".")
    if len(parts) != 4:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="ipv4_requires_4_octets",
            shape="plain_ipv4",
        )

    normalized_parts: list[str] = []
    for part in parts:
        if not _IPV4_OCTET_RE.fullmatch(part):
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="ipv4_non_decimal_octet",
                shape="plain_ipv4",
            )
        octet = int(part, 10)
        if not 0 <= octet <= 255:
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="ipv4_octet_out_of_range",
                shape="plain_ipv4",
            )
        normalized_parts.append(str(octet))

    return _verdict(
        supported=True,
        expected_valid=True,
        reason="ipv4_valid",
        shape="plain_ipv4",
        normalized=".".join(normalized_parts),
    )


def _ipv6_oracle(value: str) -> OracleVerdict:
    try:
        address = ipaddress.IPv6Address(value)
    except ValueError:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="ipv6_invalid",
            shape="plain_ipv6",
        )
    return _verdict(
        supported=True,
        expected_valid=True,
        reason="ipv6_valid",
        shape="plain_ipv6",
        normalized=str(address),
    )


def _json_oracle(value: str) -> OracleVerdict:
    """Use Python's stdlib json.loads as the reference oracle for JSON targets.

    If stdlib accepts the input it is valid JSON; if it raises JSONDecodeError
    it is invalid.  Any other exception is treated as unsupported so the fuzzer
    can still explore those inputs without committing to a verdict.
    """
    try:
        json.loads(value)
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="json_valid",
            shape="json",
        )
    except json.JSONDecodeError:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="json_invalid",
            shape="json",
        )
    except Exception:
        return _verdict(
            supported=False,
            expected_valid=None,
            reason="json_oracle_error",
            shape="unsupported",
        )


def _xml_oracle(value: str) -> OracleVerdict:
    lowered = value.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return _verdict(
            supported=False,
            expected_valid=None,
            reason="xml_subset_excludes_doctype_and_entity",
            shape="unsupported",
        )
    try:
        root = ET.fromstring(value)
        normalized = root.tag if isinstance(root.tag, str) else None
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="xml_well_formed",
            shape="xml",
            normalized=normalized,
        )
    except ET.ParseError:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="xml_malformed",
            shape="xml",
        )
    except Exception:
        return _verdict(
            supported=False,
            expected_valid=None,
            reason="xml_oracle_error",
            shape="unsupported",
        )


def _cidrize_oracle(value: str) -> OracleVerdict:
    parsed = _parse_cidrize_shape(value)
    if parsed is None:
        return _verdict(
            supported=False,
            expected_valid=None,
            reason="cidrize_unsupported_shape",
            shape="unsupported",
        )
    return _validate_cidrize_shape(parsed)


def _parse_cidrize_shape(value: str) -> _CidrizeShape | None:
    text = value.strip()
    if not text:
        return _CidrizeShape("plain_address", {"value": value})

    if "[" in value or "]" in value:
        return _parse_cidrize_wildcard(value)

    if "/" in value:
        return _parse_cidrize_network(value)

    if "-" in value:
        return _parse_cidrize_range(value)

    if "." in value or ":" in value:
        return _CidrizeShape("plain_address", {"value": value})

    return None


def _parse_cidrize_network(value: str) -> _CidrizeShape:
    left, sep, right = value.partition("/")
    if not sep:
        return _CidrizeShape("malformed", {"family": "network", "value": value})
    return _CidrizeShape("network", {"base": left, "prefix": right, "value": value})


def _parse_cidrize_range(value: str) -> _CidrizeShape:
    left, sep, right = value.partition("-")
    if not sep:
        return _CidrizeShape("malformed", {"family": "range", "value": value})
    if _looks_like_ipv4_text(left) and "." in left and _DECIMAL_RE.fullmatch(right):
        return _CidrizeShape("ipv4_partial_range", {"left": left, "right": right, "value": value})
    return _CidrizeShape("range", {"left": left, "right": right, "value": value})


def _parse_cidrize_wildcard(value: str) -> _CidrizeShape:
    if value.count("[") != 1 or value.count("]") != 1:
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})
    if value.index("[") > value.index("]"):
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})

    prefix, _, remainder = value.partition("[")
    content, closing, suffix = remainder.partition("]")
    if not closing or suffix:
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})

    if "." not in prefix:
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})

    base_prefix, fixed_octet = prefix.rsplit(".", 1)
    prefix_octets = base_prefix.split(".")
    if len(prefix_octets) != 3:
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})
    if fixed_octet and not _DECIMAL_RE.fullmatch(fixed_octet):
        return _CidrizeShape("malformed", {"family": "wildcard", "value": value})

    if content.isdigit():
        return _CidrizeShape(
            "ipv4_wildcard_set",
            {
                "prefix": base_prefix,
                "fixed_octet": fixed_octet,
                "content": content,
                "value": value,
            },
        )

    if content.count("-") == 1:
        low, high = content.split("-", 1)
        if low.isdigit() and high.isdigit():
            return _CidrizeShape(
                "ipv4_wildcard_range",
                {
                    "prefix": base_prefix,
                    "fixed_octet": fixed_octet,
                    "low": low,
                    "high": high,
                    "value": value,
                },
            )

    return _CidrizeShape("malformed", {"family": "wildcard", "value": value})


def _validate_cidrize_shape(parsed: _CidrizeShape) -> OracleVerdict:
    match parsed.shape:
        case "plain_address":
            return _validate_cidrize_plain_address(parsed.values["value"])
        case "network":
            return _validate_cidrize_network(parsed.values["base"], parsed.values["prefix"])
        case "range":
            return _validate_cidrize_range(parsed.values["left"], parsed.values["right"])
        case "ipv4_partial_range":
            return _validate_cidrize_partial_range(parsed.values["left"], parsed.values["right"])
        case "ipv4_wildcard_set":
            return _validate_cidrize_wildcard_set(
                parsed.values["prefix"],
                parsed.values["fixed_octet"],
                parsed.values["content"],
                parsed.values["value"],
            )
        case "ipv4_wildcard_range":
            return _validate_cidrize_wildcard_range(
                parsed.values["prefix"],
                parsed.values["fixed_octet"],
                parsed.values["low"],
                parsed.values["high"],
                parsed.values["value"],
            )
        case "malformed":
            family = parsed.values.get("family", "cidrize")
            return _verdict(
                supported=True,
                expected_valid=False,
                reason=f"cidrize_{family}_malformed",
                shape="malformed",
            )
        case _:
            return _verdict(
                supported=False,
                expected_valid=None,
                reason="cidrize_unsupported_shape",
                shape="unsupported",
            )


def _validate_cidrize_plain_address(value: str) -> OracleVerdict:
    ipv4 = _ipv4_oracle(value)
    if ipv4.expected_valid:
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="cidrize_plain_ipv4",
            shape="plain_ipv4",
            normalized=ipv4.normalized,
        )

    ipv6 = _ipv6_oracle(value)
    if ipv6.expected_valid:
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="cidrize_plain_ipv6",
            shape="plain_ipv6",
            normalized=ipv6.normalized,
        )

    if "." in value or ":" in value or any(ch.isspace() for ch in value):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_plain_address_invalid",
            shape="plain_address",
        )

    return _verdict(
        supported=False,
        expected_valid=None,
        reason="cidrize_plain_address_unsupported",
        shape="unsupported",
    )


def _validate_cidrize_network(base: str, prefix: str) -> OracleVerdict:
    if not base or not prefix or not prefix.isdigit():
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_network_invalid",
            shape="network",
        )
    try:
        network = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    except ValueError:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_network_invalid",
            shape="network",
        )

    family = "ipv4" if network.version == 4 else "ipv6"
    return _verdict(
        supported=True,
        expected_valid=True,
        reason=f"cidrize_{family}_network",
        shape="network",
        normalized=str(network),
    )


def _validate_cidrize_range(left: str, right: str) -> OracleVerdict:
    if not left or not right:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_range_missing_endpoint",
            shape="range",
        )

    left_ipv4 = _ipv4_oracle(left)
    if left_ipv4.expected_valid:
        right_ipv4 = _ipv4_oracle(right)
        if not right_ipv4.expected_valid:
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="cidrize_ipv4_range_invalid_end",
                shape="ipv4_range",
            )
        left_num = int(ipaddress.IPv4Address(left_ipv4.normalized or left))
        right_num = int(ipaddress.IPv4Address(right_ipv4.normalized or right))
        if left_num > right_num:
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="cidrize_ipv4_range_descending",
                shape="ipv4_range",
            )
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="cidrize_ipv4_range",
            shape="ipv4_range",
            normalized=f"{left_ipv4.normalized}-{right_ipv4.normalized}",
        )

    left_ipv6 = _ipv6_oracle(left)
    if left_ipv6.expected_valid:
        right_ipv6 = _ipv6_oracle(right)
        if not right_ipv6.expected_valid:
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="cidrize_ipv6_range_invalid_end",
                shape="ipv6_range",
            )
        left_num = int(ipaddress.IPv6Address(left_ipv6.normalized or left))
        right_num = int(ipaddress.IPv6Address(right_ipv6.normalized or right))
        if left_num > right_num:
            return _verdict(
                supported=True,
                expected_valid=False,
                reason="cidrize_ipv6_range_descending",
                shape="ipv6_range",
            )
        return _verdict(
            supported=True,
            expected_valid=True,
            reason="cidrize_ipv6_range",
            shape="ipv6_range",
            normalized=f"{left_ipv6.normalized}-{right_ipv6.normalized}",
        )

    if _looks_like_ipv4_text(left) or _looks_like_ipv4_text(right):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_range_invalid_start",
            shape="ipv4_range",
        )

    if _looks_like_ipv6_text(left) or _looks_like_ipv6_text(right):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv6_range_invalid_start",
            shape="ipv6_range",
        )

    return _verdict(
        supported=False,
        expected_valid=None,
        reason="cidrize_range_unsupported",
        shape="unsupported",
    )


def _validate_cidrize_partial_range(left: str, right_fragment: str) -> OracleVerdict:
    left_ipv4 = _ipv4_oracle(left)
    if not left_ipv4.expected_valid:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_partial_range_invalid_start",
            shape="ipv4_partial_range",
        )

    expanded = _expand_ipv4_shorthand(left, right_fragment)
    if expanded is None:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_partial_range_invalid_end",
            shape="ipv4_partial_range",
        )

    left_num = int(ipaddress.IPv4Address(left_ipv4.normalized or left))
    right_num = int(ipaddress.IPv4Address(expanded))
    if left_num > right_num:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_partial_range_descending",
            shape="ipv4_partial_range",
        )

    return _verdict(
        supported=True,
        expected_valid=True,
        reason="cidrize_ipv4_partial_range",
        shape="ipv4_partial_range",
        normalized=f"{left_ipv4.normalized}-{expanded}",
    )


def _validate_cidrize_wildcard_set(
    prefix: str,
    fixed_octet: str,
    content: str,
    original: str,
) -> OracleVerdict:
    if not _valid_ipv4_prefix(prefix):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_prefix_invalid",
            shape="ipv4_wildcard_set",
        )

    if len(fixed_octet) > 2:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_fixed_octet_invalid",
            shape="ipv4_wildcard_set",
        )

    candidates = [_compose_ipv4_from_parts(prefix, fixed_octet, digit) for digit in content]
    if any(candidate is None for candidate in candidates):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_set_invalid",
            shape="ipv4_wildcard_set",
        )

    return _verdict(
        supported=True,
        expected_valid=True,
        reason="cidrize_ipv4_wildcard_set",
        shape="ipv4_wildcard_set",
        normalized=original,
    )


def _validate_cidrize_wildcard_range(
    prefix: str,
    fixed_octet: str,
    low: str,
    high: str,
    original: str,
) -> OracleVerdict:
    if not _valid_ipv4_prefix(prefix):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_prefix_invalid",
            shape="ipv4_wildcard_range",
        )

    if len(fixed_octet) > 2:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_fixed_octet_invalid",
            shape="ipv4_wildcard_range",
        )

    left = _compose_ipv4_from_parts(prefix, fixed_octet, low)
    right = _compose_ipv4_from_parts(prefix, fixed_octet, high)
    if left is None or right is None:
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_range_invalid",
            shape="ipv4_wildcard_range",
        )

    if int(ipaddress.IPv4Address(left)) > int(ipaddress.IPv4Address(right)):
        return _verdict(
            supported=True,
            expected_valid=False,
            reason="cidrize_ipv4_wildcard_range_descending",
            shape="ipv4_wildcard_range",
        )

    return _verdict(
        supported=True,
        expected_valid=True,
        reason="cidrize_ipv4_wildcard_range",
        shape="ipv4_wildcard_range",
        normalized=original,
    )


def _expand_ipv4_shorthand(start: str, end_fragment: str) -> str | None:
    if not _DECIMAL_RE.fullmatch(end_fragment):
        return None
    start_parts = start.split(".")
    if len(start_parts) != 4:
        return None
    expanded = ".".join([*start_parts[:3], end_fragment])
    verdict = _ipv4_oracle(expanded)
    return verdict.normalized if verdict.expected_valid else None


def _valid_ipv4_prefix(prefix: str) -> bool:
    parts = prefix.split(".")
    if len(parts) != 3:
        return False
    for part in parts:
        if not _IPV4_OCTET_RE.fullmatch(part):
            return False
        if not 0 <= int(part, 10) <= 255:
            return False
    return True


def _compose_ipv4_from_parts(prefix: str, fixed_octet: str, suffix: str) -> str | None:
    if not _DECIMAL_RE.fullmatch(fixed_octet + suffix):
        return None
    octet_text = fixed_octet + suffix
    if len(octet_text) > 3:
        return None
    value = int(octet_text, 10)
    if not 0 <= value <= 255:
        return None
    candidate = f"{prefix}.{value}"
    verdict = _ipv4_oracle(candidate)
    return verdict.normalized if verdict.expected_valid else None


def _looks_like_ipv4_text(value: str) -> bool:
    return "." in value and bool(_IPV4_LIKE_RE.fullmatch(value))


def _looks_like_ipv6_text(value: str) -> bool:
    return ":" in value and bool(_IPV6_LIKE_RE.fullmatch(value))
