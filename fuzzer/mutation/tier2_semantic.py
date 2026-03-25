"""
Tier 2 - Semantic mutations for structured string formats.

The key abstraction in this module is SemanticSpan: a mutator can expose
meaningful regions of the input (IPv4 octets, IPv6 groups, JSON keys, etc.)
and then use optional hot-byte guidance from the DL surrogate to bias which
region gets mutated. This keeps the model in an "attention" role while the
format-specific mutator stays responsible for valid or near-valid edits.
"""

from __future__ import annotations

import abc
import random
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticSpan:
    """A named semantic region in the decoded input string."""

    name: str
    start: int
    end: int
    kind: str = "field"

    def matches(self, byte_index: int) -> bool:
        if self.start == self.end:
            return byte_index == self.start
        return self.start <= byte_index < self.end


class SemanticMutator(abc.ABC):
    """Contract for all format-specific semantic mutators."""

    _registry: dict[str, type["SemanticMutator"]] = {}

    @classmethod
    def register(cls, format_name: str):
        """Class decorator: register a subclass under *format_name*."""

        def decorator(subclass: type["SemanticMutator"]) -> type["SemanticMutator"]:
            cls._registry[format_name.lower()] = subclass
            return subclass

        return decorator

    def __init__(self, operations: list[str] | None = None) -> None:
        self.operations: list[str] = operations or list(getattr(self, "OPERATIONS", []))

    @abc.abstractmethod
    def mutate(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        """Return a semantically mutated copy of *data*."""

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        """Return semantic spans for *data* or an empty list if unsupported."""
        return []

    @staticmethod
    def _decode(data: bytes) -> str:
        return data.decode("latin-1", errors="replace")

    @staticmethod
    def _segment_spans(text: str, delimiter: str, prefix: str) -> list[SemanticSpan]:
        spans: list[SemanticSpan] = []
        start = 0
        index = 0
        while True:
            pos = text.find(delimiter, start)
            if pos == -1:
                spans.append(SemanticSpan(f"{prefix}{index + 1}", start, len(text)))
                break
            spans.append(SemanticSpan(f"{prefix}{index + 1}", start, pos))
            start = pos + len(delimiter)
            index += 1
        return spans

    @staticmethod
    def _normalize_hot_bytes(hot_bytes: list[int] | None, limit: int) -> list[int]:
        if not hot_bytes:
            return []
        return [idx for idx in hot_bytes if 0 <= idx <= limit]

    def _guided_span(
        self,
        spans: list[SemanticSpan],
        hot_bytes: list[int] | None,
    ) -> SemanticSpan | None:
        if not spans:
            return None

        normalized = self._normalize_hot_bytes(
            hot_bytes,
            max(span.end for span in spans) if spans else 0,
        )
        if not normalized:
            return random.choice(spans)

        best_span = None
        best_score = -1
        best_distance = None
        for span in spans:
            score = sum(1 for idx in normalized if span.matches(idx))
            distance = min(
                0 if span.matches(idx) else min(abs(idx - span.start), abs(idx - span.end))
                for idx in normalized
            )
            if (
                score > best_score
                or (score == best_score and (best_distance is None or distance < best_distance))
            ):
                best_span = span
                best_score = score
                best_distance = distance
        return best_span

    def _guided_segment_index(
        self,
        text: str,
        delimiter: str,
        prefix: str,
        hot_bytes: list[int] | None,
    ) -> int:
        spans = self._segment_spans(text, delimiter, prefix)
        chosen = self._guided_span(spans, hot_bytes)
        if chosen is None:
            return 0
        return spans.index(chosen)

    def _guided_char_index(
        self,
        text: str,
        candidates: list[int],
        hot_bytes: list[int] | None,
    ) -> int | None:
        if not candidates:
            return None
        normalized = self._normalize_hot_bytes(hot_bytes, len(text))
        if not normalized:
            return random.choice(candidates)
        return min(candidates, key=lambda pos: min(abs(pos - idx) for idx in normalized))

    def _guided_insert_position(self, text: str, hot_bytes: list[int] | None) -> int:
        normalized = self._normalize_hot_bytes(hot_bytes, len(text))
        if not normalized:
            return random.randint(0, len(text))
        anchor = random.choice(normalized)
        return max(0, min(len(text), anchor + random.choice([-1, 0, 1])))


class PassThroughMutator(SemanticMutator):
    """Fallback mutator for unrecognised formats."""

    def mutate(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:  # noqa: ARG002
        return data


def get_mutator(format_name: str, fmt_config: dict | None = None) -> SemanticMutator:
    """Return the registered SemanticMutator for *format_name*."""
    key = format_name.lower()
    cls = SemanticMutator._registry.get(key)
    if cls is None:
        registered = sorted(SemanticMutator._registry)
        print(
            f"[tier2] No semantic mutator for '{format_name}' "
            f"(registered: {registered}) - using pass-through."
        )
        return PassThroughMutator()
    operations = None
    if fmt_config and "semantic_rules" in fmt_config:
        operations = list(fmt_config["semantic_rules"])
    return cls(operations=operations)


@SemanticMutator.register("ipv4")
class IPv4SemanticMutator(SemanticMutator):
    OPERATIONS = [
        "octet_boundary",
        "leading_zeros",
        "extra_octets",
        "missing_octets",
        "wrong_separator",
        "overflow_octet",
        "negative_octet",
        "hex_octet",
        "empty_octet",
        "whitespace_injection",
    ]

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        return self._segment_spans(self._decode(data), ".", "octet")

    def mutate(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        op = random.choice(self.operations)
        try:
            return getattr(self, f"_{op}")(data, hot_bytes=hot_bytes)
        except Exception:
            return data

    def _octet_boundary(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        parts[idx] = str(random.choice([0, 1, 127, 128, 254, 255]))
        return ".".join(parts).encode()

    def _leading_zeros(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        try:
            parts[idx] = str(int(parts[idx])).zfill(random.randint(1, 4))
        except ValueError:
            pass
        return ".".join(parts).encode()

    def _extra_octets(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        extra = ".".join(str(random.randint(0, 255)) for _ in range(random.randint(1, 3)))
        pos = self._guided_insert_position(s, hot_bytes)
        if pos >= len(s):
            return f"{s}.{extra}".encode()
        return (s[:pos] + "." + extra + s[pos:]).encode()

    def _missing_octets(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) < 2:
            return data
        idx = min(len(parts) - 1, self._guided_segment_index(s, ".", "octet", hot_bytes))
        parts.pop(idx)
        return ".".join(parts).encode()

    def _wrong_separator(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        dots = [i for i, c in enumerate(s) if c == "."]
        pos = self._guided_char_index(s, dots, hot_bytes)
        if pos is None:
            return data
        replacement = random.choice([":", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1 :]).encode()

    def _overflow_octet(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        parts[idx] = str(random.choice([256, 300, 999, 1000, 65535, 2**32]))
        return ".".join(parts).encode()

    def _negative_octet(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        parts[idx] = str(random.choice([-1, -127, -128, -255]))
        return ".".join(parts).encode()

    def _hex_octet(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        try:
            parts[idx] = hex(int(parts[idx]))
        except ValueError:
            pass
        return ".".join(parts).encode()

    def _empty_octet(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes)
        parts[idx] = ""
        return ".".join(parts).encode()

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
    ) -> bytes:
        s = self._decode(data)
        pos = self._guided_insert_position(s, hot_bytes)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode()


@SemanticMutator.register("ipv6")
class IPv6SemanticMutator(SemanticMutator):
    OPERATIONS = [
        "group_boundary",
        "double_colon_position",
        "mixed_notation",
        "extra_groups",
        "missing_groups",
        "wrong_separator",
        "overflow_group",
        "leading_zeros",
        "zone_id",
        "multiple_double_colons",
        "empty_group",
        "whitespace_injection",
    ]

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        s = self._decode(data)
        spans = self._segment_spans(s, ":", "group")
        for match in re.finditer(r"::", s):
            spans.append(SemanticSpan("double_colon", match.start(), match.end(), kind="separator"))
        return spans

    def mutate(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        op = random.choice(self.operations)
        try:
            return getattr(self, f"_{op}")(data, hot_bytes=hot_bytes)
        except Exception:
            return data

    def _group_boundary(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes)
        parts[idx] = random.choice(["0", "1", "ffff", "8000", "7fff", "0000"])
        return ":".join(parts).encode()

    def _double_colon_position(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        s_clean = s.replace("::", ":")
        parts = [part for part in s_clean.split(":") if part]
        if len(parts) < 2:
            return data
        insert_pos = min(len(parts), self._guided_segment_index(s_clean, ":", "group", hot_bytes))
        parts.insert(insert_pos, "")
        parts.insert(insert_pos, "")
        return ":".join(parts).encode()

    def _mixed_notation(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:  # noqa: ARG002
        s = self._decode(data)
        ipv4 = ".".join(str(random.choice([0, 1, 127, 192, 255])) for _ in range(4))
        if "::" in s:
            return f"{s}{ipv4}".encode()
        return f"::ffff:{ipv4}".encode()

    def _extra_groups(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        extra = ":".join(
            hex(random.randint(0, 0xFFFF))[2:] for _ in range(random.randint(1, 3))
        )
        pos = self._guided_insert_position(s, hot_bytes)
        if pos >= len(s):
            return f"{s}:{extra}".encode()
        return (s[:pos] + ":" + extra + s[pos:]).encode()

    def _missing_groups(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(":")
        if len(parts) < 3:
            return data
        idx = min(len(parts) - 1, self._guided_segment_index(s, ":", "group", hot_bytes))
        parts.pop(idx)
        return ":".join(parts).encode()

    def _wrong_separator(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        colons = [i for i, c in enumerate(s) if c == ":"]
        pos = self._guided_char_index(s, colons, hot_bytes)
        if pos is None:
            return data
        replacement = random.choice([".", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1 :]).encode()

    def _overflow_group(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes)
        parts[idx] = hex(random.choice([0x10000, 0xFFFFF, 0xFFFFFF]))[2:]
        return ":".join(parts).encode()

    def _multiple_double_colons(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
    ) -> bytes:
        s = self._decode(data)
        pos = self._guided_insert_position(s, hot_bytes)
        return (s[:pos] + "::" + s[pos:]).encode()

    def _zone_id(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        zone = random.choice(["%eth0", "%lo", "%0", "%999", "%"])
        pos = self._guided_insert_position(s, hot_bytes)
        if pos >= len(s):
            return (s + zone).encode()
        return (s[:pos] + zone + s[pos:]).encode()

    def _empty_group(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(":")
        if not parts:
            return data
        idx = min(len(parts) - 1, self._guided_segment_index(s, ":", "group", hot_bytes))
        parts[idx] = ""
        return ":".join(parts).encode()

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
    ) -> bytes:
        s = self._decode(data)
        pos = self._guided_insert_position(s, hot_bytes)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode()

    def _leading_zeros(self, data: bytes, hot_bytes: list[int] | None = None) -> bytes:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes)
        try:
            parts[idx] = format(int(parts[idx], 16), "04x").zfill(random.randint(4, 8))
        except ValueError:
            pass
        return ":".join(parts).encode()
