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
        self._last_trace: dict[str, object] | None = None

    @abc.abstractmethod
    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        """Return a semantically mutated copy of *data*."""

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        """Return semantic spans for *data* or an empty list if unsupported."""
        return []

    def consume_last_trace(self) -> dict[str, object]:
        trace = self._last_trace or {"applied": False}
        self._last_trace = None
        return trace

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
        preferred_fields: list[str] | None = None,
    ) -> SemanticSpan | None:
        if not spans:
            return None

        normalized = self._normalize_hot_bytes(
            hot_bytes,
            max(span.end for span in spans) if spans else 0,
        )
        if not normalized:
            if preferred_fields:
                preferred = [span for span in spans if span.name in preferred_fields]
                if preferred:
                    return random.choice(preferred)
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
        preferred_fields: list[str] | None = None,
    ) -> int:
        spans = self._segment_spans(text, delimiter, prefix)
        chosen = self._guided_span(spans, hot_bytes, preferred_fields=preferred_fields)
        if chosen is None:
            return 0
        return spans.index(chosen)

    def _guided_char_index(
        self,
        text: str,
        candidates: list[int],
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None = None,
        spans: list[SemanticSpan] | None = None,
    ) -> int | None:
        if not candidates:
            return None
        normalized = self._normalize_hot_bytes(hot_bytes, len(text))
        if not normalized:
            if preferred_fields and spans:
                preferred_positions = [
                    pos
                    for pos in candidates
                    if any(span.name in preferred_fields and span.matches(pos) for span in spans)
                ]
                if preferred_positions:
                    return random.choice(preferred_positions)
            return random.choice(candidates)
        return min(candidates, key=lambda pos: min(abs(pos - idx) for idx in normalized))

    def _guided_insert_position(
        self,
        text: str,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None = None,
        spans: list[SemanticSpan] | None = None,
    ) -> int:
        normalized = self._normalize_hot_bytes(hot_bytes, len(text))
        if not normalized:
            if preferred_fields and spans:
                preferred = [span for span in spans if span.name in preferred_fields]
                if preferred:
                    span = random.choice(preferred)
                    return random.randint(span.start, span.end if span.end > span.start else span.start)
            return random.randint(0, len(text))
        anchor = random.choice(normalized)
        return max(0, min(len(text), anchor + random.choice([-1, 0, 1])))

    def _guidance_label(
        self,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
        field: str | None,
    ) -> str:
        if hot_bytes:
            return "guided"
        if preferred_fields and field and field in preferred_fields:
            return "preferred_field"
        return "random"

    def _record_trace(
        self,
        *,
        operation: str,
        field: str | None,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
    ) -> None:
        self._last_trace = {
            "applied": True,
            "operation": operation,
            "field": field,
            "guidance": self._guidance_label(hot_bytes, preferred_fields, field),
        }

    @staticmethod
    def _field_for_position(
        spans: list[SemanticSpan],
        pos: int,
        default: str,
    ) -> str:
        for span in spans:
            if span.matches(pos):
                return span.name
        return default


class PassThroughMutator(SemanticMutator):
    """Fallback mutator for unrecognised formats."""

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:  # noqa: ARG002
        self._last_trace = {"applied": False}
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


@SemanticMutator.register("json")
@SemanticMutator.register("json_direct")
class JSONSemanticMutator(SemanticMutator):
    OPERATIONS = [
        "literal_swap",
        "quote_damage",
        "comma_damage",
        "colon_damage",
        "bracket_flip",
        "duplicate_fragment",
        "delete_fragment",
        "whitespace_injection",
    ]

    _TOKEN_RE = re.compile(
        r'"(?:\\.|[^"\\])*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?'
    )

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        s = self._decode(data)
        spans = [SemanticSpan("root", 0, len(s))]
        for match in self._TOKEN_RE.finditer(s):
            token = match.group(0)
            name = "string" if token.startswith('"') else "literal"
            spans.append(SemanticSpan(name, match.start(), match.end()))
        for idx, char in enumerate(s):
            if char in "{}":
                spans.append(SemanticSpan("object", idx, idx + 1, kind="punctuation"))
            elif char in "[]":
                spans.append(SemanticSpan("array", idx, idx + 1, kind="punctuation"))
            elif char == ",":
                spans.append(SemanticSpan("comma", idx, idx + 1, kind="separator"))
            elif char == ":":
                spans.append(SemanticSpan("colon", idx, idx + 1, kind="separator"))
        return spans

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = random.choice(self.operations)
        try:
            mutated, field = getattr(self, f"_{op}")(
                data,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            self._record_trace(
                operation=op,
                field=field,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            return mutated
        except Exception:
            self._last_trace = {"applied": False}
            return data

    def _spans_by_name(self, data: bytes, *names: str) -> list[SemanticSpan]:
        allowed = set(names)
        return [span for span in self.get_semantic_spans(data) if span.name in allowed]

    def _literal_swap(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self._spans_by_name(data, "literal")
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        replacement = random.choice(["null", "true", "false", "0", "1", "-1", "1.0", "1e309"])
        if chosen is None:
            return replacement.encode(), "literal"
        return (s[: chosen.start] + replacement + s[chosen.end :]).encode(), "literal"

    def _quote_damage(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self._spans_by_name(data, "string")
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            return (s + '"').encode(), "string"
        token = s[chosen.start : chosen.end]
        if len(token) >= 2 and random.random() < 0.5:
            token = token[1:-1]
        else:
            token = '"' + token
        return (s[: chosen.start] + token + s[chosen.end :]).encode(), "string"

    def _comma_damage(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        commas = [span for span in spans if span.name == "comma"]
        chosen = self._guided_span(commas, hot_bytes, preferred_fields)
        if chosen is None:
            pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
            return (s[:pos] + "," + s[pos:]).encode(), "comma"
        replacement = random.choice(["", ",,", ":"])
        return (s[: chosen.start] + replacement + s[chosen.end :]).encode(), "comma"

    def _colon_damage(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        colons = [span for span in spans if span.name == "colon"]
        chosen = self._guided_span(colons, hot_bytes, preferred_fields)
        if chosen is None:
            return (s + ":").encode(), "colon"
        replacement = random.choice(["", "::", ",", " "])
        return (s[: chosen.start] + replacement + s[chosen.end :]).encode(), "colon"

    def _bracket_flip(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self._spans_by_name(data, "object", "array")
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            return random.choice([b"{", b"}", b"[", b"]"]), "root"
        mapping = {"{": "[", "}": "]", "[": "{", "]": "}"}
        current = s[chosen.start : chosen.end]
        replacement = mapping.get(current, random.choice(["{", "}", "[", "]"]))
        return (s[: chosen.start] + replacement + s[chosen.end :]).encode(), chosen.name

    def _duplicate_fragment(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self._spans_by_name(data, "string", "literal")
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            if not s:
                return b"{}", "root"
            start = random.randint(0, max(0, len(s) - 1))
            end = min(len(s), start + random.randint(1, 6))
            fragment = s[start:end]
            return (s[:end] + fragment + s[end:]).encode(), "root"
        fragment = s[chosen.start : chosen.end]
        return (s[: chosen.end] + fragment + s[chosen.end :]).encode(), chosen.name

    def _delete_fragment(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self._spans_by_name(data, "string", "literal")
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            if not s:
                return data, "root"
            start = random.randint(0, len(s) - 1)
            end = min(len(s), start + random.randint(1, 6))
            return (s[:start] + s[end:]).encode(), "root"
        return (s[: chosen.start] + s[chosen.end :]).encode(), chosen.name

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="root"
        )


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

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = random.choice(self.operations)
        try:
            mutated, field = getattr(self, f"_{op}")(
                data,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            self._record_trace(
                operation=op,
                field=field,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            return mutated
        except Exception:
            self._last_trace = {"applied": False}
            return data

    def _octet_boundary(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        parts[idx] = str(random.choice([0, 1, 127, 128, 254, 255]))
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _leading_zeros(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        try:
            parts[idx] = str(int(parts[idx])).zfill(random.randint(1, 4))
        except ValueError:
            pass
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _extra_octets(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        extra = ".".join(str(random.randint(0, 255)) for _ in range(random.randint(1, 3)))
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        if pos >= len(s):
            return f"{s}.{extra}".encode(), "octet4"
        return (s[:pos] + "." + extra + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="octet1"
        )

    def _missing_octets(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) < 2:
            return data, "octet1"
        idx = min(
            len(parts) - 1,
            self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields),
        )
        parts.pop(idx)
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _wrong_separator(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        dots = [i for i, c in enumerate(s) if c == "."]
        spans = self.get_semantic_spans(data)
        pos = self._guided_char_index(
            s,
            dots,
            hot_bytes,
            preferred_fields=preferred_fields,
            spans=spans,
        )
        if pos is None:
            return data, "octet1"
        replacement = random.choice([":", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1 :]).encode(), self._field_for_position(
            spans, pos, default="octet1"
        )

    def _overflow_octet(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        parts[idx] = str(random.choice([256, 300, 999, 1000, 65535, 2**32]))
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _negative_octet(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        parts[idx] = str(random.choice([-1, -127, -128, -255]))
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _hex_octet(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        try:
            parts[idx] = hex(int(parts[idx]))
        except ValueError:
            pass
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _empty_octet(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return data, "octet1"
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        parts[idx] = ""
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="octet1"
        )


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
        "colon_run",
        "empty_group",
        "whitespace_injection",
    ]

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        s = self._decode(data)
        spans = self._segment_spans(s, ":", "group")
        for match in re.finditer(r"::", s):
            spans.append(SemanticSpan("double_colon", match.start(), match.end(), kind="separator"))
        return spans

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = random.choice(self.operations)
        try:
            mutated, field = getattr(self, f"_{op}")(
                data,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            self._record_trace(
                operation=op,
                field=field,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            return mutated
        except Exception:
            self._last_trace = {"applied": False}
            return data

    def _group_boundary(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes, preferred_fields)
        parts[idx] = random.choice(["0", "1", "ffff", "8000", "7fff", "0000"])
        return ":".join(parts).encode(), f"group{idx + 1}"

    def _double_colon_position(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        s_clean = s.replace("::", ":")
        parts = [part for part in s_clean.split(":") if part]
        if len(parts) < 2:
            return data, "group1"
        insert_pos = min(
            len(parts),
            self._guided_segment_index(s_clean, ":", "group", hot_bytes, preferred_fields),
        )
        parts.insert(insert_pos, "")
        parts.insert(insert_pos, "")
        return ":".join(parts).encode(), f"group{min(insert_pos + 1, 8)}"

    def _mixed_notation(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        s = self._decode(data)
        ipv4 = ".".join(str(random.choice([0, 1, 127, 192, 255])) for _ in range(4))
        if "::" in s:
            return f"{s}{ipv4}".encode(), "group8"
        return f"::ffff:{ipv4}".encode(), "group6"

    def _extra_groups(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        extra = ":".join(
            hex(random.randint(0, 0xFFFF))[2:] for _ in range(random.randint(1, 3))
        )
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        if pos >= len(s):
            return f"{s}:{extra}".encode(), "group8"
        return (s[:pos] + ":" + extra + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _missing_groups(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(":")
        if len(parts) < 3:
            return data, "group1"
        idx = min(
            len(parts) - 1,
            self._guided_segment_index(s, ":", "group", hot_bytes, preferred_fields),
        )
        parts.pop(idx)
        return ":".join(parts).encode(), f"group{idx + 1}"

    def _wrong_separator(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        colons = [i for i, c in enumerate(s) if c == ":"]
        spans = self.get_semantic_spans(data)
        pos = self._guided_char_index(
            s,
            colons,
            hot_bytes,
            preferred_fields=preferred_fields,
            spans=spans,
        )
        if pos is None:
            return data, "group1"
        replacement = random.choice([".", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1 :]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _overflow_group(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes, preferred_fields)
        parts[idx] = hex(random.choice([0x10000, 0xFFFFF, 0xFFFFFF]))[2:]
        return ":".join(parts).encode(), f"group{idx + 1}"

    def _multiple_double_colons(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        return (s[:pos] + "::" + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _colon_run(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        """Replace an existing colon separator with a run of 2–4 colons.

        Targets the separator positions directly so the run lands between
        two real groups, which is the only path that survives the
        pyparsing grammar and reaches the token-processing logic.
        """
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        colon_positions = [i for i, ch in enumerate(s) if ch == ":"]
        if not colon_positions:
            return data, "group1"
        if hot_bytes:
            normalized = self._normalize_hot_bytes(hot_bytes, len(s))
            if normalized:
                best = min(colon_positions, key=lambda p: min(abs(p - h) for h in normalized))
                pos = best
            else:
                pos = random.choice(colon_positions)
        else:
            pos = random.choice(colon_positions)
        n = random.choice([2, 3, 4])
        replacement = ":" * n
        return (s[:pos] + replacement + s[pos + 1:]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _zone_id(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        zone = random.choice(["%eth0", "%lo", "%0", "%999", "%"])
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        if pos >= len(s):
            return (s + zone).encode(), "group8"
        return (s[:pos] + zone + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _empty_group(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(":")
        if not parts:
            return data, "group1"
        idx = min(
            len(parts) - 1,
            self._guided_segment_index(s, ":", "group", hot_bytes, preferred_fields),
        )
        parts[idx] = ""
        return ":".join(parts).encode(), f"group{idx + 1}"

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="group1"
        )

    def _leading_zeros(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(":")
        idx = self._guided_segment_index(s, ":", "group", hot_bytes, preferred_fields)
        try:
            parts[idx] = format(int(parts[idx], 16), "04x").zfill(random.randint(4, 8))
        except ValueError:
            pass
        return ":".join(parts).encode(), f"group{idx + 1}"


@SemanticMutator.register("cidrize")
class CidrizeSemanticMutator(SemanticMutator):
    OPERATIONS = [
        "address_boundary",
        "cidr_prefix",
        "cidr_missing_prefix",
        "range_flip",
        "partial_range_end",
        "wildcard_expand",
        "wildcard_damage",
        "separator_confusion",
        "family_mix",
        "token_duplication",
        "whitespace_injection",
    ]

    _IPV4_TOKEN_RE = re.compile(r"\d+(?:\.\d+){3}")
    _IPV6_TOKEN_RE = re.compile(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{0,39}")
    _CIDR_RE = re.compile(r"/\d{1,3}")
    _PARTIAL_RANGE_RE = re.compile(r"(\d+(?:\.\d+){3})-(\d{1,3})")
    _FULL_RANGE_RE = re.compile(r"([0-9A-Fa-f:.]+)-([0-9A-Fa-f:.]+)")
    _WILDCARD_RE = re.compile(r"\[[^\]]*\]")

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        s = self._decode(data)
        spans = [SemanticSpan("root", 0, len(s))]
        for match in self._IPV4_TOKEN_RE.finditer(s):
            spans.append(SemanticSpan("address", match.start(), match.end()))
        for match in self._IPV6_TOKEN_RE.finditer(s):
            token = match.group(0)
            if ":" in token:
                spans.append(SemanticSpan("address", match.start(), match.end()))
        for match in self._CIDR_RE.finditer(s):
            spans.append(SemanticSpan("cidr_prefix", match.start(), match.end()))
        for match in self._WILDCARD_RE.finditer(s):
            spans.append(SemanticSpan("wildcard", match.start(), match.end()))
        for idx, char in enumerate(s):
            if char == "-":
                spans.append(SemanticSpan("range_sep", idx, idx + 1, kind="separator"))
            elif char == "/":
                spans.append(SemanticSpan("cidr_sep", idx, idx + 1, kind="separator"))
            elif char in "[]":
                spans.append(SemanticSpan("wildcard_bracket", idx, idx + 1, kind="separator"))
            elif char.isspace():
                spans.append(SemanticSpan("separator", idx, idx + 1, kind="separator"))
        return spans

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = random.choice(self.operations)
        try:
            mutated, field = getattr(self, f"_{op}")(
                data,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            self._record_trace(
                operation=op,
                field=field,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            return mutated
        except Exception:
            self._last_trace = {"applied": False}
            return data

    @staticmethod
    def _replace_match(text: str, match: re.Match[str], replacement: str) -> str:
        return text[: match.start()] + replacement + text[match.end() :]

    def _address_matches(self, s: str) -> list[re.Match[str]]:
        matches = list(self._IPV4_TOKEN_RE.finditer(s))
        matches.extend(match for match in self._IPV6_TOKEN_RE.finditer(s) if ":" in match.group(0))
        matches.sort(key=lambda match: match.start())
        return matches

    def _choose_match(
        self,
        s: str,
        pattern: re.Pattern[str],
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
        field_name: str,
    ) -> re.Match[str] | None:
        matches = list(pattern.finditer(s))
        if not matches:
            return None
        spans = [SemanticSpan(field_name, match.start(), match.end()) for match in matches]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            return matches[0]
        return matches[spans.index(chosen)]

    def _choose_address_match(
        self,
        s: str,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
    ) -> re.Match[str] | None:
        matches = self._address_matches(s)
        if not matches:
            return None
        spans = [SemanticSpan("address", match.start(), match.end()) for match in matches]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            return matches[0]
        return matches[spans.index(chosen)]

    def _address_boundary(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_address_match(s, hot_bytes, preferred_fields)
        replacements = [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.0.2.33",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ]
        if match is None:
            return random.choice(replacements).encode(), "address"
        return self._replace_match(s, match, random.choice(replacements)).encode(), "address"

    def _cidr_prefix(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(s, self._CIDR_RE, hot_bytes, preferred_fields, "cidr_prefix")
        replacement = "/" + str(random.choice([0, 1, 8, 24, 32, 64, 96, 128, 129, 999]))
        if match is None:
            base = self._choose_address_match(s, hot_bytes, preferred_fields)
            if base is None:
                return f"192.0.2.0{replacement}".encode(), "cidr_prefix"
            return (s[: base.end()] + replacement + s[base.end() :]).encode(), "cidr_prefix"
        return self._replace_match(s, match, replacement).encode(), "cidr_prefix"

    def _cidr_missing_prefix(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(s, self._CIDR_RE, hot_bytes, preferred_fields, "cidr_prefix")
        if match is not None:
            replacement = random.choice(["/", "/-", "/ ", ""])
            return self._replace_match(s, match, replacement).encode(), "cidr_prefix"
        base = self._choose_address_match(s, hot_bytes, preferred_fields)
        if base is None:
            return b"192.0.2.0/", "cidr_prefix"
        return (s[: base.end()] + "/" + s[base.end() :]).encode(), "cidr_prefix"

    def _range_flip(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(s, self._FULL_RANGE_RE, hot_bytes, preferred_fields, "range_sep")
        if match is None:
            return b"192.0.2.85-192.0.2.80", "range_sep"
        left, right = match.group(1), match.group(2)
        return self._replace_match(s, match, f"{right}-{left}").encode(), "range_sep"

    def _partial_range_end(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(
            s, self._PARTIAL_RANGE_RE, hot_bytes, preferred_fields, "range_end"
        )
        if match is None:
            return b"192.0.2.170-999", "range_end"
        replacement = f"{match.group(1)}-{random.choice(['0', '5', '15', '175', '255', '999'])}"
        return self._replace_match(s, match, replacement).encode(), "range_end"

    def _wildcard_expand(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(s, self._WILDCARD_RE, hot_bytes, preferred_fields, "wildcard")
        replacement = random.choice(["[0-9]", "[0-255]", "[0123456789]", "[1-3][0-5]"])
        if match is None:
            return f"{s}{replacement}".encode(), "wildcard"
        return self._replace_match(s, match, replacement).encode(), "wildcard"

    def _wildcard_damage(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_match(s, self._WILDCARD_RE, hot_bytes, preferred_fields, "wildcard")
        if match is None:
            return b"192.0.2.[", "wildcard"
        replacement = random.choice(["[", "]", "[]", "[0-", "[--]", "[5-0]"])
        return self._replace_match(s, match, replacement).encode(), "wildcard"

    def _separator_confusion(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        candidates = [idx for idx, char in enumerate(s) if char in "-/[],:."]
        pos = self._guided_char_index(
            s,
            candidates,
            hot_bytes,
            preferred_fields=preferred_fields,
            spans=spans,
        )
        if pos is None:
            return data, "separator"
        replacement = random.choice([" ", ",", ":", "-", "/", "", ".."])
        return (s[:pos] + replacement + s[pos + 1 :]).encode(), self._field_for_position(
            spans, pos, default="separator"
        )

    def _family_mix(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_address_match(s, hot_bytes, preferred_fields)
        replacement = random.choice(
            [
                "::ffff:192.0.2.33",
                "2001:db8::1",
                "192.0.2.33",
                "2001:db8::192.0.2.33",
            ]
        )
        if match is None:
            return replacement.encode(), "address"
        return self._replace_match(s, match, replacement).encode(), "address"

    def _token_duplication(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        match = self._choose_address_match(s, hot_bytes, preferred_fields)
        if match is None:
            return b"192.0.2.1,192.0.2.1", "address"
        token = match.group(0)
        duplicate = random.choice([f"{token},{token}", f"{token} {token}", f"{token}-{token}"])
        return self._replace_match(s, match, duplicate).encode(), "address"

    def _whitespace_injection(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
        ws = random.choice([" ", "\t", "\n", "\r"])
        return (s[:pos] + ws + s[pos:]).encode(), self._field_for_position(
            spans, pos, default="separator"
        )
