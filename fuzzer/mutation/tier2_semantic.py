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

from fuzzer.oracle import evaluate_target_input


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

    def _oracle_guided_operation(
        self,
        target_name: str,
        data: bytes,
        *,
        preferred_ops: list[str] | tuple[str, ...],
        valid_bias: float = 0.80,
        repair_bias: float = 0.70,
    ) -> str:
        preferred = [op for op in preferred_ops if op in self.operations]
        if not preferred:
            return random.choice(self.operations)

        verdict = evaluate_target_input(target_name, self._decode(data))
        if verdict.supported and verdict.expected_valid is True and random.random() < valid_bias:
            return random.choice(preferred)
        if verdict.supported and verdict.expected_valid is False and random.random() < repair_bias:
            return random.choice(preferred)
        return random.choice(self.operations)


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


# ── Generic auto-detecting mutator ───────────────────────────────────────────

class GenericSemanticMutator(SemanticMutator):
    """Format-agnostic semantic mutator.

    Instead of hand-coded format knowledge, this mutator inspects the input
    itself to discover its token structure, then applies mutations that target
    those tokens.  It works on any structured string format without requiring
    a registered subclass or ``semantic_rules`` in the config.

    Token types detected
    --------------------
    - **numeric**  : contiguous digit runs (``\\d+``)
    - **separator** : single non-alphanumeric, non-space characters
                      from a common pool (``./:?#@-_=&;,|~+``)
    - **quoted**   : ``"..."`` or ``'...'`` substrings
    - **segment**  : text between consecutive separators
    """

    # Separators common across most structured string formats
    SEPARATOR_CHARS = set('./:?#@=&;,|~+')

    # Numeric boundary/overflow values to inject
    BOUNDARY_NUMS = [
        "0", "1", "-1", "127", "128", "255", "256",
        "32767", "32768", "65535", "65536",
        "2147483647", "2147483648", "4294967295",
    ]

    OPERATIONS = [
        "separator_replace",
        "separator_delete",
        "separator_duplicate",
        "numeric_boundary",
        "numeric_overflow",
        "segment_delete",
        "segment_duplicate",
        "segment_truncate",
        "quote_damage",
        "case_flip",
        "whitespace_inject",
    ]

    BINARY_OPERATIONS = [
        "magic_tail_flip",
        "marker_duplicate",
        "marker_delete",
        "chunk_duplicate",
        "chunk_truncate",
        "length_field_stress",
        "delimiter_replace",
        "object_marker_insert",
    ]

    # ── Token detection ───────────────────────────────────────────────────────

    _NUM_RE    = re.compile(r'\d+')
    _QUOTED_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
    _LENGTH_VALUE_RE = re.compile(r"(Length|Size|Count)\s+(\d+)")

    def __init__(
        self,
        operations: list[str] | None = None,
        fmt_config: dict | None = None,
    ) -> None:
        self._fmt_config = fmt_config or {}
        self.format_kind = str(self._fmt_config.get("format_kind", "text")).lower()
        self.token_hints = self._normalize_token_hints(self._fmt_config.get("token_hints", {}))
        self.mutation_hints = (
            self._fmt_config.get("generic_mutation_hints")
            or self._fmt_config.get("mutation_hints")
            or {}
        )
        default_operations = (
            list(self.BINARY_OPERATIONS)
            if self.format_kind in {"binary", "container"}
            else list(self.OPERATIONS)
        )
        selected_operations = operations or self._preferred_operations(default_operations)
        super().__init__(operations=selected_operations)

    def _preferred_operations(self, default_operations: list[str]) -> list[str]:
        prefer = self.mutation_hints.get("prefer_operations", [])
        avoid = set(self.mutation_hints.get("avoid_operations", []))
        preferred = [op for op in prefer if op in default_operations and op not in avoid]
        remainder = [op for op in default_operations if op not in avoid and op not in preferred]
        return preferred + remainder or default_operations

    @staticmethod
    def _normalize_token_hints(token_hints: dict | None) -> dict[str, list[bytes]]:
        hints = token_hints or {}
        normalized: dict[str, list[bytes]] = {}
        for key, values in hints.items():
            bucket: list[bytes] = []
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, bytes):
                    bucket.append(value)
                elif isinstance(value, str):
                    bucket.append(value.encode("latin-1", errors="replace"))
            normalized[key] = [value for value in bucket if value]
        return normalized

    def _separator_positions(self, text: str) -> list[int]:
        return [i for i, ch in enumerate(text) if ch in self.SEPARATOR_CHARS]

    def _segment_spans_generic(self, text: str) -> list[tuple[int, int]]:
        """Return (start, end) spans of text between separators."""
        sep_pos = [-1] + self._separator_positions(text) + [len(text)]
        spans = []
        for a, b in zip(sep_pos, sep_pos[1:]):
            start, end = a + 1, b
            if end > start:
                spans.append((start, end))
        return spans

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        if self.format_kind in {"binary", "container"}:
            return self._binary_semantic_spans(data)
        text = self._decode(data)
        spans: list[SemanticSpan] = [SemanticSpan("root", 0, len(text))]
        for m in self._NUM_RE.finditer(text):
            spans.append(SemanticSpan("numeric", m.start(), m.end()))
        for m in self._QUOTED_RE.finditer(text):
            spans.append(SemanticSpan("quoted", m.start(), m.end()))
        for i, ch in enumerate(text):
            if ch in self.SEPARATOR_CHARS:
                spans.append(SemanticSpan("separator", i, i + 1, kind="separator"))
        for idx, (start, end) in enumerate(self._segment_spans_generic(text)):
            spans.append(SemanticSpan(f"segment{idx}", start, end))
        return spans

    def _binary_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        spans = [SemanticSpan("root", 0, len(data))]
        for start, end in self._find_hint_occurrences(data, "magic_bytes"):
            spans.append(SemanticSpan("magic", start, end))
        for start, end in self._find_hint_occurrences(
            data,
            "section_markers",
            "delimiters",
            "field_like_regions",
        ):
            spans.append(SemanticSpan("marker", start, end))
        for start, end in self._length_value_spans(data):
            spans.append(SemanticSpan("length_field", start, end))
        return spans

    # ── Main entry point ──────────────────────────────────────────────────────

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = random.choice(self.operations)
        try:
            result, field = getattr(self, f"_{op}")(
                data, hot_bytes=hot_bytes, preferred_fields=preferred_fields
            )
            self._record_trace(
                operation=op,
                field=field,
                hot_bytes=hot_bytes,
                preferred_fields=preferred_fields,
            )
            return result
        except Exception:
            self._last_trace = {"applied": False}
            return data

    def _find_hint_occurrences(self, data: bytes, *hint_keys: str) -> list[tuple[int, int]]:
        occurrences: list[tuple[int, int]] = []
        for key in hint_keys:
            for token in self.token_hints.get(key, []):
                start = 0
                while token and start < len(data):
                    pos = data.find(token, start)
                    if pos == -1:
                        break
                    occurrences.append((pos, pos + len(token)))
                    start = pos + max(1, len(token))
        return occurrences

    def _length_value_spans(self, data: bytes) -> list[tuple[int, int]]:
        text = data.decode("latin-1", errors="ignore")
        spans: list[tuple[int, int]] = []
        for match in self._LENGTH_VALUE_RE.finditer(text):
            spans.append((match.start(2), match.end(2)))
        return spans

    def _choose_binary_span(
        self,
        data: bytes,
        field_name: str,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
    ) -> SemanticSpan | None:
        spans = [span for span in self._binary_semantic_spans(data) if span.name == field_name]
        return self._guided_span(spans, hot_bytes, preferred_fields)

    def _avoid_prefix_end(self, data: bytes) -> int:
        if not self.mutation_hints.get("avoid_magic_prefix_damage"):
            return 0
        magic_occurrences = self._find_hint_occurrences(data, "magic_bytes")
        if not magic_occurrences:
            return 0
        return max(end for _, end in magic_occurrences)

    def _chunk_bounds(
        self,
        data: bytes,
        hot_bytes: list[int] | None,
        preferred_fields: list[str] | None,
    ) -> tuple[int, int]:
        if not data:
            return 0, 0
        protected_prefix = self._avoid_prefix_end(data)
        start_floor = min(protected_prefix, max(0, len(data) - 1))
        span = self._choose_binary_span(data, "marker", hot_bytes, preferred_fields)
        if span is not None:
            left = max(start_floor, span.start)
            right = min(len(data), span.end + random.randint(1, 16))
            if right > left:
                return left, right
        start = random.randint(start_floor, max(start_floor, len(data) - 1))
        max_width = min(32, len(data) - start)
        width = random.randint(1, max(1, max_width))
        return start, start + width

    # ── Operations ────────────────────────────────────────────────────────────

    def _separator_replace(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        positions = self._separator_positions(text)
        if not positions:
            return data, "separator"
        spans = [SemanticSpan("separator", i, i + 1, kind="separator") for i in positions]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        pos = chosen.start if chosen else random.choice(positions)
        current = text[pos]
        alternatives = list(self.SEPARATOR_CHARS - {current})
        replacement = random.choice(alternatives) if alternatives else current
        return (text[:pos] + replacement + text[pos + 1:]).encode(), "separator"

    def _separator_delete(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        positions = self._separator_positions(text)
        if not positions:
            return data, "separator"
        spans = [SemanticSpan("separator", i, i + 1, kind="separator") for i in positions]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        pos = chosen.start if chosen else random.choice(positions)
        return (text[:pos] + text[pos + 1:]).encode(), "separator"

    def _separator_duplicate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        positions = self._separator_positions(text)
        if not positions:
            return data, "separator"
        spans = [SemanticSpan("separator", i, i + 1, kind="separator") for i in positions]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        pos = chosen.start if chosen else random.choice(positions)
        return (text[:pos] + text[pos] + text[pos:]).encode(), "separator"

    def _numeric_boundary(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        matches = list(self._NUM_RE.finditer(text))
        if not matches:
            return data, "numeric"
        spans = [SemanticSpan("numeric", m.start(), m.end()) for m in matches]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        replacement = random.choice(self.BOUNDARY_NUMS)
        return (text[:chosen.start] + replacement + text[chosen.end:]).encode(), "numeric"

    def _numeric_overflow(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        matches = list(self._NUM_RE.finditer(text))
        if not matches:
            return data, "numeric"
        spans = [SemanticSpan("numeric", m.start(), m.end()) for m in matches]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        # Multiply the existing number by a large factor or wrap it with overflow value
        try:
            val = int(text[chosen.start:chosen.end])
            overflow = str(val * random.choice([256, 65536, 2**32]))
        except (ValueError, OverflowError):
            overflow = "99999999999"
        return (text[:chosen.start] + overflow + text[chosen.end:]).encode(), "numeric"

    def _segment_delete(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        segs = self._segment_spans_generic(text)
        if not segs:
            return data, "segment"
        spans = [SemanticSpan(f"segment{i}", s, e) for i, (s, e) in enumerate(segs)]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        return (text[:chosen.start] + text[chosen.end:]).encode(), "segment"

    def _segment_duplicate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        segs = self._segment_spans_generic(text)
        if not segs:
            return data, "segment"
        spans = [SemanticSpan(f"segment{i}", s, e) for i, (s, e) in enumerate(segs)]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        fragment = text[chosen.start:chosen.end]
        sep = text[chosen.start - 1] if chosen.start > 0 and text[chosen.start - 1] in self.SEPARATOR_CHARS else "."
        return (text[:chosen.end] + sep + fragment + text[chosen.end:]).encode(), "segment"

    def _segment_truncate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        segs = self._segment_spans_generic(text)
        if not segs:
            return data, "segment"
        spans = [SemanticSpan(f"segment{i}", s, e) for i, (s, e) in enumerate(segs)]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        length = chosen.end - chosen.start
        if length <= 1:
            return data, "segment"
        cut = random.randint(1, length - 1)
        return (text[:chosen.start + cut] + text[chosen.end:]).encode(), "segment"

    def _quote_damage(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        matches = list(self._QUOTED_RE.finditer(text))
        if matches:
            # Remove quotes from a quoted token
            spans = [SemanticSpan("quoted", m.start(), m.end()) for m in matches]
            chosen = self._guided_span(spans, hot_bytes, preferred_fields)
            if chosen is None:
                chosen = random.choice(spans)
            inner = text[chosen.start + 1:chosen.end - 1]
            return (text[:chosen.start] + inner + text[chosen.end:]).encode(), "quoted"
        else:
            # No quotes found — inject one at a guided position
            pos = self._guided_insert_position(text, hot_bytes, preferred_fields)
            return (text[:pos] + '"' + text[pos:]).encode(), "quoted"

    def _case_flip(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        segs = self._segment_spans_generic(text)
        alpha_segs = [(s, e) for s, e in segs if any(c.isalpha() for c in text[s:e])]
        if not alpha_segs:
            return data, "segment"
        spans = [SemanticSpan(f"segment{i}", s, e) for i, (s, e) in enumerate(alpha_segs)]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            chosen = random.choice(spans)
        fragment = text[chosen.start:chosen.end]
        flipped = fragment.swapcase() if random.random() < 0.5 else fragment.upper()
        return (text[:chosen.start] + flipped + text[chosen.end:]).encode(), "segment"

    def _whitespace_inject(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = self._decode(data)
        positions = self._separator_positions(text)
        if not positions:
            pos = self._guided_insert_position(text, hot_bytes, preferred_fields)
        else:
            spans = [SemanticSpan("separator", i, i + 1, kind="separator") for i in positions]
            chosen = self._guided_span(spans, hot_bytes, preferred_fields)
            pos = (chosen.start if chosen else random.choice(positions))
        ws = random.choice([" ", "\t", "\n", "  "])
        return (text[:pos] + ws + text[pos:]).encode(), "separator"

    # ── Binary/container operations ──────────────────────────────────────────

    def _magic_tail_flip(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        if not data:
            return b"\x00", "magic"
        chosen = self._choose_binary_span(data, "magic", hot_bytes, preferred_fields)
        if chosen is None:
            end = min(4, len(data))
            chosen = SemanticSpan("magic", 0, end)
        pos = chosen.end - 1 if chosen.end > chosen.start else chosen.start
        if pos >= len(data):
            pos = len(data) - 1
        current = data[pos]
        replacement = random.choice([0x00, 0x0A, 0x20, 0x25, 0x2F, 0x41, 0xFF])
        if replacement == current:
            replacement = (current + 1) % 256
        mutated = bytearray(data)
        mutated[pos] = replacement
        return bytes(mutated), "magic"

    def _marker_duplicate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        chosen = self._choose_binary_span(data, "marker", hot_bytes, preferred_fields)
        if chosen is None:
            start, end = self._chunk_bounds(data, hot_bytes, preferred_fields)
        else:
            start, end = chosen.start, chosen.end
        chunk = data[start:end]
        if not chunk:
            return data, "marker"
        insert_at = min(len(data), end + random.randint(0, 4))
        return data[:insert_at] + chunk + data[insert_at:], "marker"

    def _marker_delete(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        chosen = self._choose_binary_span(data, "marker", hot_bytes, preferred_fields)
        if chosen is None:
            start, end = self._chunk_bounds(data, hot_bytes, preferred_fields)
        else:
            start, end = chosen.start, chosen.end
        return data[:start] + data[end:], "marker"

    def _chunk_duplicate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        start, end = self._chunk_bounds(data, hot_bytes, preferred_fields)
        chunk = data[start:end]
        if not chunk:
            return data, "root"
        insert_at = random.randint(end, len(data))
        return data[:insert_at] + chunk + data[insert_at:], "root"

    def _chunk_truncate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        if len(data) <= 1:
            return data, "root"
        start, end = self._chunk_bounds(data, hot_bytes, preferred_fields)
        return data[:start] + data[end:], "root"

    def _length_field_stress(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        text = data.decode("latin-1", errors="ignore")
        spans = [SemanticSpan("length_field", start, end) for start, end in self._length_value_spans(data)]
        chosen = self._guided_span(spans, hot_bytes, preferred_fields)
        if chosen is None:
            insert_at = min(len(data), self._avoid_prefix_end(data))
            return data[:insert_at] + b" Length 999999 " + data[insert_at:], "length_field"
        replacement = random.choice(["0", "1", "4096", "65535", "999999"])
        return (
            text[:chosen.start].encode("latin-1", errors="replace")
            + replacement.encode("ascii")
            + text[chosen.end:].encode("latin-1", errors="replace")
        ), "length_field"

    def _delimiter_replace(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        delimiters = self.token_hints.get("delimiters", [])
        if not delimiters:
            if not data:
                return b"/", "marker"
            pos = random.randint(self._avoid_prefix_end(data), len(data) - 1)
            replacement = random.choice([b"/", b"<", b">", b"\n", b" ", b"%"])
            return data[:pos] + replacement + data[pos + 1:], "marker"
        chosen_token = random.choice(delimiters)
        pos = data.find(chosen_token)
        if pos == -1:
            insert_at = self._avoid_prefix_end(data)
            return data[:insert_at] + chosen_token + data[insert_at:], "marker"
        replacement = random.choice([token for token in delimiters if token != chosen_token] or [b"/"])
        return data[:pos] + replacement + data[pos + len(chosen_token):], "marker"

    def _object_marker_insert(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        markers = (
            self.token_hints.get("section_markers", [])
            or self.token_hints.get("field_like_regions", [])
            or [b"obj"]
        )
        marker = random.choice(markers)
        anchor = self._choose_binary_span(data, "marker", hot_bytes, preferred_fields)
        insert_at = anchor.end if anchor is not None else self._avoid_prefix_end(data)
        return data[:insert_at] + marker + b"\n" + data[insert_at:], "marker"


def get_mutator(format_name: str, fmt_config: dict | None = None) -> SemanticMutator:
    """Return the registered SemanticMutator for *format_name*.

    Falls back to ``GenericSemanticMutator`` (auto-detects token structure
    from the input) if no format-specific subclass is registered.
    """
    key = format_name.lower()
    cls = SemanticMutator._registry.get(key)
    if cls is None:
        registered = sorted(SemanticMutator._registry)
        print(
            f"[tier2] No semantic mutator for '{format_name}' "
            f"(registered: {registered}) — using GenericSemanticMutator."
        )
        operations = list(fmt_config["semantic_rules"]) if fmt_config and "semantic_rules" in fmt_config else None
        return GenericSemanticMutator(operations=operations, fmt_config=fmt_config)
    operations = None
    if fmt_config and "semantic_rules" in fmt_config:
        operations = list(fmt_config["semantic_rules"])
    return cls(operations=operations)


@SemanticMutator.register("json")
@SemanticMutator.register("json_direct")
@SemanticMutator.register("cjson")
class JSONSemanticMutator(SemanticMutator):
    OPERATIONS = [
        "literal_swap",
        "container_wrap",
        "replace_with_valid_example",
        "quote_damage",
        "comma_damage",
        "colon_damage",
        "bracket_flip",
        "duplicate_fragment",
        "delete_fragment",
        "whitespace_injection",
    ]
    VALID_FOCUSED_OPS = [
        "literal_swap",
        "container_wrap",
        "replace_with_valid_example",
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
        op = self._oracle_guided_operation(
            "json",
            data,
            preferred_ops=self.VALID_FOCUSED_OPS,
        )
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

    def _container_wrap(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        s = self._decode(data).strip()
        if not s:
            return b"{}", "root"
        wrapped = random.choice([
            f"[{s}]",
            f'{{"value":{s}}}',
        ])
        return wrapped.encode(), "root"

    def _replace_with_valid_example(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        example = random.choice([
            "{}",
            "[]",
            '{"value":1}',
            '{"enabled":true,"count":0}',
            '[0,1,2]',
        ])
        return example.encode(), "root"

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
        "neighbor_octet",
        "swap_octets",
        "replace_with_valid_example",
        "extra_octets",
        "missing_octets",
        "wrong_separator",
        "overflow_octet",
        "negative_octet",
        "hex_octet",
        "empty_octet",
        "whitespace_injection",
    ]
    VALID_FOCUSED_OPS = [
        "octet_boundary",
        "leading_zeros",
        "neighbor_octet",
        "swap_octets",
        "replace_with_valid_example",
    ]

    def get_semantic_spans(self, data: bytes) -> list[SemanticSpan]:
        return self._segment_spans(self._decode(data), ".", "octet")

    def mutate(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> bytes:
        op = self._oracle_guided_operation(
            "ipv4",
            data,
            preferred_ops=self.VALID_FOCUSED_OPS,
        )
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

    def _neighbor_octet(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return self._replace_with_valid_example(data, hot_bytes, preferred_fields)
        idx = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        try:
            current = int(parts[idx], 10)
        except ValueError:
            return self._replace_with_valid_example(data, hot_bytes, preferred_fields)
        delta = random.choice([-16, -8, -1, 1, 8, 16])
        parts[idx] = str(max(0, min(255, current + delta)))
        return ".".join(parts).encode(), f"octet{idx + 1}"

    def _swap_octets(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        parts = s.split(".")
        if len(parts) != 4:
            return self._replace_with_valid_example(data, hot_bytes, preferred_fields)
        idx1 = self._guided_segment_index(s, ".", "octet", hot_bytes, preferred_fields)
        idx2 = (idx1 + random.choice([1, 2, 3])) % 4
        parts[idx1], parts[idx2] = parts[idx2], parts[idx1]
        return ".".join(parts).encode(), f"octet{idx1 + 1}"

    def _replace_with_valid_example(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        example = random.choice([
            "0.0.0.0",
            "1.2.3.4",
            "10.0.0.1",
            "127.0.0.1",
            "192.168.0.1",
            "254.99.254.199",
            "255.255.255.255",
        ])
        return example.encode(), "octet1"

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
        "replace_with_valid_example",
        "double_colon_position",
        "triple_colon",
        "compressed_overflow",
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
    VALID_FOCUSED_OPS = [
        "group_boundary",
        "leading_zeros",
        "mixed_notation",
        "replace_with_valid_example",
        "double_colon_position",
        "triple_colon",
        "compressed_overflow",
        "overflow_group",
        "multiple_double_colons",
        "colon_run",
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
        op = self._oracle_guided_operation(
            "ipv6",
            data,
            preferred_ops=self.VALID_FOCUSED_OPS,
        )
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

    def _replace_with_valid_example(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        example = random.choice([
            "::",
            "::1",
            "2001:db8::1",
            "fe80::1",
            "::ffff:192.0.2.33",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ])
        return example.encode(), "group1"

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

    def _triple_colon(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        if "::" in s:
            idx = s.index("::")
            return (s[:idx] + ":::" + s[idx + 2 :]).encode(), self._field_for_position(
                spans, idx, default="group1"
            )

        colon_positions = [
            i for i, ch in enumerate(s)
            if ch == ":" and (i == 0 or s[i - 1] != ":") and (i + 1 >= len(s) or s[i + 1] != ":")
        ]
        if colon_positions:
            pos = self._guided_char_index(
                s,
                colon_positions,
                hot_bytes,
                preferred_fields=preferred_fields,
                spans=spans,
            )
            if pos is not None:
                return (s[:pos] + ":::" + s[pos + 1 :]).encode(), self._field_for_position(
                    spans, pos, default="group1"
                )

        if s:
            pos = self._guided_insert_position(s, hot_bytes, preferred_fields, spans)
            return (s[:pos] + ":::" + s[pos:]).encode(), self._field_for_position(
                spans, pos, default="group1"
            )
        return b":::", "group1"

    def _compressed_overflow(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:
        s = self._decode(data)
        if not s:
            return b"1:::2", "group1"

        spans = self.get_semantic_spans(data)
        if "::" not in s:
            valid_base = random.choice([
                "::1",
                "2001:db8::1",
                "fe80::1",
                "::ffff:192.0.2.33",
            ])
            s = valid_base

        variant = random.choice([
            lambda text: text + ":" + random.choice(["1", "ffff", "dead"]),
            lambda text: text + "::",
            lambda text: text.replace("::", ":::", 1),
            lambda text: text.replace("::", "::" + random.choice(["1:", "ffff:", "dead:"]), 1),
        ])
        mutated = variant(s)
        pos = max(mutated.find("::"), 0)
        return mutated.encode(), self._field_for_position(spans, pos, default="group1")

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

        Only bare group-separator colons are eligible — colons that are
        already adjacent to another colon (i.e. part of '::' notation) are
        skipped so the mutation doesn't corrupt compressed-notation addresses
        into unstructured byte noise.
        """
        s = self._decode(data)
        spans = self.get_semantic_spans(data)
        colon_positions = [
            i for i, ch in enumerate(s)
            if ch == ":" and (i == 0 or s[i - 1] != ":") and (i + 1 >= len(s) or s[i + 1] != ":")
        ]
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
        "replace_with_valid_example",
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
    VALID_FOCUSED_OPS = [
        "address_boundary",
        "replace_with_valid_example",
        "wildcard_expand",
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
        op = self._oracle_guided_operation(
            "cidrize",
            data,
            preferred_ops=self.VALID_FOCUSED_OPS,
        )
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

    def _replace_with_valid_example(
        self,
        data: bytes,
        hot_bytes: list[int] | None = None,
        preferred_fields: list[str] | None = None,
    ) -> tuple[bytes, str]:  # noqa: ARG002
        example = random.choice([
            "192.0.2.33",
            "2001:db8::1",
            "192.0.2.0/24",
            "2001:db8::/64",
            "192.0.2.80-192.0.2.85",
            "192.0.2.170-175",
            "192.0.2.[5678]",
        ])
        return example.encode(), "address"

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
