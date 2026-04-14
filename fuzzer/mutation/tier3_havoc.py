"""
Tier 3 - Havoc mutations (byte-level, format-agnostic).

The mutator can accept optional hot-byte guidance from the DL surrogate.
Guidance only biases where mutations land; the chosen operator is still drawn
from the normal weighted havoc policy so random exploration is preserved.
"""

from __future__ import annotations

import random


class HavocMutator:
    def __init__(self, operator_weights: dict[str, float]):
        self.operators = list(operator_weights.keys())
        self.weights = list(operator_weights.values())
        self._last_trace: dict[str, object] | None = None

    def consume_last_trace(self) -> dict[str, object]:
        trace = self._last_trace or {
            "operators": [],
            "fields": [],
            "guided_iterations": 0,
            "random_iterations": 0,
        }
        self._last_trace = None
        return trace

    def mutate(
        self,
        data: bytes,
        iterations: int = 8,
        hot_bytes: list[int] | None = None,
        preferred_indices: list[int] | None = None,
        field_lookup: dict[int, str] | None = None,
        guided_ratio: float = 0.7,
        splice_seed: bytes | None = None,
    ) -> bytes:
        buf = bytearray(data)
        trace = {
            "operators": [],
            "fields": [],
            "guided_iterations": 0,
            "random_iterations": 0,
        }
        for _ in range(iterations):
            op = random.choices(self.operators, weights=self.weights, k=1)[0]
            buf, idx, used_guidance = self._apply(
                buf,
                op,
                hot_bytes=hot_bytes,
                preferred_indices=preferred_indices,
                guided_ratio=guided_ratio,
                splice_seed=splice_seed,
            )
            trace["operators"].append(op)
            if used_guidance:
                trace["guided_iterations"] += 1
            else:
                trace["random_iterations"] += 1
            field = (field_lookup or {}).get(idx)
            if field:
                trace["fields"].append(field)
        self._last_trace = trace
        return bytes(buf)

    def _pick_index(
        self,
        buf_len: int,
        hot_bytes: list[int] | None,
        preferred_indices: list[int] | None,
        guided_ratio: float,
    ) -> tuple[int, bool]:
        if buf_len <= 1:
            return 0, False

        candidates = [idx for idx in (hot_bytes or []) if 0 <= idx < buf_len]
        if candidates and random.random() < guided_ratio:
            return random.choice(candidates), True

        preferred = [idx for idx in (preferred_indices or []) if 0 <= idx < buf_len]
        if preferred and random.random() < guided_ratio:
            return random.choice(preferred), True

        return random.randint(0, buf_len - 1), False

    _ARITHMETIC_DELTAS = [-35, -16, -4, -1, 1, 4, 16, 35]
    _INTERESTING_BYTES = [0x00, 0x01, 0x10, 0x20, 0x2E, 0x3A, 0x40, 0x64, 0x7E, 0x7F, 0x80, 0x81, 0xFF]

    def _apply(
        self,
        buf: bytearray,
        op: str,
        hot_bytes: list[int] | None = None,
        preferred_indices: list[int] | None = None,
        guided_ratio: float = 0.7,
        splice_seed: bytes | None = None,
    ) -> tuple[bytearray, int, bool]:
        if not buf:
            return buf, 0, False
        idx, used_guidance = self._pick_index(
            len(buf),
            hot_bytes,
            preferred_indices,
            guided_ratio,
        )

        match op:
            case "bit_flip":
                buf[idx] ^= 1 << random.randint(0, 7)
            case "byte_substitute":
                buf[idx] = random.randint(0, 255)
            case "arithmetic":
                buf[idx] = (buf[idx] + random.choice(self._ARITHMETIC_DELTAS)) & 0xFF
            case "splice":
                # True cross-seed splice: take a suffix from a second corpus entry
                # and graft it onto a prefix of the current buffer at idx.
                if splice_seed and len(splice_seed) > 2:
                    cross = random.randint(1, len(splice_seed) - 1)
                    buf = buf[:idx] + bytearray(splice_seed[cross:])
                elif len(buf) > 4:
                    # Fallback: circular rotation when no second seed is available
                    mid = max(1, min(len(buf) - 1, idx))
                    buf = buf[mid:] + buf[:mid]
            case "delete_range":
                end = min(idx + random.randint(1, 8), len(buf))
                del buf[idx:end]
            case "insert_random":
                ins = bytes(random.randint(0, 255) for _ in range(random.randint(1, 8)))
                buf[idx:idx] = ins
            case "interesting_byte":
                buf[idx] = random.choice(self._INTERESTING_BYTES)

        return buf, idx, used_guidance
