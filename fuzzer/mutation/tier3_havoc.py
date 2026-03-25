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

    def mutate(
        self,
        data: bytes,
        iterations: int = 8,
        hot_bytes: list[int] | None = None,
        guided_ratio: float = 0.7,
    ) -> bytes:
        buf = bytearray(data)
        for _ in range(iterations):
            op = random.choices(self.operators, weights=self.weights, k=1)[0]
            buf = self._apply(buf, op, hot_bytes=hot_bytes, guided_ratio=guided_ratio)
        return bytes(buf)

    def _pick_index(
        self,
        buf_len: int,
        hot_bytes: list[int] | None,
        guided_ratio: float,
    ) -> int:
        if buf_len <= 1:
            return 0

        candidates = [idx for idx in (hot_bytes or []) if 0 <= idx < buf_len]
        use_guidance = candidates and random.random() < guided_ratio
        if use_guidance:
            return random.choice(candidates)
        return random.randint(0, buf_len - 1)

    def _apply(
        self,
        buf: bytearray,
        op: str,
        hot_bytes: list[int] | None = None,
        guided_ratio: float = 0.7,
    ) -> bytearray:
        if not buf:
            return buf
        idx = self._pick_index(len(buf), hot_bytes, guided_ratio)

        match op:
            case "bit_flip":
                buf[idx] ^= 1 << random.randint(0, 7)
            case "byte_substitute":
                buf[idx] = random.randint(0, 255)
            case "arithmetic":
                buf[idx] = (buf[idx] + random.choice([-35, -1, 1, 35])) & 0xFF
            case "splice":
                if len(buf) > 4:
                    mid = max(1, min(len(buf) - 1, idx))
                    buf = buf[mid:] + buf[:mid]
            case "delete_range":
                end = min(idx + random.randint(1, 8), len(buf))
                del buf[idx:end]
            case "insert_random":
                ins = bytes(random.randint(0, 255) for _ in range(random.randint(1, 8)))
                buf[idx:idx] = ins
            case "interesting_byte":
                buf[idx] = random.choice([0x00, 0x01, 0x2E, 0x3A, 0x7F, 0x80, 0xFF])

        return buf
