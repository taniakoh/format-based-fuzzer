"""
Tier 3 — Havoc Mutations (byte-level, format-agnostic).

Stacks multiple stochastic operators in a single mutation pass.
Operator selection is weighted — Phase 1 uses static priors from the format
config; Phase 2 replaces these with DL-learned weights (same interface).
"""

import random


class HavocMutator:
    def __init__(self, operator_weights: dict[str, float]):
        self.operators = list(operator_weights.keys())
        self.weights = list(operator_weights.values())

    def mutate(self, data: bytes, iterations: int = 8) -> bytes:
        buf = bytearray(data)
        for _ in range(iterations):
            op = random.choices(self.operators, weights=self.weights, k=1)[0]
            buf = self._apply(buf, op)
        return bytes(buf)

    def _apply(self, buf: bytearray, op: str) -> bytearray:
        if not buf:
            return buf
        idx = random.randint(0, len(buf) - 1)

        match op:
            case "bit_flip":
                buf[idx] ^= (1 << random.randint(0, 7))
            case "byte_substitute":
                buf[idx] = random.randint(0, 255)
            case "arithmetic":
                val = (buf[idx] + random.choice([-35, -1, 1, 35])) & 0xFF
                buf[idx] = val
            case "splice":
                if len(buf) > 4:
                    mid = random.randint(1, len(buf) - 1)
                    # Reverse the two halves to create a new combination
                    buf = buf[mid:] + buf[:mid]
            case "delete_range":
                end = min(idx + random.randint(1, 8), len(buf))
                del buf[idx:end]
            case "insert_random":
                ins = bytes([random.randint(0, 255) for _ in range(random.randint(1, 8))])
                buf[idx:idx] = ins
            case "interesting_byte":
                buf[idx] = random.choice([0x00, 0x01, 0x2E, 0x3A, 0x7F, 0x80, 0xFF])
                # 0x2E = '.', 0x3A = ':' — IP-relevant interesting bytes

        return buf
