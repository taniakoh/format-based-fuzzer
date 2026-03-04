"""
AFL-style mutation strategies for byte-level fuzzing.

Mutations operate on bytearray representations of input strings.
Strategies based on AFL's deterministic and havoc stages:
  - Bit flips (1, 2, 4 consecutive bits)
  - Byte flips (1, 2, 4 consecutive bytes)
  - Arithmetic add/subtract on bytes
  - Interesting value substitution (8-bit and 16-bit)
  - Havoc: random replace, insert, delete, splice
"""

import random
import struct

# AFL-style interesting values
INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 129, 255]
INTERESTING_16 = [0, 1, 255, 256, 512, 1000, 1024, 32767, 32768, 65535]
ARITH_MAX = 35  # AFL uses 35 for arithmetic stage


def _flip_bit(data: bytearray, bit_pos: int) -> bytearray:
    """Flip a single bit at the given bit position."""
    out = bytearray(data)
    byte_pos = bit_pos // 8
    bit_offset = 7 - (bit_pos % 8)
    out[byte_pos] ^= (1 << bit_offset)
    return out


# ── Deterministic: Bit flips ──────────────────────────────────────────────────

def bit_flip_1(data: bytearray) -> list[bytearray]:
    """Flip every single bit."""
    results = []
    for i in range(len(data) * 8):
        results.append(_flip_bit(data, i))
    return results


def bit_flip_2(data: bytearray) -> list[bytearray]:
    """Flip every pair of consecutive bits."""
    results = []
    for i in range(len(data) * 8 - 1):
        out = _flip_bit(data, i)
        out = _flip_bit(out, i + 1)
        results.append(out)
    return results


def bit_flip_4(data: bytearray) -> list[bytearray]:
    """Flip every group of 4 consecutive bits."""
    results = []
    for i in range(len(data) * 8 - 3):
        out = bytearray(data)
        for j in range(4):
            out = _flip_bit(out, i + j)
        results.append(out)
    return results


# ── Deterministic: Byte flips ─────────────────────────────────────────────────

def byte_flip_1(data: bytearray) -> list[bytearray]:
    """XOR every byte with 0xFF."""
    results = []
    for i in range(len(data)):
        out = bytearray(data)
        out[i] ^= 0xFF
        results.append(out)
    return results


def byte_flip_2(data: bytearray) -> list[bytearray]:
    """XOR every pair of consecutive bytes with 0xFF."""
    results = []
    for i in range(len(data) - 1):
        out = bytearray(data)
        out[i] ^= 0xFF
        out[i + 1] ^= 0xFF
        results.append(out)
    return results


def byte_flip_4(data: bytearray) -> list[bytearray]:
    """XOR every group of 4 consecutive bytes with 0xFF."""
    results = []
    for i in range(len(data) - 3):
        out = bytearray(data)
        for j in range(4):
            out[i + j] ^= 0xFF
        results.append(out)
    return results


# ── Deterministic: Arithmetic ─────────────────────────────────────────────────

def arith_8(data: bytearray) -> list[bytearray]:
    """Add/subtract 1..ARITH_MAX to every byte (wrapping)."""
    results = []
    for i in range(len(data)):
        for delta in range(1, ARITH_MAX + 1):
            out = bytearray(data)
            out[i] = (data[i] + delta) & 0xFF
            results.append(out)
            out2 = bytearray(data)
            out2[i] = (data[i] - delta) & 0xFF
            results.append(out2)
    return results


def arith_16(data: bytearray) -> list[bytearray]:
    """Add/subtract 1..ARITH_MAX to every 16-bit word (little-endian)."""
    results = []
    for i in range(len(data) - 1):
        orig = struct.unpack_from('<H', data, i)[0]
        for delta in range(1, ARITH_MAX + 1):
            for sign in (+1, -1):
                val = (orig + sign * delta) & 0xFFFF
                out = bytearray(data)
                struct.pack_into('<H', out, i, val)
                results.append(out)
    return results


# ── Deterministic: Interesting values ────────────────────────────────────────

def interesting_8(data: bytearray) -> list[bytearray]:
    """Replace every byte with each interesting 8-bit value."""
    results = []
    for i in range(len(data)):
        for val in INTERESTING_8:
            out = bytearray(data)
            out[i] = val
            results.append(out)
    return results


def interesting_16(data: bytearray) -> list[bytearray]:
    """Replace every 16-bit word with each interesting 16-bit value (LE)."""
    results = []
    for i in range(len(data) - 1):
        for val in INTERESTING_16:
            out = bytearray(data)
            struct.pack_into('<H', out, i, val)
            results.append(out)
    return results


# ── Havoc stage (random mutations) ───────────────────────────────────────────

def _havoc_single(data: bytearray, rng: random.Random) -> bytearray:
    """Apply one randomly chosen havoc mutation."""
    out = bytearray(data)
    if not out:
        return out
    op = rng.randint(0, 8)

    if op == 0:
        # Flip a random bit
        bit = rng.randrange(len(out) * 8)
        out = _flip_bit(out, bit)

    elif op == 1:
        # Set a random byte to a random value
        i = rng.randrange(len(out))
        out[i] = rng.randint(0, 255)

    elif op == 2:
        # Add/subtract random delta from a random byte
        i = rng.randrange(len(out))
        delta = rng.randint(1, ARITH_MAX)
        sign = rng.choice([-1, 1])
        out[i] = (out[i] + sign * delta) & 0xFF

    elif op == 3:
        # Replace byte with interesting 8-bit value
        i = rng.randrange(len(out))
        out[i] = rng.choice(INTERESTING_8)

    elif op == 4:
        # Replace 16-bit word with interesting 16-bit value
        if len(out) >= 2:
            i = rng.randrange(len(out) - 1)
            val = rng.choice(INTERESTING_16) & 0xFFFF
            struct.pack_into('<H', out, i, val)

    elif op == 5:
        # Delete a random byte
        if len(out) > 1:
            i = rng.randrange(len(out))
            del out[i]

    elif op == 6:
        # Insert a random byte
        i = rng.randrange(len(out) + 1)
        out.insert(i, rng.randint(0, 255))

    elif op == 7:
        # Clone/duplicate a random chunk
        if len(out) >= 2:
            src = rng.randrange(len(out))
            length = rng.randint(1, max(1, len(out) // 4))
            chunk = out[src:src + length]
            dest = rng.randrange(len(out) + 1)
            out[dest:dest] = chunk

    elif op == 8:
        # Overwrite a chunk with random bytes
        src = rng.randrange(len(out))
        length = rng.randint(1, max(1, len(out) // 4))
        for j in range(length):
            if src + j < len(out):
                out[src + j] = rng.randint(0, 255)

    return out


def havoc(data: bytearray, count: int, seed: int | None = None) -> list[bytearray]:
    """
    Generate `count` havoc mutations of `data`.
    Each mutation applies a random number of random havoc ops (1-8 stacked).
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        out = bytearray(data)
        stacks = rng.randint(1, 8)
        for _ in range(stacks):
            out = _havoc_single(out, rng)
        results.append(out)
    return results


# ── Deterministic mutation pipeline ──────────────────────────────────────────

def deterministic_mutations(data: bytearray) -> list[bytearray]:
    """
    Run all deterministic AFL stages and return every generated variant.
    Suitable for short inputs (IP addresses are short, so this is feasible).
    """
    results = []
    results.extend(bit_flip_1(data))
    results.extend(bit_flip_2(data))
    results.extend(bit_flip_4(data))
    results.extend(byte_flip_1(data))
    results.extend(byte_flip_2(data))
    results.extend(byte_flip_4(data))
    results.extend(arith_8(data))
    results.extend(arith_16(data))
    results.extend(interesting_8(data))
    results.extend(interesting_16(data))
    return results
