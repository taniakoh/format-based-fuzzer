"""
Tier 2 — Semantic Mutations for IPv4 and IPv6 address strings.

Unlike the raw-packet mutations in the implementation guide (which use scapy),
our targets are *string-based* IP parsers that accept addresses via --ipstr.
All mutations therefore operate on the decoded address string and return the
re-encoded bytes, preserving the bytes-in / bytes-out interface.

Mutation categories:
  IPv4: octet boundary values, leading zeros, extra/missing octets,
        wrong separators, overflowed octets, hex notation, whitespace injection
  IPv6: group boundary values, double-colon position, mixed IPv4 notation,
        extra/missing groups, multiple double-colons, zone-ID injection
"""

import random
import re


# ─────────────────────────────────────────────────────────────────────────────
#  IPv4
# ─────────────────────────────────────────────────────────────────────────────

class IPv4SemanticMutator:
    OPERATIONS = [
        "octet_boundary", "leading_zeros", "extra_octets",
        "missing_octets", "wrong_separator", "overflow_octet",
        "negative_octet", "hex_octet", "empty_octet",
        "whitespace_injection",
    ]

    def mutate(self, data: bytes) -> bytes:
        op = random.choice(self.OPERATIONS)
        try:
            return getattr(self, f"_{op}")(data)
        except Exception:
            return data  # never crash the fuzzer on a bad parse

    # ── individual operations ─────────────────────────────────────────────────

    def _octet_boundary(self, data: bytes) -> bytes:
        """Replace one octet with a boundary value."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = random.randint(0, 3)
        parts[idx] = str(random.choice([0, 1, 127, 128, 254, 255]))
        return ".".join(parts).encode()

    def _leading_zeros(self, data: bytes) -> bytes:
        """Add or remove leading zeros from one octet."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = random.randint(0, 3)
        try:
            val = int(parts[idx])
            parts[idx] = str(val).zfill(random.randint(1, 4))
        except ValueError:
            pass
        return ".".join(parts).encode()

    def _extra_octets(self, data: bytes) -> bytes:
        """Append one or more extra octets."""
        s = data.decode("latin-1", errors="replace")
        extra = ".".join(str(random.randint(0, 255)) for _ in range(random.randint(1, 3)))
        return f"{s}.{extra}".encode()

    def _missing_octets(self, data: bytes) -> bytes:
        """Drop one octet."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) < 2:
            return data
        parts.pop(random.randint(0, len(parts) - 1))
        return ".".join(parts).encode()

    def _wrong_separator(self, data: bytes) -> bytes:
        """Replace one dot with an unexpected character."""
        s = data.decode("latin-1", errors="replace")
        dots = [i for i, c in enumerate(s) if c == "."]
        if not dots:
            return data
        pos = random.choice(dots)
        replacement = random.choice([":", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1:]).encode()

    def _overflow_octet(self, data: bytes) -> bytes:
        """Replace one octet with a value > 255."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = random.randint(0, 3)
        parts[idx] = str(random.choice([256, 300, 999, 1000, 65535, 2**32]))
        return ".".join(parts).encode()

    def _negative_octet(self, data: bytes) -> bytes:
        """Replace one octet with a negative value."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = random.randint(0, 3)
        parts[idx] = str(random.choice([-1, -127, -128, -255]))
        return ".".join(parts).encode()

    def _hex_octet(self, data: bytes) -> bytes:
        """Replace one octet with its hex representation."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        idx = random.randint(0, 3)
        try:
            val = int(parts[idx])
            parts[idx] = hex(val)
        except ValueError:
            pass
        return ".".join(parts).encode()

    def _empty_octet(self, data: bytes) -> bytes:
        """Replace one octet with an empty string."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(".")
        if len(parts) != 4:
            return data
        parts[random.randint(0, 3)] = ""
        return ".".join(parts).encode()

    def _whitespace_injection(self, data: bytes) -> bytes:
        """Inject whitespace around a separator or inside an octet."""
        s = data.decode("latin-1", errors="replace")
        ws = random.choice([" ", "\t", "\n", "\r"])
        pos = random.randint(0, len(s))
        return (s[:pos] + ws + s[pos:]).encode()


# ─────────────────────────────────────────────────────────────────────────────
#  IPv6
# ─────────────────────────────────────────────────────────────────────────────

class IPv6SemanticMutator:
    OPERATIONS = [
        "group_boundary", "double_colon_position", "mixed_notation",
        "extra_groups", "missing_groups", "wrong_separator",
        "overflow_group", "multiple_double_colons", "zone_id",
        "empty_group", "whitespace_injection",
    ]

    def mutate(self, data: bytes) -> bytes:
        op = random.choice(self.OPERATIONS)
        try:
            return getattr(self, f"_{op}")(data)
        except Exception:
            return data

    def _group_boundary(self, data: bytes) -> bytes:
        """Replace one hex group with a boundary value."""
        s = data.decode("latin-1", errors="replace")
        # Operate only on the colon-separated groups (ignore :: for simplicity)
        parts = s.split(":")
        idx = random.randint(0, len(parts) - 1)
        parts[idx] = random.choice(["0", "1", "ffff", "8000", "7fff", "0000"])
        return ":".join(parts).encode()

    def _double_colon_position(self, data: bytes) -> bytes:
        """Move or add a :: to a different position."""
        s = data.decode("latin-1", errors="replace")
        # Remove existing ::
        s_clean = s.replace("::", ":")
        parts = [p for p in s_clean.split(":") if p]
        if len(parts) < 2:
            return data
        insert_pos = random.randint(0, len(parts))
        parts.insert(insert_pos, "")
        parts.insert(insert_pos, "")
        return ":".join(parts).encode()

    def _mixed_notation(self, data: bytes) -> bytes:
        """Append or inject an IPv4-style suffix."""
        s = data.decode("latin-1", errors="replace")
        ipv4 = ".".join(str(random.choice([0, 1, 127, 192, 255])) for _ in range(4))
        if "::" in s:
            return f"{s}{ipv4}".encode()
        return f"::ffff:{ipv4}".encode()

    def _extra_groups(self, data: bytes) -> bytes:
        """Append extra colon-separated groups."""
        s = data.decode("latin-1", errors="replace")
        extra = ":".join(
            hex(random.randint(0, 0xFFFF))[2:] for _ in range(random.randint(1, 3))
        )
        return f"{s}:{extra}".encode()

    def _missing_groups(self, data: bytes) -> bytes:
        """Remove one group from a full address."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(":")
        if len(parts) < 3:
            return data
        parts.pop(random.randint(0, len(parts) - 1))
        return ":".join(parts).encode()

    def _wrong_separator(self, data: bytes) -> bytes:
        """Replace one colon with an unexpected character."""
        s = data.decode("latin-1", errors="replace")
        colons = [i for i, c in enumerate(s) if c == ":"]
        if not colons:
            return data
        pos = random.choice(colons)
        replacement = random.choice([".", ",", "/", " ", "-", ""])
        return (s[:pos] + replacement + s[pos + 1:]).encode()

    def _overflow_group(self, data: bytes) -> bytes:
        """Replace one group with a value > 0xFFFF."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(":")
        idx = random.randint(0, len(parts) - 1)
        parts[idx] = hex(random.choice([0x10000, 0xFFFFF, 0xFFFFFF]))[2:]
        return ":".join(parts).encode()

    def _multiple_double_colons(self, data: bytes) -> bytes:
        """Insert a second :: (invalid per RFC)."""
        s = data.decode("latin-1", errors="replace")
        pos = random.randint(0, len(s))
        return (s[:pos] + "::" + s[pos:]).encode()

    def _zone_id(self, data: bytes) -> bytes:
        """Append a zone ID (e.g. %eth0)."""
        s = data.decode("latin-1", errors="replace")
        zone = random.choice(["%eth0", "%lo", "%0", "%999", "%"])
        return (s + zone).encode()

    def _empty_group(self, data: bytes) -> bytes:
        """Replace one group with an empty string."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(":")
        if not parts:
            return data
        parts[random.randint(0, len(parts) - 1)] = ""
        return ":".join(parts).encode()

    def _whitespace_injection(self, data: bytes) -> bytes:
        """Inject whitespace at a random position."""
        s = data.decode("latin-1", errors="replace")
        ws = random.choice([" ", "\t", "\n", "\r"])
        pos = random.randint(0, len(s))
        return (s[:pos] + ws + s[pos:]).encode()
