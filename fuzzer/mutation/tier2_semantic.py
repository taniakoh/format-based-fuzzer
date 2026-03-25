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

Adding a new format
-------------------
1. Subclass SemanticMutator and implement every operation as ``_<name>``.
2. Decorate the class with ``@SemanticMutator.register("<format_name>")``.
3. Add a ``config/<format_name>_format.json`` with a ``semantic_rules`` list.
   The factory will read that list and pass it to the mutator automatically.
No changes to existing code or main.py are required.
"""

import abc
import random
import re


# ─────────────────────────────────────────────────────────────────────────────
#  Abstract base + registry
# ─────────────────────────────────────────────────────────────────────────────

class SemanticMutator(abc.ABC):
    """Contract for all format-specific semantic mutators."""

    _registry: dict[str, type["SemanticMutator"]] = {}

    @classmethod
    def register(cls, format_name: str):
        """Class decorator: register a subclass under *format_name* (case-insensitive)."""
        def decorator(subclass: type["SemanticMutator"]) -> type["SemanticMutator"]:
            cls._registry[format_name.lower()] = subclass
            return subclass
        return decorator

    def __init__(self, operations: list[str] | None = None) -> None:
        # Prefer explicitly-supplied list (e.g. from config JSON); fall back to
        # the class-level OPERATIONS constant so subclasses still work standalone.
        self.operations: list[str] = operations or list(getattr(self, "OPERATIONS", []))

    @abc.abstractmethod
    def mutate(self, data: bytes) -> bytes:
        """Return a semantically mutated copy of *data*."""


class PassThroughMutator(SemanticMutator):
    """Fallback mutator for unrecognised formats — returns data unchanged."""

    def mutate(self, data: bytes) -> bytes:
        return data


def get_mutator(format_name: str, fmt_config: dict | None = None) -> SemanticMutator:
    """Return the registered SemanticMutator for *format_name*.

    If *fmt_config* contains a ``semantic_rules`` list it is used as the active
    operation set; otherwise the subclass default (OPERATIONS) is kept.

    If no mutator is registered for *format_name* a PassThroughMutator is
    returned so the pipeline keeps running without semantic mutations.
    """
    key = format_name.lower()
    cls = SemanticMutator._registry.get(key)
    if cls is None:
        registered = sorted(SemanticMutator._registry)
        print(
            f"[tier2] No semantic mutator for '{format_name}' "
            f"(registered: {registered}) — using pass-through."
        )
        return PassThroughMutator()
    operations = None
    if fmt_config and "semantic_rules" in fmt_config:
        operations = list(fmt_config["semantic_rules"])
    return cls(operations=operations)


# ─────────────────────────────────────────────────────────────────────────────
#  IPv4
# ─────────────────────────────────────────────────────────────────────────────

@SemanticMutator.register("ipv4")
class IPv4SemanticMutator(SemanticMutator):
    # Default operation list — overridden by config["semantic_rules"] when the
    # mutator is created via get_mutator().
    OPERATIONS = [
        "octet_boundary", "leading_zeros", "extra_octets",
        "missing_octets", "wrong_separator", "overflow_octet",
        "negative_octet", "hex_octet", "empty_octet",
        "whitespace_injection",
    ]

    def mutate(self, data: bytes) -> bytes:
        op = random.choice(self.operations)
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

@SemanticMutator.register("ipv6")
class IPv6SemanticMutator(SemanticMutator):
    OPERATIONS = [
        "group_boundary", "double_colon_position", "mixed_notation",
        "extra_groups", "missing_groups", "wrong_separator",
        "overflow_group", "multiple_double_colons", "zone_id",
        "empty_group", "whitespace_injection",
    ]

    def mutate(self, data: bytes) -> bytes:
        op = random.choice(self.operations)
        try:
            return getattr(self, f"_{op}")(data)
        except Exception:
            return data

    def _group_boundary(self, data: bytes) -> bytes:
        """Replace one hex group with a boundary value."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(":")
        idx = random.randint(0, len(parts) - 1)
        parts[idx] = random.choice(["0", "1", "ffff", "8000", "7fff", "0000"])
        return ":".join(parts).encode()

    def _double_colon_position(self, data: bytes) -> bytes:
        """Move or add a :: to a different position."""
        s = data.decode("latin-1", errors="replace")
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

    def _leading_zeros(self, data: bytes) -> bytes:
        """Pad one hex group with leading zeros."""
        s = data.decode("latin-1", errors="replace")
        parts = s.split(":")
        idx = random.randint(0, len(parts) - 1)
        try:
            val = int(parts[idx], 16)
            parts[idx] = format(val, "04x").zfill(random.randint(4, 8))
        except ValueError:
            pass
        return ":".join(parts).encode()
