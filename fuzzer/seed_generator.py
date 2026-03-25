"""
Grammar-based seed generators for IPv4 and IPv6 address strings.

Produces 100% syntactically valid seeds so mutations start from a known-good
state, not random bytes.  All seeds are returned as bytes (UTF-8 encoded
address strings) to match the common bytes-in / bytes-out mutation interface.

Adding a new format
-------------------
Option A — config only (zero Python):
  Add ``valid_examples`` to ``config/<target>_format.json``.
  ``get_seed_generator`` will use ``GenericSeedGenerator`` which reads that list
  and supplements it from ``corpus/<target>_seeds.txt`` if present.

Option B — custom generator (full control):
  Subclass ``SeedGenerator``, implement ``generate()`` and decorate with
  ``@SeedGenerator.register("<target>")``.
"""

import abc
import random
from pathlib import Path

_HERE = Path(__file__).parent.parent


# ─────────────────────────────────────────────────────────────────────────────
#  Abstract base + registry
# ─────────────────────────────────────────────────────────────────────────────

class SeedGenerator(abc.ABC):
    """Contract for all format-specific seed generators."""

    _registry: dict[str, type["SeedGenerator"]] = {}

    @classmethod
    def register(cls, format_name: str):
        """Class decorator: register a subclass under *format_name*."""
        def decorator(subclass: type["SeedGenerator"]) -> type["SeedGenerator"]:
            cls._registry[format_name.lower()] = subclass
            return subclass
        return decorator

    @abc.abstractmethod
    def generate(self) -> bytes:
        """Return a single valid seed."""

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        """Return up to *n* seeds, loading from the seed file first if present."""
        seeds: list[bytes] = []
        seed_file = _HERE / "corpus" / f"{self._target_name()}_seeds.txt"
        if seed_file.exists():
            for line in seed_file.read_text().splitlines():
                line = line.strip()
                if line:
                    seeds.append(line.encode())
        while len(seeds) < n:
            seeds.append(self.generate())
        return seeds[:n]

    def _target_name(self) -> str:
        """Subclasses may override; default derives the name from the class."""
        for name, cls in SeedGenerator._registry.items():
            if cls is type(self):
                return name
        return "unknown"


def get_seed_generator(format_name: str, fmt_config: dict | None = None) -> SeedGenerator:
    """Return the registered SeedGenerator for *format_name*.

    Falls back to ``GenericSeedGenerator`` (seeded from ``valid_examples`` in
    the format config) if no custom generator is registered.
    """
    key = format_name.lower()
    cls = SeedGenerator._registry.get(key)
    if cls is not None:
        return cls()

    registered = sorted(SeedGenerator._registry)
    examples = (fmt_config or {}).get("valid_examples", [])
    print(
        f"[seed_generator] No generator registered for '{format_name}' "
        f"(registered: {registered}) — using GenericSeedGenerator "
        f"with {len(examples)} example(s) from config."
    )
    return GenericSeedGenerator(format_name, examples)


# ─────────────────────────────────────────────────────────────────────────────
#  Generic fallback
# ─────────────────────────────────────────────────────────────────────────────

class GenericSeedGenerator(SeedGenerator):
    """Fallback generator: shuffles ``valid_examples`` from the format config.

    If no examples are provided it emits a single-byte seed so the pipeline
    always has something to mutate.
    """

    def __init__(self, target_name: str, examples: list[str]) -> None:
        self._name = target_name
        self._examples: list[bytes] = [e.encode() for e in examples] or [b""]

    def _target_name(self) -> str:
        return self._name

    def generate(self) -> bytes:
        return random.choice(self._examples)

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds: list[bytes] = []
        seed_file = _HERE / "corpus" / f"{self._name}_seeds.txt"
        if seed_file.exists():
            for line in seed_file.read_text().splitlines():
                line = line.strip()
                if line:
                    seeds.append(line.encode())
        while len(seeds) < n:
            seeds.append(self.generate())
        return seeds[:n]


# ─────────────────────────────────────────────────────────────────────────────
#  IPv4
# ─────────────────────────────────────────────────────────────────────────────

@SeedGenerator.register("ipv4")
class IPv4SeedGenerator(SeedGenerator):
    """Generates valid IPv4 address strings."""

    # Boundary-rich octet values that stress parsers
    BOUNDARY_OCTETS = [0, 1, 9, 10, 99, 100, 127, 128, 199, 200, 254, 255]

    def generate(self) -> bytes:
        octets = [random.choice(self.BOUNDARY_OCTETS) for _ in range(4)]
        # Randomly add leading zeros (valid per the parser's spec)
        parts = [
            str(o).zfill(random.choice([1, 2, 3])) if random.random() < 0.3 else str(o)
            for o in octets
        ]
        return ".".join(parts).encode()


# ─────────────────────────────────────────────────────────────────────────────
#  IPv6
# ─────────────────────────────────────────────────────────────────────────────

@SeedGenerator.register("ipv6")
class IPv6SeedGenerator(SeedGenerator):
    """Generates valid IPv6 address strings."""

    BOUNDARY_GROUPS = ["0", "1", "ff", "fe", "ffff", "0001", "dead", "beef", "db8"]

    # Fixed valid addresses that cover distinct structural forms
    STRUCTURAL_TEMPLATES = [
        "{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}",   # full 8-group
        "{g}::{g}",                             # double-colon middle
        "::{g}",                                # leading double-colon
        "{g}::",                                # trailing double-colon
        "::",                                   # all-zeros compressed
        "{g}::{g}:{g}:{g}",
        "{g}:{g}::{g}:{g}",
        "{g}:{g}:{g}::{g}",
    ]

    def _random_group(self) -> str:
        return random.choice(self.BOUNDARY_GROUPS)

    def generate(self) -> bytes:
        template = random.choice(self.STRUCTURAL_TEMPLATES)
        addr = template.format(g=self._random_group())
        # Occasionally append a mixed IPv4 suffix
        if random.random() < 0.15:
            ipv4_suffix = ".".join(str(random.randint(0, 255)) for _ in range(4))
            parts = addr.rsplit(":", 1)
            addr = parts[0] + ":" + ipv4_suffix
        return addr.encode()


@SeedGenerator.register("cidrize")
class CidrizeSeedGenerator(SeedGenerator):
    """Generates valid mixed-notation IP strings for the cidrize target."""

    IPV4_OCTETS = [0, 1, 2, 8, 10, 24, 26, 64, 80, 85, 127, 170, 175, 192, 255]
    IPV6_GROUPS = ["0", "1", "2", "5", "8", "64", "db8", "ffff", "abcd", "dead"]
    IPV4_PREFIXES = [0, 8, 16, 24, 26, 31, 32]
    IPV6_PREFIXES = [0, 32, 48, 64, 96, 112, 128]

    def _ipv4(self) -> str:
        return ".".join(str(random.choice(self.IPV4_OCTETS)) for _ in range(4))

    def _ipv6(self) -> str:
        templates = [
            "{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}",
            "{g}::{g}",
            "::{g}",
            "{g}::{g}:{g}",
            "::ffff:{ipv4}",
        ]
        template = random.choice(templates)
        return template.format(g=random.choice(self.IPV6_GROUPS), ipv4=self._ipv4())

    def generate(self) -> bytes:
        choice = random.choice(
            [
                "ipv4",
                "ipv4_cidr",
                "ipv4_range",
                "ipv4_partial_range",
                "ipv4_wildcard",
                "ipv6",
                "ipv6_cidr",
                "ipv6_range",
            ]
        )
        if choice == "ipv4":
            value = self._ipv4()
        elif choice == "ipv4_cidr":
            value = f"{self._ipv4()}/{random.choice(self.IPV4_PREFIXES)}"
        elif choice == "ipv4_range":
            start = self._ipv4()
            end = self._ipv4()
            value = f"{start}-{end}"
        elif choice == "ipv4_partial_range":
            base = ".".join(str(random.choice(self.IPV4_OCTETS)) for _ in range(3))
            start = random.choice([1, 8, 80, 170, 200])
            end = random.choice([5, 15, 85, 175, 254])
            if end < start:
                start, end = end, start
            value = f"{base}.{start}-{end}"
        elif choice == "ipv4_wildcard":
            base = ".".join(str(random.choice(self.IPV4_OCTETS)) for _ in range(3))
            value = random.choice(
                [
                    f"{base}.[{random.choice(['0123', '5678', '89'])}]",
                    f"{base}.{random.choice(['1', '8', '9'])}[0-5]",
                ]
            )
        elif choice == "ipv6":
            value = self._ipv6()
        elif choice == "ipv6_cidr":
            value = f"{self._ipv6()}/{random.choice(self.IPV6_PREFIXES)}"
        else:
            value = f"{self._ipv6()}-{self._ipv6()}"
        return value.encode()
