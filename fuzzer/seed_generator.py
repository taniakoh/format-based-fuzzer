"""
Grammar-based seed generators for IPv4 and IPv6 address strings.

Produces 100% syntactically valid seeds so mutations start from a known-good
state, not random bytes.  All seeds are returned as bytes (UTF-8 encoded
address strings) to match the common bytes-in / bytes-out mutation interface.
"""

import random
from pathlib import Path

_HERE = Path(__file__).parent.parent


class IPv4SeedGenerator:
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

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = []
        # First: load the hand-curated seed file if present
        seed_file = _HERE / "corpus" / "ipv4_seeds.txt"
        if seed_file.exists():
            for line in seed_file.read_text().splitlines():
                line = line.strip()
                if line:
                    seeds.append(line.encode())
        # Fill remainder with generated seeds
        while len(seeds) < n:
            seeds.append(self.generate())
        return seeds[:n]


class IPv6SeedGenerator:
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
            # Replace last group with IPv4 notation
            parts = addr.rsplit(":", 1)
            addr = parts[0] + ":" + ipv4_suffix
        return addr.encode()

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = []
        seed_file = _HERE / "corpus" / "ipv6_seeds.txt"
        if seed_file.exists():
            for line in seed_file.read_text().splitlines():
                line = line.strip()
                if line:
                    seeds.append(line.encode())
        while len(seeds) < n:
            seeds.append(self.generate())
        return seeds[:n]
