"""
Grammar-based seed generators for IPv4 and IPv6 address strings.

Produces a mixed corpus of valid and structured-invalid seeds.  Valid seeds
give mutations a well-formed starting point; invalid seeds exercise parser
error-handling paths directly without relying on mutations to stumble into
them.  The ratio is roughly 70 % valid / 30 % invalid for each generator.

All seeds are returned as bytes (UTF-8 encoded address strings) to match the
common bytes-in / bytes-out mutation interface.

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

from fuzzer.bootstrap import load_seed_inputs

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
        seeds = load_seed_inputs(self._target_name(), allow_bootstrap=False)
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
    return GenericSeedGenerator(format_name, examples, fmt_config=fmt_config or {})


# ─────────────────────────────────────────────────────────────────────────────
#  Generic fallback
# ─────────────────────────────────────────────────────────────────────────────

class GenericSeedGenerator(SeedGenerator):
    """Fallback generator: shuffles ``valid_examples`` from the format config.

    If no examples are provided it emits a single-byte seed so the pipeline
    always has something to mutate.
    """

    def __init__(self, target_name: str, examples: list[str], fmt_config: dict | None = None) -> None:
        self._name = target_name
        self._fmt_config = dict(fmt_config or {})
        self._examples: list[bytes] = [e.encode() for e in examples] or [b""]

    def _target_name(self) -> str:
        return self._name

    def generate(self) -> bytes:
        return random.choice(self._examples)

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = load_seed_inputs(
            self._name,
            {
                **self._fmt_config,
                "valid_examples": [e.decode("utf-8", errors="replace") for e in self._examples],
            },
            allow_bootstrap=True,
        )
        while len(seeds) < n:
            seeds.append(self.generate())
        return seeds[:n]


# ─────────────────────────────────────────────────────────────────────────────
#  IPv4
# ─────────────────────────────────────────────────────────────────────────────

@SeedGenerator.register("ipv4")
class IPv4SeedGenerator(SeedGenerator):
    """Generates a mix of valid and structured-invalid IPv4 address strings."""

    BOUNDARY_OCTETS = [0, 1, 9, 10, 99, 100, 127, 128, 199, 200, 254, 255]
    OVERFLOW_OCTETS = [256, 300, 999]
    CURATED_VALID = [
        "0.0.0.0",
        "1.2.3.4",
        "10.0.0.1",
        "10.10.10.10",
        "99.100.127.128",
        "127.0.0.1",
        "169.254.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "223.255.255.254",
        "224.0.0.1",
        "239.255.255.250",
        "255.255.255.255",
        "001.002.003.004",
        "010.000.000.001",
    ]
    CURATED_INVALID = [
        "",
        "1.2.3",
        "1.2.3.4.5",
        ".1.2.3.4",
        "1.2.3.4.",
        "1.2..4",
        "256.0.0.1",
        "1.2.3.999",
        "-1.2.3.4",
        "1.2.3.-4",
        "1,2,3,4",
        "1 .2.3.4",
        "1.2.3. 4",
        "1.2.3.a",
        "0x1.2.3.4",
    ]

    # Invalid structural templates — wrong octet count, out-of-range, bad separators
    INVALID_TEMPLATES = [
        "{o}.{o}.{o}",            # too few octets
        "{o}.{o}.{o}.{o}.{o}",   # too many octets
        "{x}.{o}.{o}.{o}",        # first octet out of range
        "{o}.{o}.{o}.{x}",        # last octet out of range
        "{o}.{o}.{o}.",            # trailing dot
        ".{o}.{o}.{o}.{o}",       # leading dot
        "{o}.{o}..{o}",            # consecutive dots
        "{o},{o},{o},{o}",         # wrong separator
        "",                        # empty string
    ]

    def _octet(self) -> str:
        return str(random.choice(self.BOUNDARY_OCTETS))

    def _overflow(self) -> str:
        return str(random.choice(self.OVERFLOW_OCTETS))

    def generate(self) -> bytes:
        if random.random() < 0.3:
            tmpl = random.choice(self.INVALID_TEMPLATES)
            return tmpl.format(o=self._octet(), x=self._overflow()).encode()
        octets = [random.choice(self.BOUNDARY_OCTETS) for _ in range(4)]
        parts = [
            str(o).zfill(random.choice([1, 2, 3])) if random.random() < 0.3 else str(o)
            for o in octets
        ]
        return ".".join(parts).encode()

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = load_seed_inputs(self._target_name(), allow_bootstrap=False)
        curated = [entry.encode() for entry in self.CURATED_VALID + self.CURATED_INVALID]
        random.shuffle(curated)
        seen = set(seeds)
        for entry in curated:
            if entry not in seen:
                seeds.append(entry)
                seen.add(entry)
        while len(seeds) < n:
            candidate = self.generate()
            if candidate in seen:
                continue
            seeds.append(candidate)
            seen.add(candidate)
        return seeds[:n]


# ─────────────────────────────────────────────────────────────────────────────
#  IPv6
# ─────────────────────────────────────────────────────────────────────────────

@SeedGenerator.register("ipv6")
class IPv6SeedGenerator(SeedGenerator):
    """Generates a mix of valid and structured-invalid IPv6 address strings."""

    BOUNDARY_GROUPS = ["0", "1", "ff", "fe", "ffff", "0001", "dead", "beef", "db8"]
    IPV4_SUFFIXES = [
        "0.0.0.0",
        "1.2.3.4",
        "13.1.68.3",
        "129.144.52.38",
        "192.0.2.1",
        "192.0.2.33",
        "255.255.255.255",
    ]
    CURATED_VALID = [
        "::",
        "::1",
        "1::",
        "1::7:8",
        "2001:db8::1",
        "2001:db8:0:1:2:3:4:5",
        "2001:db8:0:1::1",
        "1:2:3:4:5::7:8",
        "1:2:3:4::7:8",
        "1:2:3::7:8",
        "1:2::7:8",
        "fe80::1",
        "fe80::abcd:1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8::192.0.2.33",
        "::192.0.2.1",
        "::ffff:192.168.0.1",
        "1::ffff:192.168.0.1",
        "0:0:0:0:0:0:13.1.68.3",
        "0:0:0:0:0:FFFF:129.144.52.38",
        "1:2:3:4:5:6:192.168.0.1",
        "1:2:3:4:5::192.168.0.1",
        "1:2:3:4::192.168.0.1",
        "1:2::192.168.0.1",
        "1::192.168.0.1",
        "1234:5678:9abc:def0:1111:2222:3333:4444",
        "0001:0002:0003:0004:0005:0006:0007:0008",
    ]
    CURATED_INVALID = [
        "",
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:",
        "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:9",
        "1::2::3",
        "fffff::1",
        "1:2:3:4:5:6:7:gggg",
        "2001-db8::1",
        "2001:db8:::1",
        "::ffff:192.0.2.999",
        "12345::",
        ":::",
        "1:::2",
        "::::",
        "::fffff:192.0.2.33",
        "::ffff:192.0.2.999",
        "2001:db8::1::",
        "2001:db8::1:",
        "2001::db8::1",
        "fe80::abcd:1:",
        "1:2:3:4:::5:6:7:8",
        "1:2:3:::4:5:6:7:8",
        "ffff:ffff:ffff:::ffff:ffff:ffff:ffff:ffff",
        "fffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "1:2:3:4:5:6:7:8:9:a",
        "1:2:3:4:5:6:7::8",
        "1:2:3:4:5:6:7::8:9",
        # embedded IPv4 boundary: exercises IPv4_in_IPv6 with known buggy value
        "::255.255.255.255",
        "::ffff:255.255.255.255",
        "0:0:0:0:0:0:255.255.255.255",
        "1:2:3:4:5:6:255.255.255.255",
        "1:2:3:4:5::255.255.255.255",
        # triple-colon with exactly 7 hex groups → hits "Invalid token(':::')" path
        "a:b:c:d:e:f:::1",
        "1:2:3:4:5:6:::7",
        "ffff:ffff:ffff:ffff:ffff:ffff:::ffff",
        # triple-colon with few groups → hits "Incorrect token length" path
        "a:b:::c",
        "1:::2:3:4",
        # 5-char hex in mid/tail positions (not just leading)
        "1:2:3:4:fffff:6:7:8",
        "1:2:3:4:5:6:7:fffff",
        "::fffff",
    ]

    VALID_TEMPLATES = [
        "{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}",   # full 8-group
        "{g}::{g}",                             # double-colon middle
        "::{g}",                                # leading double-colon
        "{g}::",                                # trailing double-colon
        "::",                                   # all-zeros compressed
        "{g}::{g}:{g}:{g}",
        "{g}:{g}::{g}:{g}",
        "{g}:{g}:{g}::{g}",
        "::ffff:{ipv4}",
        "{g}::ffff:{ipv4}",
        "{g}:{g}:{g}:{g}:{g}:{g}:{ipv4}",
        "{g}:{g}:{g}:{g}:{g}::{ipv4}",
        "{g}:{g}:{g}:{g}::{ipv4}",
        "{g}:{g}::{ipv4}",
        "{g}::{ipv4}",
    ]

    # Invalid structural forms — wrong group count, bad separators, overlong groups
    INVALID_TEMPLATES = [
        "{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}", # too many groups
        "{g}:{g}:{g}:{g}:{g}:{g}:{g}",          # too few groups, no ::
        "{g}::{g}::{g}",                          # multiple double-colons
        "{g}:::{g}",                              # triple-colon defect
        "{g}:{g}:{g}:{g}:::{g}:{g}:{g}:{g}",      # triple-colon while keeping 8+ tokens
        "{g}:{g}:{g}:::{g}:{g}:{g}:{g}:{g}",      # shifted triple-colon full-width defect
        "::{g}::{g}",                             # leading double-colon plus extra compression
        "{g}::{g}:{g}:{g}:{g}:{g}:{g}:{g}",      # compressed plus too many groups
        "{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}:",      # trailing colon
        ":{g}:{g}:{g}:{g}:{g}:{g}:{g}:{g}",      # leading single colon
        "{g5}:{g}:{g}:{g}:{g}:{g}:{g}:{g}",      # 5-hex-digit group (overlong)
        "{g}",                                     # single group
        "",                                        # empty string
    ]

    def _group(self) -> str:
        return random.choice(self.BOUNDARY_GROUPS)

    def _group5(self) -> str:
        return random.choice(["fffff", "10000", "1ffff", "abcde"])

    def _ipv4_suffix(self) -> str:
        return random.choice(self.IPV4_SUFFIXES)

    def _compressed_valid_variant(self) -> str:
        return random.choice([
            "::",
            "::1",
            f"{self._group()}::",
            f"{self._group()}::{self._group()}:{self._group()}",
            f"{self._group()}:{self._group()}::{self._group()}:{self._group()}",
            f"{self._group()}:{self._group()}:{self._group()}::{self._group()}",
        ])

    def _embedded_ipv4_valid_variant(self) -> str:
        ipv4 = self._ipv4_suffix()
        return random.choice([
            f"::{ipv4}",
            f"::ffff:{ipv4}",
            f"{self._group()}::ffff:{ipv4}",
            f"{self._group()}:{self._group()}:{self._group()}:{self._group()}:{self._group()}:{self._group()}:{ipv4}",
            f"{self._group()}:{self._group()}:{self._group()}:{self._group()}:{self._group()}::{ipv4}",
            f"{self._group()}:{self._group()}:{self._group()}:{self._group()}::{ipv4}",
            f"{self._group()}:{self._group()}::{ipv4}",
            f"{self._group()}::{ipv4}",
        ])

    def generate(self) -> bytes:
        if random.random() < 0.4:
            tmpl = random.choice(self.INVALID_TEMPLATES)
            addr = tmpl.format(g=self._group(), g5=self._group5())
        else:
            variant_roll = random.random()
            if variant_roll < 0.22:
                addr = self._compressed_valid_variant()
            elif variant_roll < 0.42:
                addr = self._embedded_ipv4_valid_variant()
            else:
                tmpl = random.choice(self.VALID_TEMPLATES)
                addr = tmpl.format(g=self._group(), ipv4=self._ipv4_suffix())
            # Occasionally append a mixed IPv4 suffix
            if random.random() < 0.15:
                ipv4_suffix = ".".join(str(random.randint(0, 255)) for _ in range(4))
                parts = addr.rsplit(":", 1)
                addr = parts[0] + ":" + ipv4_suffix
            # Keep near-valid malformed compressed forms in circulation.
            elif random.random() < 0.2:
                addr = random.choice([
                    addr.replace("::", ":::", 1) if "::" in addr else addr + "::",
                    f"{addr}:",
                    f"{addr}::",
                    f"{addr}:{self._group()}",
                    "::ffff:192.0.2.999",
                    "2001:db8::192.0.2.999",
                ])
        return addr.encode()

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = load_seed_inputs(self._target_name(), allow_bootstrap=False)
        curated = [entry.encode() for entry in self.CURATED_VALID + self.CURATED_INVALID]
        random.shuffle(curated)
        seen = set(seeds)
        for entry in curated:
            if entry not in seen:
                seeds.append(entry)
                seen.add(entry)
        while len(seeds) < n:
            candidate = self.generate()
            if candidate in seen:
                continue
            seeds.append(candidate)
            seen.add(candidate)
        return seeds[:n]


@SeedGenerator.register("json")
@SeedGenerator.register("json_direct")
@SeedGenerator.register("cjson")
class JSONSeedGenerator(SeedGenerator):
    """Generates a mix of valid and structured-invalid JSON seeds.

    Valid seeds cover all value types, nesting depths, boundary numbers,
    unicode strings, and edge cases.  Invalid seeds cover common structural
    errors (bad syntax, wrong types, truncated input) that exercise the
    parser's error-handling paths directly.
    """

    BOUNDARY_INTS  = [0, 1, -1, 127, -128, 255, 256, -256,
                      32767, -32768, 65535, 2**31 - 1, -(2**31),
                      2**53, -(2**53), 2**63 - 1]
    BOUNDARY_FLOATS = [0.0, 1.0, -1.0, 0.1, -0.1, 1e10, -1e10,
                       1.7976931348623157e+308, 5e-324, float("inf")]
    UNICODE_STRINGS = [
        "", " ", "\t", "\n", "hello", "Hello, World!",
        "café", "日本語", "中文", "한국어", "العربية",
        "emoji: 😀🎉", "\u0000", "\uffff",
        "line1\nline2", "tab\there", "quote\"here",
        "backslash\\here", "null\x00byte",
        "a" * 64, "a" * 256,
    ]

    def _random_string(self) -> str:
        return random.choice(self.UNICODE_STRINGS)

    def _random_scalar(self) -> object:
        choice = random.randint(0, 4)
        if choice == 0:
            return random.choice(self.BOUNDARY_INTS)
        if choice == 1:
            f = random.choice(self.BOUNDARY_FLOATS)
            if f != float("inf"):
                return f
            return 1e308
        if choice == 2:
            return self._random_string()
        if choice == 3:
            return random.choice([True, False])
        return None

    def _random_value(self, depth: int = 0) -> object:
        if depth >= 4:
            return self._random_scalar()
        choice = random.randint(0, 5)
        if choice == 0:
            return {}
        if choice == 1:
            return []
        if choice == 2:
            n = random.choice([1, 2, 3, 5])
            return {self._random_string(): self._random_value(depth + 1) for _ in range(n)}
        if choice == 3:
            n = random.choice([1, 2, 3, 5])
            return [self._random_value(depth + 1) for _ in range(n)]
        return self._random_scalar()

    def _random_top_level(self) -> object:
        """Top-level JSON must be any valid value per RFC 8259."""
        kind = random.choice([
            "object", "object", "object",   # weighted toward objects
            "array", "array",
            "string", "int", "float", "bool", "null",
        ])
        if kind == "object":
            n = random.choice([0, 1, 2, 3, 5])
            return {self._random_string(): self._random_value() for _ in range(n)}
        if kind == "array":
            n = random.choice([0, 1, 2, 3, 5])
            return [self._random_value() for _ in range(n)]
        if kind == "string":
            return self._random_string()
        if kind == "int":
            return random.choice(self.BOUNDARY_INTS)
        if kind == "float":
            f = random.choice(self.BOUNDARY_FLOATS)
            return f if f != float("inf") else 1e308
        if kind == "bool":
            return random.choice([True, False])
        return None

    # Structurally invalid JSON strings that exercise parser error paths
    INVALID_SEEDS = [
        b"{",                        # unclosed object
        b"[",                        # unclosed array
        b'{"a": 1,}',               # trailing comma in object
        b'[1, 2, 3,]',              # trailing comma in array
        b"{'a': 1}",                # single-quoted keys
        b'{a: 1}',                  # unquoted key
        b'{"a": undefined}',        # undefined value
        b'{"a": .5}',               # leading-dot float
        b'{"a": 1 "b": 2}',        # missing comma
        b'[1, 2',                   # truncated array
        b'"\x00"',                  # null byte in string
        b"",                         # empty input
        b"NaN",                      # bare NaN
        b"Infinity",                 # bare Infinity
        b"\xff\xfe{}",              # BOM prefix
    ]

    TARGETED_VALID_SEEDS = [
        b'"\\t"',
        b'"\\b"',
        b'"\\f"',
        b'{"key":"\\t"}',
        b'{"key":"\\b"}',
        b'{"key":"\\f"}',
        b'["\\t"]',
        b'["\\b"]',
        b'["\\f"]',
    ]

    TARGETED_INVALID_SEEDS = [
        b'"\\u1"',
        b'"\\u12"',
        b'"\\u123"',
        b'"\\u12345"',
        b'"\\uABCDE"',
        b'{"hex":"\\u1"}',
        b'{"hex":"\\u12345"}',
        b'["\\u12"]',
        b'["\\uABCDE"]',
    ]

    @staticmethod
    def _nested_array_seed(depth: int, leaf: str = "0") -> bytes:
        return ("[" * depth + leaf + "]" * depth).encode("utf-8")

    @staticmethod
    def _nested_object_seed(depth: int, leaf: str = "0") -> bytes:
        return ('{"a":' * depth + leaf + "}" * depth).encode("utf-8")

    @staticmethod
    def _huge_integer_seed(length: int, *, wrapped: bool = False) -> bytes:
        digits = "9" * max(4301, length)
        if wrapped:
            return ('{"n":' + digits + "}").encode("utf-8")
        return digits.encode("utf-8")

    def generate(self) -> bytes:
        import json as _json
        selector = random.random()
        if selector < 0.18:
            return random.choice(self.TARGETED_VALID_SEEDS)
        if selector < 0.36:
            return random.choice(self.TARGETED_INVALID_SEEDS)
        if selector < 0.46:
            return random.choice([
                self._nested_array_seed(random.choice([32, 64, 128, 256, 512])),
                self._nested_object_seed(random.choice([24, 48, 96, 192])),
                self._huge_integer_seed(random.choice([4301, 5000, 7000])),
                self._huge_integer_seed(random.choice([4301, 5000]), wrapped=True),
            ])
        if selector < 0.66:
            return random.choice(self.INVALID_SEEDS)
        try:
            value = self._random_top_level()
            return _json.dumps(value, ensure_ascii=False).encode("utf-8")
        except (ValueError, OverflowError):
            return b"{}"

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        seeds = load_seed_inputs(self._target_name(), allow_bootstrap=False)
        seen = set(seeds)

        deterministic = [
            *self.TARGETED_VALID_SEEDS,
            *self.TARGETED_INVALID_SEEDS,
            self._nested_array_seed(64),
            self._nested_array_seed(256),
            self._nested_array_seed(1200),
            self._nested_object_seed(64),
            self._nested_object_seed(256),
            self._huge_integer_seed(4301),
            self._huge_integer_seed(5000),
            self._huge_integer_seed(4301, wrapped=True),
        ]
        for seed in deterministic:
            if seed not in seen:
                seen.add(seed)
                seeds.append(seed)

        while len(seeds) < n:
            candidate = self.generate()
            if candidate not in seen:
                seen.add(candidate)
                seeds.append(candidate)
        return seeds[:n]


@SeedGenerator.register("cidrize")
class CidrizeSeedGenerator(SeedGenerator):
    """Generates a mix of valid and structured-invalid IP strings for the cidrize target."""

    IPV4_OCTETS = [0, 1, 2, 8, 10, 24, 26, 64, 80, 85, 127, 170, 175, 192, 255]
    IPV6_GROUPS = ["0", "1", "2", "5", "8", "64", "db8", "ffff", "abcd", "dead"]
    IPV4_PREFIXES = [0, 8, 16, 24, 26, 31, 32]
    IPV6_PREFIXES = [0, 32, 48, 64, 96, 112, 128]
    HOST_LABELS = ["edge", "alpha", "svc", "mail", "node", "api", "cache", "demo"]
    HOST_TLDS = ["ai", "io", "dev", "cloud", "museum", "travel", "local"]

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

    def _hostname(self, tld: str | None = None) -> str:
        labels = [random.choice(self.HOST_LABELS)]
        if random.random() < 0.4:
            labels.append(random.choice(self.HOST_LABELS))
        suffix = tld or random.choice(self.HOST_TLDS)
        labels.append(suffix)
        return ".".join(labels)

    def _invalid(self) -> str:
        choice = random.choice([
            "bad_cidr_prefix",
            "descending_range",
            "bad_octet",
            "missing_part",
            "wrong_separator",
            "separator_repeat",
            "stacked_prefix",
            "wildcard_repeat",
            "truncated_range_start",
            "adjacent_mask",
            "hostname_tld_edge",
        ])
        if choice == "bad_cidr_prefix":
            return f"{self._ipv4()}/{random.choice([33, 64, 128, 999])}"
        if choice == "descending_range":
            # end numerically before start — always invalid
            a, b = self._ipv4(), self._ipv4()
            return f"{b}-{a}" if a < b else f"{a}-{b[:-1]}0"
        if choice == "bad_octet":
            return f"{random.choice([256, 300, 999])}.{self._ipv4()}"
        if choice == "missing_part":
            return random.choice(["", "/24", "-", f"{self._ipv4()}/", f"{self._ipv4()}-"])
        if choice == "separator_repeat":
            base = ".".join(str(random.choice(self.IPV4_OCTETS)) for _ in range(3))
            start = random.choice([1, 8, 80, 170, 200])
            end = random.choice([5, 15, 85, 175, 254])
            return f"{base}.{start}{random.choice(['--', '---'])}{end}"
        if choice == "stacked_prefix":
            return f"{self._ipv4()}/{random.choice(self.IPV4_PREFIXES)}/{random.choice([1, 24, 64, 999])}"
        if choice == "wildcard_repeat":
            base = ".".join(str(random.choice(self.IPV4_OCTETS)) for _ in range(3))
            return f"{base}.{random.choice(['**', '***'])}"
        if choice == "truncated_range_start":
            return f"{'.'.join(str(random.choice(self.IPV4_OCTETS)) for _ in range(3))}.-{self._ipv4()}"
        if choice == "adjacent_mask":
            return f"{self._ipv4()} {random.choice(['255.255.255.0', '255.255.0.0', '255.0.255.0'])}"
        if choice == "hostname_tld_edge":
            return random.choice([
                self._hostname("a"),
                self._hostname("ab"),
                self._hostname("abcde"),
                self._hostname("museum"),
            ])
        # wrong_separator
        return self._ipv4().replace(".", random.choice([",", ":", " "]))

    def generate(self) -> bytes:
        if random.random() < 0.3:
            return self._invalid().encode()
        choice = random.choice([
            "ipv4",
            "ipv4_cidr",
            "ipv4_range",
            "ipv4_partial_range",
            "ipv4_wildcard",
            "hostname",
            "ipv6",
            "ipv6_cidr",
            "ipv6_range",
        ])
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
            value = random.choice([
                f"{base}.[{random.choice(['0123', '5678', '89'])}]",
                f"{base}.{random.choice(['1', '8', '9'])}[0-5]",
            ])
        elif choice == "hostname":
            value = self._hostname(random.choice(["ai", "io", "dev", "cloud", "museum"]))
        elif choice == "ipv6":
            value = self._ipv6()
        elif choice == "ipv6_cidr":
            value = f"{self._ipv6()}/{random.choice(self.IPV6_PREFIXES)}"
        else:
            value = f"{self._ipv6()}-{self._ipv6()}"
        return value.encode()
