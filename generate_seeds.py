"""
generate_seeds.py — Programmatically generate IPv4 and IPv6 seed corpora.

Usage:
    python generate_seeds.py           # regenerate both files
    python generate_seeds.py --ipv4    # IPv4 only
    python generate_seeds.py --ipv6    # IPv6 only
    python generate_seeds.py --dry-run # print without writing
"""

import argparse
import os


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

# Original README seeds — kept first for comparability with prior results
_IPV4_README = [
    "0.0.0.0",
    "00.01.002.000",
    "1.2.3.4",
    "09.10.99.100",
    "127.0.0.1",
    "192.168.001.001",
    "249.250.251.252",
    "255.255.255.255",
]


def gen_ipv4_seeds() -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    def add(s: str) -> None:
        if s not in seen:
            seen.add(s)
            result.append(s)

    # 1. README originals (always first)
    for s in _IPV4_README:
        add(s)

    boundary = [0, 1, 127, 128, 254, 255]

    # 2. All-same boundary octets  (0.0.0.0 already in README)
    for v in boundary:
        add(f"{v}.{v}.{v}.{v}")

    # 3. One-hot boundary: vary one octet, others at 0
    for pos in range(4):
        for v in boundary:
            octets = [0, 0, 0, 0]
            octets[pos] = v
            add(".".join(str(o) for o in octets))

    # 4. One-hot boundary: vary one octet, others at 255
    for pos in range(4):
        for v in boundary:
            octets = [255, 255, 255, 255]
            octets[pos] = v
            add(".".join(str(o) for o in octets))

    # 5. Ascending / descending structural variety
    for s in ["1.2.3.4", "255.254.253.252", "10.20.30.40", "100.101.102.103"]:
        add(s)

    # 6. Leading-zero forms
    for s in [
        "00.00.00.00",
        "001.002.003.004",
        "010.020.030.040",
        "000.000.000.000",
        "001.001.001.001",
    ]:
        add(s)

    # 7. Mixed 1-digit / 3-digit lengths
    for s in [
        "1.255.1.255",
        "255.1.255.1",
        "128.0.128.0",
        "0.128.0.128",
        "1.1.1.1",
    ]:
        add(s)

    # 8. Private / special RFC-defined ranges
    for s in [
        "10.0.0.0",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.0",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.0.1",
        "192.168.255.255",
        "169.254.0.0",
        "169.254.1.1",
        "224.0.0.0",
        "224.0.0.1",
        "239.255.255.255",
        "100.64.0.0",
        "198.51.100.0",
        "203.0.113.0",
    ]:
        add(s)

    # 9. Near-boundary combinations (mixed boundary values across octets)
    near_boundary_combos = [
        (0, 0, 0, 1),
        (0, 0, 1, 0),
        (0, 1, 0, 0),
        (1, 0, 0, 0),
        (255, 255, 255, 254),
        (255, 255, 254, 255),
        (255, 254, 255, 255),
        (254, 255, 255, 255),
        (127, 255, 255, 255),
        (128, 0, 0, 1),
    ]
    for combo in near_boundary_combos:
        add(".".join(str(v) for v in combo))

    return result


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------

# Original README seeds — kept first
_IPV6_README = [
    "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "2001:db8:0:0:0:0:192.0.2.33",
    "2001:db8::",
    "2001:db8::1",
    "2001:db8::192.0.2.33",
    "2001:db8::1:2",
    "2001:db8::1:192.0.2.33",
    "2001:db8::1:2:3",
    "2001:db8::1:2:192.0.2.33",
    "2001:db8::1:2:3:4",
    "2001:db8::1:2:3:192.0.2.33",
    "2001:db8::1:2:3:4:5",
    "2001::1:2:3:4:5:6",
    "::192.0.2.33",
]


def gen_ipv6_seeds() -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    def add(s: str) -> None:
        if s not in seen:
            seen.add(s)
            result.append(s)

    # 1. README originals (always first)
    for s in _IPV6_README:
        add(s)

    # 2. Loopback / all-zeros
    for s in ["::1", "::", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1"]:
        add(s)

    # 3. Full 8-group, no compression, no leading zeros
    add("1:2:3:4:5:6:7:8")
    add("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    add("a:b:c:d:e:f:0:1")

    # 4. Full 8-group zero-padded to 4 hex digits
    add("0001:0002:0003:0004:0005:0006:0007:0008")
    add("ffff:0000:ffff:0000:ffff:0000:ffff:0000")

    # 5. :: at every possible position (groups 0..7)
    #    Position k means k groups before :: and (7-k) groups after
    #    Use groups 1..7 as the non-compressed values
    groups = ["1", "2", "3", "4", "5", "6", "7"]
    for k in range(8):
        before = groups[:k]
        after = groups[k : k + (7 - k)]
        s = ":".join(before) + "::" + ":".join(after)
        # normalise double leading/trailing colons
        add(s)

    # 6. Link-local / multicast well-known addresses
    for s in [
        "fe80::1",
        "fe80::1%eth0",  # with zone id — parser may or may not accept
        "fe80:0:0:0:0:0:0:1",
        "ff02::1",
        "ff02::2",
        "ff02::fb",
        "ff01::1",
    ]:
        add(s)

    # 7. IPv4-mapped / IPv4-compatible (varying group depths before IPv4 suffix)
    ipv4_suffix = "192.0.2.1"
    for s in [
        f"::{ipv4_suffix}",
        f"::ffff:{ipv4_suffix}",
        f"0:0:0:0:0:ffff:{ipv4_suffix}",
        f"64:ff9b::{ipv4_suffix}",
        f"1::{ipv4_suffix}",
        f"1:2::{ipv4_suffix}",
        f"1:2:3::{ipv4_suffix}",
        f"1:2:3:4::{ipv4_suffix}",
        f"1:2:3:4:5::{ipv4_suffix}",
    ]:
        add(s)

    # 8. Globally routable / documentation prefixes
    for s in [
        "2001:db8:1:2:3:4:5:6",
        "2001:db8:dead:beef::",
        "2001:db8:dead:beef::1",
        "2001:4860:4860::8888",   # Google DNS
        "2606:4700:4700::1111",   # Cloudflare DNS
        "2620:fe::fe",            # PCH DNS
        "fd00::1",                # ULA
        "fc00::1",                # ULA
    ]:
        add(s)

    # 9. Compressed zeros at various positions within a longer address
    for s in [
        "2001:db8::ff00:42:8329",
        "2001:db8:0:1::1",
        "2001:db8:0:0:1::1",
        "2001:0:0:1::1",
        "::1:0:0:1",
    ]:
        add(s)

    return result


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def write_seeds(seeds: list[str], path: str) -> None:
    """Write deduplicated seeds (preserving order) to *path*."""
    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    deduped: list[str] = []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            deduped.append(s)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(deduped) + "\n")
    print(f"Wrote {len(deduped)} seeds -> {path}")


# ---------------------------------------------------------------------------
# Main / CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate IPv4/IPv6 seed corpora.")
    parser.add_argument("--ipv4", action="store_true", help="Generate IPv4 seeds only")
    parser.add_argument("--ipv6", action="store_true", help="Generate IPv6 seeds only")
    parser.add_argument(
        "--dry-run", action="store_true", help="Print seeds without writing files"
    )
    args = parser.parse_args()

    # Default: both
    do_ipv4 = args.ipv4 or not (args.ipv4 or args.ipv6)
    do_ipv6 = args.ipv6 or not (args.ipv4 or args.ipv6)

    base = os.path.join(os.path.dirname(__file__), "corpus")

    if do_ipv4:
        seeds = gen_ipv4_seeds()
        print(f"\n--- IPv4 seeds ({len(seeds)} total) ---")
        for s in seeds:
            print(f"  {s}")
        if not args.dry_run:
            write_seeds(seeds, os.path.join(base, "ipv4_seeds.txt"))

    if do_ipv6:
        seeds = gen_ipv6_seeds()
        print(f"\n--- IPv6 seeds ({len(seeds)} total) ---")
        for s in seeds:
            print(f"  {s}")
        if not args.dry_run:
            write_seeds(seeds, os.path.join(base, "ipv6_seeds.txt"))


if __name__ == "__main__":
    main()
