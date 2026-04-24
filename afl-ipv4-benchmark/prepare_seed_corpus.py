from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FORMAT_CONFIG = ROOT / "config" / "ipv4_format.json"
OUT_DIR = ROOT / "afl_in"

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


def main() -> None:
    seeds: list[bytes] = []
    seen: set[bytes] = set()

    if FORMAT_CONFIG.exists():
        config = json.loads(FORMAT_CONFIG.read_text(encoding="utf-8"))
        for example in config.get("valid_examples", []):
            encoded = str(example).encode("utf-8")
            if encoded not in seen:
                seeds.append(encoded)
                seen.add(encoded)

    for example in CURATED_INVALID:
        encoded = example.encode("utf-8")
        if encoded not in seen:
            seeds.append(encoded)
            seen.add(encoded)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for existing in OUT_DIR.glob("*"):
        if existing.is_file():
            existing.unlink()

    for index, seed in enumerate(seeds):
        (OUT_DIR / f"seed_{index:03d}.txt").write_bytes(seed)

    print(f"Wrote {len(seeds)} unique IPv4 seeds to {OUT_DIR}")


if __name__ == "__main__":
    main()
