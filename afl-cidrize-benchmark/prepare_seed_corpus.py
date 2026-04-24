from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FORMAT_CONFIG = ROOT / "config" / "cidrize_format.json"
OUT_DIR = ROOT / "afl_in"

CURATED_INVALID = [
    "",
    "192.0.2.0 255.255.255.0",
    "192.0.2.80-",
    "-192.0.2.85",
    "192.0.2.999",
    "192.0.2.8[0-999]",
    "192.0.2.[56-]",
    "2001:db8::1-",
    "2001:::1",
    "1.2.3.4/999",
    "not-an-ip",
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

    print(f"Wrote {len(seeds)} unique cidrize seeds to {OUT_DIR}")


if __name__ == "__main__":
    main()
