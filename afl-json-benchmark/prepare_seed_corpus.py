from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE_SEEDS = ROOT / "corpus_src" / "json_seeds.txt"
FORMAT_CONFIG = ROOT / "config" / "json_format.json"
OUT_DIR = ROOT / "afl_in"


def load_seed_lines() -> list[bytes]:
    seeds: list[bytes] = []
    seen: set[bytes] = set()

    if FORMAT_CONFIG.exists():
        config = json.loads(FORMAT_CONFIG.read_text(encoding="utf-8"))
        for example in config.get("valid_examples", []):
            encoded = str(example).encode("utf-8")
            if encoded not in seen:
                seeds.append(encoded)
                seen.add(encoded)

    if SOURCE_SEEDS.exists():
        for line in SOURCE_SEEDS.read_text(encoding="utf-8").splitlines():
            candidate = line.strip().encode("utf-8")
            if not candidate or candidate in seen:
                continue
            seeds.append(candidate)
            seen.add(candidate)
    return seeds


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for existing in OUT_DIR.glob("*"):
        if existing.is_file():
            existing.unlink()

    seeds = load_seed_lines()
    for index, seed in enumerate(seeds):
        suffix = "json" if seed[:1] in (b"{", b"[", b"\"", b"n", b"t", b"f") else "txt"
        (OUT_DIR / f"seed_{index:03d}.{suffix}").write_bytes(seed)

    print(f"Wrote {len(seeds)} unique JSON seeds to {OUT_DIR}")


if __name__ == "__main__":
    main()
