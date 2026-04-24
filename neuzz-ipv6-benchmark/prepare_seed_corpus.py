from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from neuzz_text_benchmark_common import detect_workspace_target, load_seed_lines


OUT_DIR = ROOT / "neuzz_in"


def main() -> None:
    target = detect_workspace_target(ROOT)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for existing in OUT_DIR.glob("*"):
        if existing.is_file():
            existing.unlink()

    seeds = load_seed_lines(ROOT)
    for index, seed in enumerate(seeds):
        (OUT_DIR / f"seed_{index:03d}.txt").write_bytes(seed)

    max_len = max((len(seed) for seed in seeds), default=0)
    print(f"Wrote {len(seeds)} unique {target} seeds to {OUT_DIR}")
    print(f"Longest seed length: {max_len} bytes")


if __name__ == "__main__":
    main()
