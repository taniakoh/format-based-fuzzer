"""
Format-based fuzzer for IPv4 / IPv6 parser binaries.

Fuzzing approach (AFL-inspired, no semantic knowledge):
  1. Load seed corpus from corpus/<target>_seeds.txt
  2. Deterministic stage: exhaustively apply all AFL deterministic mutations
     to each seed (bit flips, byte flips, arithmetic, interesting values)
  3. Havoc stage: generate random stacked mutations for a configurable number
     of iterations

Mutations are all byte-level — no awareness of IP address format.
Bugs are classified as:
  - invalidity : ParseException caught by the parser
  - bonus      : Unexpected exception
  - CRASH      : Hard crash / non-zero exit / timeout

Results are saved to results/<target>/ :
  - crashes/      : one .txt file per unique crashing input
  - bugs.jsonl    : JSONL log of every interesting result
  - stats.txt     : final statistics summary

Usage:
    python fuzzer.py ipv4 [--havoc-iters N] [--seed SEED]
    python fuzzer.py ipv6 [--havoc-iters N] [--seed SEED]
    python fuzzer.py all  [--havoc-iters N] [--seed SEED]

Options:
    --havoc-iters N   Number of havoc mutations per seed (default: 500)
    --seed SEED       RNG seed for reproducibility (default: 42)
    --det             Run deterministic stage only (skip havoc)
    --havoc-only      Run havoc stage only (skip deterministic)
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

from mutations import deterministic_mutations, havoc
from test_driver import BugType, RunResult, run

# ── Paths ─────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
CORPUS_DIR = _HERE / "corpus"
RESULTS_DIR = _HERE / "results"


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_seeds(target: str) -> list[str]:
    seed_file = CORPUS_DIR / f"{target}_seeds.txt"
    if not seed_file.exists():
        print(f"[!] Seed file not found: {seed_file}")
        return []
    seeds = [line.strip() for line in seed_file.read_text().splitlines() if line.strip()]
    print(f"[*] Loaded {len(seeds)} seeds for {target}")
    return seeds


def setup_results_dir(target: str) -> Path:
    out = RESULTS_DIR / target
    (out / "crashes").mkdir(parents=True, exist_ok=True)
    return out


def decode_safe(data: bytearray) -> str:
    """Decode bytearray to string, replacing undecodable bytes."""
    return data.decode("utf-8", errors="replace")


def save_result(result: RunResult, out_dir: Path, idx: int) -> None:
    """Append result to bugs.jsonl; if crash, also save input file."""
    entry = {
        "idx": idx,
        "input": result.input_str,
        "bug_type": result.bug_type,
        "exit_code": result.exit_code,
        "exception": result.exception_msg,
    }
    with open(out_dir / "bugs.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    if result.is_crash:
        crash_path = out_dir / "crashes" / f"crash_{idx:06d}.txt"
        crash_path.write_text(result.input_str, encoding="utf-8", errors="replace")


# ── Fuzzer core ───────────────────────────────────────────────────────────────

class Fuzzer:
    def __init__(self, target: str, havoc_iters: int = 20, rng_seed: int = 42):
        self.target = target
        self.havoc_iters = havoc_iters
        self.rng_seed = rng_seed
        self.out_dir = setup_results_dir(target)
        self.seeds = load_seeds(target)

        # Statistics
        self.total_inputs = 0
        self.bug_counts: dict[str, int] = defaultdict(int)
        self.unique_exceptions: set[str] = set()
        self.start_time = 0.0

    # ── Execution ─────────────────────────────────────────────────────────────

    def _test(self, input_bytes: bytearray) -> RunResult:
        input_str = decode_safe(input_bytes)
        result = run(self.target, input_str)
        self.total_inputs += 1

        if result.is_interesting:
            self.bug_counts[result.bug_type] += 1
            is_new = result.exception_msg not in self.unique_exceptions
            if result.exception_msg:
                self.unique_exceptions.add(result.exception_msg)
            save_result(result, self.out_dir, self.total_inputs)
            self._print_finding(result, new=is_new)

        return result

    def _print_finding(self, result: RunResult, new: bool) -> None:
        tag = "[NEW] " if new else "      "
        elapsed = time.time() - self.start_time
        # ASCII-safe repr so Windows cp1252 console never chokes on unicode
        safe_input = repr(result.input_str).encode("ascii", errors="backslashreplace").decode("ascii")
        safe_exc = repr(result.exception_msg[:60]).encode("ascii", errors="backslashreplace").decode("ascii")
        print(f"  {tag}{result.bug_type:12s} | input={safe_input:42s} | {safe_exc} | t={elapsed:.1f}s")

    # ── Stages ────────────────────────────────────────────────────────────────

    def run_deterministic(self) -> None:
        print(f"\n[*] === Deterministic stage ({self.target}) ===")
        for seed_str in self.seeds:
            data = bytearray(seed_str.encode("utf-8"))
            variants = deterministic_mutations(data)
            print(f"    Seed {seed_str!r:30s}  -> {len(variants)} variants")
            for v in variants:
                self._test(v)
        print(f"    Done. Total inputs so far: {self.total_inputs}")

    def run_havoc(self) -> None:
        print(f"\n[*] === Havoc stage ({self.target}, {self.havoc_iters} iters/seed) ===")
        seed_offset = self.rng_seed
        for seed_str in self.seeds:
            data = bytearray(seed_str.encode("utf-8"))
            variants = havoc(data, count=self.havoc_iters, seed=seed_offset)
            seed_offset += 1
            print(f"    Seed {seed_str!r:30s}  -> {len(variants)} havoc variants")
            for v in variants:
                self._test(v)
        print(f"    Done. Total inputs so far: {self.total_inputs}")

    # ── Summary ───────────────────────────────────────────────────────────────

    def print_summary(self) -> None:
        elapsed = time.time() - self.start_time
        print(f"\n{'=' * 60}")
        print(f"  Fuzzing summary for {self.target}")
        print(f"{'=' * 60}")
        print(f"  Total inputs tested : {self.total_inputs}")
        print(f"  Elapsed time        : {elapsed:.1f}s")
        print(f"  Inputs / second     : {self.total_inputs / max(elapsed, 0.001):.1f}")
        print(f"  Bug counts:")
        for btype, count in sorted(self.bug_counts.items()):
            print(f"    {btype:16s}: {count}")
        print(f"  Unique exceptions   : {len(self.unique_exceptions)}")
        print(f"  Results saved to    : {self.out_dir}")
        print(f"{'=' * 60}")

        stats_path = self.out_dir / "stats.txt"
        with open(stats_path, "w", encoding="utf-8") as f:
            f.write(f"target          : {self.target}\n")
            f.write(f"total_inputs    : {self.total_inputs}\n")
            f.write(f"elapsed_seconds : {elapsed:.1f}\n")
            f.write(f"inputs_per_sec  : {self.total_inputs / max(elapsed, 0.001):.1f}\n")
            f.write(f"bug_counts      : {dict(self.bug_counts)}\n")
            f.write(f"unique_exceptions: {len(self.unique_exceptions)}\n")

    # ── Entry point ───────────────────────────────────────────────────────────

    def fuzz(self, det: bool = True, havoc_stage: bool = True) -> None:
        self.start_time = time.time()
        print(f"\n[*] Starting fuzzer for target: {self.target}")
        print(f"    Output dir  : {self.out_dir}")
        print(f"    RNG seed    : {self.rng_seed}")
        print(f"    Havoc iters : {self.havoc_iters} per seed")

        if det:
            self.run_deterministic()
        if havoc_stage:
            self.run_havoc()

        self.print_summary()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AFL-style byte-level fuzzer for IPv4/IPv6 parser binaries"
    )
    parser.add_argument(
        "target",
        choices=["ipv4", "ipv6", "all"],
        help="Which parser binary to fuzz",
    )
    parser.add_argument(
        "--havoc-iters",
        type=int,
        default=20,
        metavar="N",
        help="Number of havoc mutations per seed (default: 20). "
             "NOTE: each binary invocation takes ~25 s on Windows "
             "(PyInstaller bundle). Keep N small for interactive use.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        metavar="SEED",
        help="RNG seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--det",
        action="store_true",
        default=False,
        help="Run deterministic stage only",
    )
    parser.add_argument(
        "--havoc-only",
        action="store_true",
        default=False,
        help="Run havoc stage only",
    )
    args = parser.parse_args()

    run_det = not args.havoc_only
    run_havoc = not args.det

    targets = ["ipv4", "ipv6"] if args.target == "all" else [args.target]
    for t in targets:
        f = Fuzzer(t, havoc_iters=args.havoc_iters, rng_seed=args.seed)
        f.fuzz(det=run_det, havoc_stage=run_havoc)


if __name__ == "__main__":
    main()
