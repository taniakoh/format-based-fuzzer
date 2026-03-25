"""
Hybrid Coverage-Guided Fuzzer — Entry Point.

Targets : IPv4 and IPv6 string-based parser binaries
Stack   : Python 3.11+, three-tier mutation engine, behavior-based coverage

Architecture (Phase 1 — no torch):
  Seed generator → Tier 1 (pass-through) → Tier 2 (semantic) →
  Tier 3 (havoc, static weights) → Executor → Coverage → Corpus

Architecture (Phase 2 — torch available):
  Same pipeline, but Tier 3 weights come from a trained DL surrogate.
  Model is loaded from models/<target>_surrogate.pt if it exists,
  trained every TRAIN_EVERY new behaviors, and saved after each training run.

Usage:
    python main.py ipv4 [--havoc-iters N] [--time-budget S] [--seed RNG]
    python main.py ipv6 [--havoc-iters N] [--time-budget S] [--seed RNG]
    python main.py all  [--havoc-iters N] [--time-budget S] [--seed RNG]

Options:
    --havoc-iters N   Havoc mutations per execution (default: 8)
    --time-budget S   Fuzzing duration in seconds (default: 86400)
    --seed RNG        RNG seed for reproducibility (default: 42)
    --seeds-n N       Initial corpus size per target (default: 100)
"""

import argparse
import random
import time

from fuzzer.corpus import Corpus
from fuzzer.coverage import CoverageAnalyzer
from fuzzer.executor import Executor, register_binary
from fuzzer.format_loader import load_format
from fuzzer.mutation.tier1_structure import StructureMutator
from fuzzer.mutation.tier2_semantic import get_mutator
from fuzzer.mutation.tier3_havoc import HavocMutator
from fuzzer.scheduler import StaticScheduler
from fuzzer.seed_generator import get_seed_generator
from evaluation.collect_metrics import MetricsCollector

# Train the surrogate every N new behaviors discovered.
# Low because each binary call is ~30 s, so corpus growth is slow.
TRAIN_EVERY = 10


def fuzz(
    target: str,
    havoc_iters: int = 8,
    time_budget_secs: int = 86400,
    seeds_n: int = 100,
) -> None:
    """Run the hybrid fuzzer against one target."""

    print(f"\n{'='*60}")
    print(f"[*] Target        : {target}")
    print(f"[*] Time budget   : {time_budget_secs}s")
    print(f"[*] Havoc iters   : {havoc_iters}")
    print(f"{'='*60}\n")

    # ── Load format config ────────────────────────────────────────────────────
    fmt = load_format(target)

    # ── Register binary paths from config if provided ─────────────────────────
    if fmt.get("binary_windows") or fmt.get("binary_linux"):
        register_binary(
            target,
            windows=fmt.get("binary_windows"),
            linux=fmt.get("binary_linux"),
        )

    # ── Seed generation ───────────────────────────────────────────────────────
    generator = get_seed_generator(target, fmt)
    corpus = Corpus()
    for seed in generator.generate_corpus(n=seeds_n):
        corpus.add(seed, priority=1.0)
    print(f"[*] Corpus loaded : {len(corpus)} seeds")

    # ── Mutation engine ───────────────────────────────────────────────────────
    tier1 = StructureMutator()  # pass-through for IP strings
    tier2 = get_mutator(target, fmt)

    # ── Scheduler: DLScheduler if torch available, else StaticScheduler ───────
    model = None
    scheduler = None
    try:
        import torch
        from dl.surrogate import CoverageSurrogate, DLScheduler
        from dl.trustworthiness import is_trustworthy
        from dl.trainer import load_checkpoint, save_checkpoint, train

        model = CoverageSurrogate()
        scheduler = DLScheduler(model, is_trustworthy, fmt)  # auto-detects CUDA
        load_checkpoint(model, target, scheduler.device)
        model.eval()
        print(f"[*] Scheduler     : DLScheduler (device={scheduler.device})")
    except ImportError:
        scheduler = StaticScheduler(fmt)
        print("[*] Scheduler     : StaticScheduler (torch not installed)")

    tier3 = HavocMutator(scheduler.get_operator_weights(b""))

    # ── Infrastructure ────────────────────────────────────────────────────────
    executor = Executor(target)
    coverage = CoverageAnalyzer()
    metrics = MetricsCollector(target)

    # Training buffer: list of (seed_bytes, [bitmap_positions_that_were_set])
    training_buffer: list[tuple[bytes, list[int]]] = []
    behaviors_since_last_train = 0

    # ── Main fuzzing loop ─────────────────────────────────────────────────────
    start = time.time()
    exec_count = 0

    while time.time() - start < time_budget_secs:
        seed = corpus.select()

        # Tier 1 — structural (pass-through for IP strings)
        mutated = tier1.mutate(seed)

        # Tier 2 — semantic IP mutations (50 % probability)
        if random.random() < 0.5:
            mutated = tier2.mutate(mutated)

        # Tier 3 — havoc with per-seed operator weights
        weights = scheduler.get_operator_weights(seed)
        tier3 = HavocMutator(weights)
        mutated = tier3.mutate(mutated, iterations=havoc_iters)

        # ── Execute ───────────────────────────────────────────────────────────
        bitmap, crashed, result = executor.run(mutated)
        exec_count += 1

        metrics.record_execution(mutated, result)

        # ── Coverage update ───────────────────────────────────────────────────
        is_new = coverage.is_interesting(bitmap)
        if is_new:
            priority = scheduler.get_seed_priority(mutated)
            corpus.add(mutated, priority=priority)
            metrics.update_coverage(coverage.edge_count)
            print(
                f"[NEW] execs={exec_count:>6} behaviors={coverage.edge_count:>4} "
                f"corpus={len(corpus):>4} input={mutated[:60]!r}"
            )

            # Accumulate training data: record which bitmap positions were set
            positions = [i for i, b in enumerate(bitmap) if b]
            training_buffer.append((mutated, positions))
            behaviors_since_last_train += 1

            # ── Incremental training ──────────────────────────────────────────
            if model is not None and behaviors_since_last_train >= TRAIN_EVERY:
                print(f"[DL] Training on {len(training_buffer)} samples...")
                loss = train(model, training_buffer, epochs=5,
                             device=scheduler.device)
                save_checkpoint(model, target)
                print(f"[DL] Training done. Loss={loss:.4f}")
                behaviors_since_last_train = 0

        elif result.is_interesting:
            bug_label = result.bug_type
            print(
                f"[{bug_label.upper():<12}] execs={exec_count:>6} "
                f"input={mutated[:60]!r}"
            )

    # ── Save final checkpoint ─────────────────────────────────────────────────
    if model is not None and training_buffer:
        print(f"[DL] Final training on {len(training_buffer)} samples...")
        loss = train(model, training_buffer, epochs=5, device=scheduler.device)
        save_checkpoint(model, target)
        print(f"[DL] Final loss={loss:.4f}")

    # ── Finalise ──────────────────────────────────────────────────────────────
    final = metrics.finalize()
    print(f"\n[*] Done. Executions: {exec_count} | "
          f"Behaviors: {final.behaviors_covered} | "
          f"Corpus size: {len(corpus)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Coverage-Guided IP Fuzzer")
    parser.add_argument(
        "target",
        help="Parser to fuzz (e.g. ipv4, ipv6, or any registered format; 'all' runs ipv4+ipv6)",
    )
    parser.add_argument("--havoc-iters", type=int, default=8,
                        help="Havoc mutations per execution (default: 8)")
    parser.add_argument("--time-budget", type=int, default=86400,
                        help="Time budget in seconds (default: 86400 = 24 h)")
    parser.add_argument("--seed", type=int, default=42,
                        help="RNG seed for reproducibility (default: 42)")
    parser.add_argument("--seeds-n", type=int, default=100,
                        help="Initial corpus size per target (default: 100)")
    args = parser.parse_args()

    random.seed(args.seed)

    targets = ["ipv4", "ipv6"] if args.target == "all" else [args.target]
    for t in targets:
        fuzz(
            target=t,
            havoc_iters=args.havoc_iters,
            time_budget_secs=args.time_budget,
            seeds_n=args.seeds_n,
        )


if __name__ == "__main__":
    main()
