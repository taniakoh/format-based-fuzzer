"""
Hybrid Coverage-Guided Fuzzer - Entry Point.

Targets : IPv4 and IPv6 string-based parser binaries
Stack   : Python 3.11+, three-tier mutation engine, behavior-based coverage

Architecture (Phase 1 - no torch):
  Seed generator -> Tier 1 (pass-through) -> Tier 2 (semantic) ->
  Tier 3 (havoc, static weights) -> Executor -> Coverage -> Corpus

Architecture (Phase 2 - torch available):
  Same pipeline, but Tier 3 uses a hybrid scheduler that blends static
  weights with DL guidance only when the model has earned trust.
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

from evaluation.collect_metrics import MetricsCollector
from fuzzer.corpus import Corpus
from fuzzer.coverage import CoverageAnalyzer
from fuzzer.executor import Executor, register_binary
from fuzzer.format_loader import load_format
from fuzzer.mutation.tier1_structure import StructureMutator
from fuzzer.mutation.tier2_semantic import get_mutator
from fuzzer.mutation.tier3_havoc import HavocMutator
from fuzzer.scheduler import StaticScheduler
from fuzzer.seed_generator import get_seed_generator

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

    print(f"\n{'=' * 60}")
    print(f"[*] Target        : {target}")
    print(f"[*] Time budget   : {time_budget_secs}s")
    print(f"[*] Havoc iters   : {havoc_iters}")
    print(f"{'=' * 60}\n")

    fmt = load_format(target)

    if fmt.get("binary_windows") or fmt.get("binary_linux"):
        register_binary(
            target,
            windows=fmt.get("binary_windows"),
            linux=fmt.get("binary_linux"),
        )

    generator = get_seed_generator(target, fmt)
    corpus = Corpus()
    for seed in generator.generate_corpus(n=seeds_n):
        corpus.add(seed, priority=1.0)
    print(f"[*] Corpus loaded : {len(corpus)} seeds")

    tier1 = StructureMutator()
    tier2 = get_mutator(target, fmt)

    model = None
    scheduler = None
    try:
        import torch
        from dl.surrogate import CoverageSurrogate, DLScheduler
        from dl.trainer import load_checkpoint, save_checkpoint, train
        from dl.trustworthiness import is_trustworthy

        model = CoverageSurrogate()
        model._optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        scheduler = DLScheduler(model, is_trustworthy, fmt)
        checkpoint_state = load_checkpoint(model, target, scheduler.device)
        scheduler.load_runtime_metadata(checkpoint_state.get("metadata"))
        model.eval()
        print(f"[*] Scheduler     : Hybrid DLScheduler (device={scheduler.device})")
    except ImportError:
        scheduler = StaticScheduler(fmt)
        print("[*] Scheduler     : StaticScheduler (torch not installed)")

    tier3 = HavocMutator(scheduler.get_operator_weights(b""))

    executor = Executor(target)
    coverage = CoverageAnalyzer()
    metrics = MetricsCollector(target)

    print(f"[*] Executor mode : {executor.mode}")
    print(f"[*] Binary path   : {executor.binary}")
    metrics.write_fuzzer_config(
        {
            "target": target,
            "time_budget_secs": time_budget_secs,
            "havoc_iters": havoc_iters,
            "seeds_n": seeds_n,
            "executor_mode": executor.mode,
            "binary_path": str(executor.binary),
            "scheduler": type(scheduler).__name__,
            "scheduler_mode": "hybrid" if model is not None else "static",
            "format_config": fmt,
        }
    )

    training_buffer: list[tuple[bytes, list[int]]] = []
    behaviors_since_last_train = 0

    start = time.time()
    exec_count = 0

    while time.time() - start < time_budget_secs:
        seed = corpus.select()

        mutated = tier1.mutate(seed)
        hot_bytes = getattr(scheduler, "get_hot_bytes", lambda current_seed: [])(mutated)

        if random.random() < 0.5:
            mutated = tier2.mutate(mutated, hot_bytes=hot_bytes)

        if hasattr(scheduler, "plan_mutation"):
            plan = scheduler.plan_mutation(seed)
        else:
            plan = {"weights": scheduler.get_operator_weights(seed), "mode": "static"}

        tier3 = HavocMutator(plan["weights"])
        mutated = tier3.mutate(mutated, iterations=havoc_iters, hot_bytes=hot_bytes)

        bitmap, crashed, result = executor.run(mutated)
        exec_count += 1

        metrics.record_execution(mutated, result)

        is_new = coverage.is_interesting(bitmap)
        if hasattr(scheduler, "record_result"):
            scheduler.record_result(plan["mode"], is_new)

        if is_new:
            priority = scheduler.get_seed_priority(mutated)
            corpus.add(mutated, priority=priority)
            metrics.update_coverage(coverage.edge_count)
            metrics.record_queue_entry(mutated, exec_count, priority)
            print(
                f"[NEW] execs={exec_count:>6} behaviors={coverage.edge_count:>4} "
                f"corpus={len(corpus):>4} input={mutated[:60]!r}"
            )

            positions = [index for index, value in enumerate(bitmap) if value]
            training_buffer.append((mutated, positions))
            behaviors_since_last_train += 1

            if model is not None and behaviors_since_last_train >= TRAIN_EVERY:
                print(f"[DL] Training on {len(training_buffer)} samples...")
                loss = train(
                    model,
                    training_buffer,
                    epochs=5,
                    device=scheduler.device,
                    optimizer=model._optimizer,
                )
                scheduler.record_training(len(training_buffer), loss)
                save_checkpoint(
                    model,
                    target,
                    metadata=scheduler.export_runtime_metadata(),
                )
                print(f"[DL] Training done. Loss={loss:.4f}")
                behaviors_since_last_train = 0

        elif result.is_interesting:
            bug_label = result.bug_type
            print(
                f"[{bug_label.upper():<12}] execs={exec_count:>6} "
                f"input={mutated[:60]!r}"
            )

        metrics.record_plot_point(len(corpus))

    if model is not None and training_buffer:
        print(f"[DL] Final training on {len(training_buffer)} samples...")
        loss = train(
            model,
            training_buffer,
            epochs=5,
            device=scheduler.device,
            optimizer=model._optimizer,
        )
        scheduler.record_training(len(training_buffer), loss)
        save_checkpoint(
            model,
            target,
            metadata=scheduler.export_runtime_metadata(),
        )
        print(f"[DL] Final loss={loss:.4f}")

    final = metrics.finalize()
    print(
        f"\n[*] Done. Executions: {exec_count} | "
        f"Behaviors: {final.behaviors_covered} | "
        f"Corpus size: {len(corpus)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Coverage-Guided IP Fuzzer")
    parser.add_argument(
        "target",
        help=(
            "Parser to fuzz (e.g. ipv4, ipv6, or any registered format; "
            "'all' runs ipv4+ipv6)"
        ),
    )
    parser.add_argument(
        "--havoc-iters",
        type=int,
        default=8,
        help="Havoc mutations per execution (default: 8)",
    )
    parser.add_argument(
        "--time-budget",
        type=int,
        default=86400,
        help="Time budget in seconds (default: 86400 = 24 h)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="RNG seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--seeds-n",
        type=int,
        default=100,
        help="Initial corpus size per target (default: 100)",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    targets = ["ipv4", "ipv6"] if args.target == "all" else [args.target]
    for current_target in targets:
        fuzz(
            target=current_target,
            havoc_iters=args.havoc_iters,
            time_budget_secs=args.time_budget,
            seeds_n=args.seeds_n,
        )


if __name__ == "__main__":
    main()
