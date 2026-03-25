"""
Hybrid Coverage-Guided Fuzzer - Entry Point.

Targets : IPv4/IPv6/cidrize parser binaries plus a JSON decoder target
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
    python main.py json [--time-budget S] [--seed RNG]
    python main.py cidrize [--havoc-iters N] [--time-budget S] [--seed RNG]
    python main.py all  [--havoc-iters N] [--time-budget S] [--seed RNG]

Options:
    --havoc-iters N   Havoc mutations per execution (default: 8)
    --time-budget S   Fuzzing duration in seconds (default: 86400)
    --seed RNG        RNG seed for reproducibility (default: 42)
    --seeds-n N       Initial corpus size per target (default: 100)
    --fresh-start     Clear prior results and any saved model checkpoint
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

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
_HERE = Path(__file__).parent


def _reset_target_state(target: str) -> None:
    """Remove prior run artifacts and model checkpoint for a clean restart."""
    results_dir = _HERE / "results" / target
    if results_dir.exists():
        shutil.rmtree(results_dir)
        print(f"[*] Fresh start   : cleared {results_dir}")

    checkpoint_path = _HERE / "models" / f"{target}_surrogate.pt"
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print(f"[*] Fresh start   : removed {checkpoint_path}")


def _write_seed_corpus(seeds: list[bytes], out_dir: Path) -> int:
    """Populate an on-disk seed corpus for external fuzzers such as Atheris."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for existing in out_dir.glob("*"):
        if existing.is_file():
            existing.unlink()

    written = 0
    seen: set[bytes] = set()
    for seed in seeds:
        if seed in seen:
            continue
        seen.add(seed)
        (out_dir / f"seed_{written:04d}.json").write_bytes(seed)
        written += 1
    return written


def _run_atheris_target(
    target: str,
    fmt: dict,
    *,
    time_budget_secs: int,
    seeds_n: int,
) -> None:
    """Run an Atheris-backed target in a subprocess-managed campaign."""
    print("[*] Instrumentation: atheris")

    phase_clock = time.perf_counter()
    generator = get_seed_generator(target, fmt)
    seeds = generator.generate_corpus(n=seeds_n)
    print(f"[*] Seed corpus   : {len(seeds)} generated ({_elapsed_ms(phase_clock):7.1f} ms)")

    results_dir = _HERE / "results" / target
    corpus_dir = results_dir / "atheris_corpus"
    crashes_dir = results_dir / "crashes"
    log_path = results_dir / "atheris.log"
    stats_path = results_dir / "stats.txt"

    crashes_dir.mkdir(parents=True, exist_ok=True)
    written_seed_count = _write_seed_corpus(seeds, corpus_dir)

    config_payload = {
        "target": target,
        "time_budget_secs": time_budget_secs,
        "seeds_n": seeds_n,
        "executor_mode": "Atheris",
        "binary_path": None,
        "scheduler": "Atheris/libFuzzer",
        "scheduler_mode": "atheris",
        "dl_enabled": False,
        "checkpoint_loaded": False,
        "checkpoint_metadata": {},
        "format_config": fmt,
        "seed_corpus_dir": str(corpus_dir),
        "crashes_dir": str(crashes_dir),
        "harness": str(_HERE / "fuzzer" / "json_atheris_harness.py"),
    }
    (results_dir / "fuzzer_config").write_text(
        json.dumps(config_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    cmd = [
        sys.executable,
        str(_HERE / "fuzzer" / "json_atheris_harness.py"),
        str(corpus_dir),
        f"-artifact_prefix={str(crashes_dir)}{os.sep}",
        f"-max_total_time={time_budget_secs}",
        "-print_final_stats=1",
        "-timeout=5",
    ]
    env = os.environ.copy()
    current_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(_HERE)
        if not current_pythonpath
        else str(_HERE) + os.pathsep + current_pythonpath
    )

    print(f"[*] Harness       : {cmd[0]} {cmd[1]}")
    print(f"[*] Seed files    : {written_seed_count}")
    print(f"[*] Crash dir     : {crashes_dir}")

    start = time.time()
    with open(log_path, "w", encoding="utf-8") as log_file:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=_HERE,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            log_file.write(line)
        return_code = proc.wait()

    crash_count = len(list(crashes_dir.glob("*")))
    corpus_count = len(list(corpus_dir.glob("*")))
    duration = time.time() - start

    stats_lines = [
        f"Target          : {target}",
        f"Wall time       : {duration:.1f}s",
        "Total execs     : Atheris-managed (see atheris.log)",
        "Behaviors seen  : Atheris-managed (see atheris.log)",
        "Unique bugs     : Atheris-managed (see atheris.log)",
        "Validity bugs   : N/A",
        "Bonus bugs      : N/A",
        "Invalidity count: N/A",
        f"Unique crashes  : {crash_count}",
        "Time-to-1st-bug : Atheris-managed",
        f"Seed corpus     : {corpus_count}",
        f"Return code     : {return_code}",
    ]
    stats_text = "\n".join(stats_lines) + "\n"
    stats_path.write_text(stats_text, encoding="utf-8")
    (results_dir / "fuzzer_stats").write_text(stats_text, encoding="utf-8")

    if return_code == 2:
        raise RuntimeError(
            "The Atheris harness could not start in this environment. "
            f"See {log_path} for details."
        )

    print("\n".join(stats_lines))


def _elapsed_ms(start_time: float) -> float:
    """Return milliseconds elapsed since start_time."""
    return (time.perf_counter() - start_time) * 1000.0


def _json_safe_metadata(metadata: dict | None) -> dict:
    """Return a JSON-friendly copy of checkpoint/runtime metadata."""
    if not metadata:
        return {}
    safe: dict[str, int | float | str | bool | None] = {}
    for key, value in metadata.items():
        if isinstance(value, (int, float, str, bool)) or value is None:
            safe[str(key)] = value
        else:
            safe[str(key)] = str(value)
    return safe


def _preferred_index_map(
    spans,
    preferred_fields: list[str] | None,
) -> tuple[list[int], dict[int, str]]:
    if not preferred_fields:
        return [], {}

    preferred_indices: list[int] = []
    field_lookup: dict[int, str] = {}
    for span in spans:
        if span.name not in preferred_fields:
            continue
        if span.start == span.end:
            preferred_indices.append(span.start)
            field_lookup[span.start] = span.name
            continue
        for idx in range(span.start, span.end):
            preferred_indices.append(idx)
            field_lookup[idx] = span.name
    return preferred_indices, field_lookup


def fuzz(
    target: str,
    havoc_iters: int = 8,
    time_budget_secs: int = 86400,
    seeds_n: int = 100,
    disable_dl: bool = False,
    fresh_start: bool = False,
) -> None:
    """Run the hybrid fuzzer against one target."""

    print(f"\n{'=' * 60}")
    print(f"[*] Target        : {target}")
    print(f"[*] Time budget   : {time_budget_secs}s")
    print(f"[*] Havoc iters   : {havoc_iters}")
    print(f"{'=' * 60}\n")

    startup_clock = time.perf_counter()

    if fresh_start:
        _reset_target_state(target)

    phase_clock = time.perf_counter()
    fmt = load_format(target)
    print(f"[*] Format loaded : {_elapsed_ms(phase_clock):7.1f} ms")

    if fmt.get("instrumentation") == "atheris":
        _run_atheris_target(
            target,
            fmt,
            time_budget_secs=time_budget_secs,
            seeds_n=seeds_n,
        )
        return

    if fmt.get("binary_windows") or fmt.get("binary_linux"):
        register_binary(
            target,
            windows=fmt.get("binary_windows"),
            linux=fmt.get("binary_linux"),
            windows_args=fmt.get("binary_windows_args"),
            linux_args=fmt.get("binary_linux_args"),
        )

    phase_clock = time.perf_counter()
    generator = get_seed_generator(target, fmt)
    corpus = Corpus()
    for seed in generator.generate_corpus(n=seeds_n):
        corpus.add(seed, priority=1.0)
    print(
        f"[*] Corpus loaded : {len(corpus)} seeds "
        f"({_elapsed_ms(phase_clock):7.1f} ms)"
    )

    phase_clock = time.perf_counter()
    tier1 = StructureMutator()
    tier2 = get_mutator(target, fmt)
    print(f"[*] Mutators ready: {_elapsed_ms(phase_clock):7.1f} ms")

    model = None
    scheduler = None
    checkpoint_loaded = False
    checkpoint_metadata: dict = {}
    phase_clock = time.perf_counter()
    if disable_dl:
        scheduler = StaticScheduler(fmt)
        print(
            f"[*] Scheduler     : StaticScheduler (--no-dl) "
            f"({_elapsed_ms(phase_clock):7.1f} ms)"
        )
    else:
        try:
            import torch
            from dl.surrogate import CoverageSurrogate, DLScheduler
            from dl.trainer import load_checkpoint, save_checkpoint, train
            from dl.trustworthiness import is_trustworthy

            model = CoverageSurrogate()
            model._optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
            scheduler = DLScheduler(model, is_trustworthy, fmt)
            checkpoint_state = load_checkpoint(model, target, scheduler.device)
            checkpoint_loaded = bool(checkpoint_state.get("loaded"))
            checkpoint_metadata = _json_safe_metadata(checkpoint_state.get("metadata"))
            scheduler.load_runtime_metadata(checkpoint_state.get("metadata"))
            model.eval()
            print(
                f"[*] Scheduler     : Hybrid DLScheduler (device={scheduler.device}) "
                f"({_elapsed_ms(phase_clock):7.1f} ms)"
            )
        except ImportError:
            scheduler = StaticScheduler(fmt)
            print(
                f"[*] Scheduler     : StaticScheduler (torch not installed) "
                f"({_elapsed_ms(phase_clock):7.1f} ms)"
            )

    phase_clock = time.perf_counter()
    tier3 = HavocMutator(scheduler.get_operator_weights(b""))
    print(f"[*] Havoc primed  : {_elapsed_ms(phase_clock):7.1f} ms")

    phase_clock = time.perf_counter()
    executor = Executor(target)
    coverage = CoverageAnalyzer()
    metrics = MetricsCollector(target)

    print(f"[*] Executor mode : {executor.mode} ({_elapsed_ms(phase_clock):7.1f} ms)")
    print(f"[*] Binary path   : {executor.binary}")
    print(f"[*] Startup total : {_elapsed_ms(startup_clock):7.1f} ms")

    initial_dl_metadata = (
        _json_safe_metadata(scheduler.export_runtime_metadata())
        if model is not None and hasattr(scheduler, "export_runtime_metadata")
        else {}
    )
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
            "dl_enabled": model is not None,
            "checkpoint_loaded": checkpoint_loaded,
            "checkpoint_metadata": checkpoint_metadata,
            "format_config": fmt,
        }
    )
    metrics.write_dl_summary(
        {
            "target": target,
            "dl_enabled": model is not None,
            "checkpoint_loaded": checkpoint_loaded,
            "initial_metadata": initial_dl_metadata,
            "final_metadata": initial_dl_metadata,
            "training_rounds_this_run": 0,
            "latest_loss": None,
        }
    )

    training_buffer: list[tuple[bytes, list[int]]] = []
    behaviors_since_last_train = 0
    dl_training_rounds_this_run = 0

    start = time.time()
    exec_count = 0

    while time.time() - start < time_budget_secs:
        seed = corpus.select(priority_fn=scheduler.get_seed_priority)

        mutated = tier1.mutate(seed)
        plan = scheduler.plan_mutation(seed)
        hot_bytes = getattr(scheduler, "get_hot_bytes", lambda current_seed: [])(mutated)

        semantic_trace = {"applied": False}
        if random.random() < float(plan.get("semantic_probability", 0.5)):
            mutated = tier2.mutate(
                mutated,
                hot_bytes=hot_bytes,
                preferred_fields=plan.get("preferred_fields"),
            )
            semantic_trace = tier2.consume_last_trace()

        semantic_spans = tier2.get_semantic_spans(mutated)
        preferred_indices, field_lookup = _preferred_index_map(
            semantic_spans,
            plan.get("preferred_fields"),
        )

        tier3 = HavocMutator(plan["weights"])
        mutated = tier3.mutate(
            mutated,
            iterations=havoc_iters,
            hot_bytes=hot_bytes,
            preferred_indices=preferred_indices,
            field_lookup=field_lookup,
            guided_ratio=float(plan.get("guided_ratio", 0.7)),
        )
        havoc_trace = tier3.consume_last_trace()

        execution_clock = time.perf_counter()
        if exec_count == 0:
            print("[*] First execution starting...")
        bitmap, crashed, result = executor.run(mutated)
        execution_ms = _elapsed_ms(execution_clock)
        exec_count += 1

        if exec_count == 1:
            print(
                f"[*] First execution finished in {execution_ms:7.1f} ms "
                f"(bug_type={result.bug_type}, crashed={crashed})"
            )
        elif execution_ms >= 1000:
            print(
                f"[*] Slow execution: execs={exec_count:>6} "
                f"duration={execution_ms:7.1f} ms bug_type={result.bug_type}"
            )

        metrics.record_execution(mutated, result)

        is_new = coverage.is_interesting(bitmap)
        corpus.record_result(seed, is_new)
        if hasattr(scheduler, "record_mutation_outcome"):
            scheduler.record_mutation_outcome(
                plan=plan,
                discovered_new_behavior=is_new,
                semantic_trace=semantic_trace,
                havoc_trace=havoc_trace,
            )

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
                training_started_at = time.time()
                loss = train(
                    model,
                    training_buffer,
                    epochs=5,
                    device=scheduler.device,
                    optimizer=model._optimizer,
                )
                scheduler.record_training(len(training_buffer), loss)
                dl_training_rounds_this_run += 1
                current_metadata = _json_safe_metadata(scheduler.export_runtime_metadata())
                metrics.record_dl_training_event(
                    {
                        "round": dl_training_rounds_this_run,
                        "event": "periodic",
                        "relative_time_sec": round(time.time() - start, 3),
                        "duration_sec": round(time.time() - training_started_at, 3),
                        "exec_count": exec_count,
                        "buffer_size": len(training_buffer),
                        "behaviors_seen": coverage.edge_count,
                        "loss": loss,
                        "device": getattr(scheduler, "device", None),
                        "metadata": current_metadata,
                    }
                )
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
        training_started_at = time.time()
        loss = train(
            model,
            training_buffer,
            epochs=5,
            device=scheduler.device,
            optimizer=model._optimizer,
        )
        scheduler.record_training(len(training_buffer), loss)
        dl_training_rounds_this_run += 1
        current_metadata = _json_safe_metadata(scheduler.export_runtime_metadata())
        metrics.record_dl_training_event(
            {
                "round": dl_training_rounds_this_run,
                "event": "final",
                "relative_time_sec": round(time.time() - start, 3),
                "duration_sec": round(time.time() - training_started_at, 3),
                "exec_count": exec_count,
                "buffer_size": len(training_buffer),
                "behaviors_seen": coverage.edge_count,
                "loss": loss,
                "device": getattr(scheduler, "device", None),
                "metadata": current_metadata,
            }
        )
        save_checkpoint(
            model,
            target,
            metadata=scheduler.export_runtime_metadata(),
        )
        print(f"[DL] Final loss={loss:.4f}")

    final_dl_metadata = (
        _json_safe_metadata(scheduler.export_runtime_metadata())
        if model is not None and hasattr(scheduler, "export_runtime_metadata")
        else {}
    )
    metrics.write_dl_summary(
        {
            "target": target,
            "dl_enabled": model is not None,
            "checkpoint_loaded": checkpoint_loaded,
            "initial_metadata": initial_dl_metadata,
            "final_metadata": final_dl_metadata,
            "training_rounds_this_run": dl_training_rounds_this_run,
            "latest_loss": final_dl_metadata.get("last_training_loss"),
        }
    )

    final = metrics.finalize()
    if hasattr(scheduler, "export_mutation_stats"):
        metrics.write_mutation_stats(scheduler.export_mutation_stats())
    print(
        f"\n[*] Done. Executions: {exec_count} | "
        f"Behaviors: {final.behaviors_covered} | "
        f"Corpus size: {len(corpus)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Coverage-Guided Format Fuzzer")
    parser.add_argument(
        "target",
        help=(
            "Parser to fuzz (e.g. ipv4, ipv6, json, or any registered format; "
            "'all' runs ipv4+ipv6+cidrize)"
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
    parser.add_argument(
        "--no-dl",
        action="store_true",
        help="Force the static scheduler even if torch is installed",
    )
    parser.add_argument(
        "--fresh-start",
        action="store_true",
        help="Clear results/<target> and models/<target>_surrogate.pt before the run",
    )
    args = parser.parse_args()

    random.seed(args.seed)

    targets = ["ipv4", "ipv6", "cidrize"] if args.target == "all" else [args.target]
    for current_target in targets:
        fuzz(
            target=current_target,
            havoc_iters=args.havoc_iters,
            time_budget_secs=args.time_budget,
            seeds_n=args.seeds_n,
            disable_dl=args.no_dl,
            fresh_start=args.fresh_start,
        )


if __name__ == "__main__":
    main()
