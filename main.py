"""
Hybrid Coverage-Guided Fuzzer - Entry Point.

Targets : IPv4/IPv6/cidrize parser binaries plus a JSON decoder target
Stack   : Python 3.11+, three-tier mutation engine, behavior-based coverage

Binary-target evaluation modes:
  havoc_only           -> fixed static havoc weights, Tier 2 disabled
  semantic_plus_havoc  -> fixed static havoc weights, Tier 2 enabled
  static_payoff        -> payoff-tracking scheduler without DL
  hybrid_dl            -> guarded DL guidance layered on payoff tracking

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
    --evaluation-mode Explicit experiment configuration (default: auto)
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
from fuzzer.scheduler import FixedScheduler, StaticScheduler
from fuzzer.seed_generator import get_seed_generator

# Train the surrogate every N new behaviors discovered.
# Low because each binary call is ~30 s, so corpus growth is slow.
TRAIN_EVERY = 2
_HERE = Path(__file__).parent
EVALUATION_MODES = ("auto", "havoc_only", "semantic_plus_havoc", "static_payoff", "hybrid_dl")


def _resolve_evaluation_mode(
    requested_mode: str,
    *,
    disable_dl: bool,
) -> str:
    """Resolve the requested evaluation mode and whether DL should be used."""
    if disable_dl and requested_mode not in ("auto", "havoc_only", "semantic_plus_havoc", "static_payoff"):
        raise ValueError("--no-dl cannot be combined with evaluation mode 'hybrid_dl'")

    if requested_mode == "havoc_only":
        return "havoc_only"
    if requested_mode == "semantic_plus_havoc":
        return "semantic_plus_havoc"
    if requested_mode == "static_payoff" or disable_dl:
        return "static_payoff"
    if requested_mode == "hybrid_dl":
        return "hybrid_dl"

    try:
        import torch  # noqa: F401

        return "hybrid_dl"
    except ImportError:
        return "static_payoff"


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
    evaluation_mode_requested: str,
    evaluation_mode_resolved: str,
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
        "evaluation_mode_requested": evaluation_mode_requested,
        "evaluation_mode_resolved": evaluation_mode_resolved,
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
        f"Eval mode req   : {evaluation_mode_requested}",
        f"Eval mode used  : {evaluation_mode_resolved}",
        f"Wall time       : {duration:.1f}s",
        "Total execs     : Atheris-managed (see atheris.log)",
        "Behaviors seen  : Atheris-managed (see atheris.log)",
        "Unique bugs     : Atheris-managed (see atheris.log)",
        "Validity bugs   : N/A",
        "Bonus bugs      : N/A",
        "Invalidity count: N/A",
        f"Unique crashes  : {crash_count}",
        "Time-to-1st-interesting: Atheris-managed",
        "Time-to-1st-real-bug: Atheris-managed",
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
    evaluation_mode: str = "auto",
    no_gradient_guidance: bool = False,
    no_retrain: bool = False,
    fixed_lr: bool = False,
    no_qemu: bool = False,
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

    resolved_mode = _resolve_evaluation_mode(
        evaluation_mode,
        disable_dl=disable_dl,
    )

    phase_clock = time.perf_counter()
    fmt = load_format(target)
    print(f"[*] Format loaded : {_elapsed_ms(phase_clock):7.1f} ms")

    if fmt.get("instrumentation") == "atheris":
        _run_atheris_target(
            target,
            fmt,
            time_budget_secs=time_budget_secs,
            seeds_n=seeds_n,
            evaluation_mode_requested=evaluation_mode,
            evaluation_mode_resolved="atheris",
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
    if resolved_mode == "havoc_only":
        scheduler = FixedScheduler(fmt, semantic_probability=0.0, guided_ratio=0.0)
        print(
            f"[*] Scheduler     : FixedScheduler (havoc-only baseline) "
            f"({_elapsed_ms(phase_clock):7.1f} ms)"
        )
    elif resolved_mode == "semantic_plus_havoc":
        scheduler = FixedScheduler(fmt, semantic_probability=0.5, guided_ratio=0.0)
        print(
            f"[*] Scheduler     : FixedScheduler (semantic+havoc baseline) "
            f"({_elapsed_ms(phase_clock):7.1f} ms)"
        )
    elif resolved_mode == "static_payoff":
        scheduler = StaticScheduler(fmt)
        print(
            f"[*] Scheduler     : StaticScheduler (payoff-tracking) "
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
            if evaluation_mode == "hybrid_dl":
                raise RuntimeError(
                    "evaluation mode 'hybrid_dl' requires torch to be installed"
                ) from None
            scheduler = StaticScheduler(fmt)
            resolved_mode = "static_payoff"
            print(
                f"[*] Scheduler     : StaticScheduler (torch not installed; fell back from auto) "
                f"({_elapsed_ms(phase_clock):7.1f} ms)"
            )

    phase_clock = time.perf_counter()
    tier3 = HavocMutator(scheduler.get_operator_weights(b""))
    print(f"[*] Havoc primed  : {_elapsed_ms(phase_clock):7.1f} ms")

    phase_clock = time.perf_counter()
    executor = Executor(target, use_qemu=not no_qemu)
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
            "evaluation_mode_requested": evaluation_mode,
            "evaluation_mode_resolved": resolved_mode,
            "executor_mode": executor.mode,
            "binary_path": str(executor.binary),
            "scheduler": type(scheduler).__name__,
            "scheduler_mode": resolved_mode,
            "dl_enabled": model is not None,
            "checkpoint_loaded": checkpoint_loaded,
            "checkpoint_metadata": checkpoint_metadata,
            "semantic_mutation_enabled": resolved_mode != "havoc_only",
            "gradient_guidance_enabled": not no_gradient_guidance,
            "behavior_proxy_dim": getattr(model, "COV_DIM", None),
            "behavior_proxy_note": (
                "DL model learns a compressed behavior proxy, not the full runtime bitmap"
                if model is not None
                else None
            ),
            "format_config": fmt,
        }
    )
    metrics.write_dl_summary(
        {
            "target": target,
            "dl_enabled": model is not None,
            "evaluation_mode_requested": evaluation_mode,
            "evaluation_mode_resolved": resolved_mode,
            "checkpoint_loaded": checkpoint_loaded,
            "initial_metadata": initial_dl_metadata,
            "final_metadata": initial_dl_metadata,
            "training_rounds_this_run": 0,
            "latest_loss": None,
            "behavior_proxy_dim": getattr(model, "COV_DIM", None),
            "behavior_proxy_note": (
                "Compressed proxy target built from observed bitmap positions represented in the model output"
                if model is not None
                else None
            ),
        }
    )

    training_buffer: list[tuple[bytes, list[int]]] = []
    behaviors_since_last_train = 0
    dl_training_rounds_this_run = 0

    start = time.time()
    exec_count = 0

    # Stagnation tracking
    execs_since_last_new_behavior = 0
    execs_since_last_new_bug      = 0
    last_unique_bug_count         = 0
    avg_exec_time_ms              = 5000  # rough initial estimate, updated each exec
    _STAGNATION_WARN     = 100   # print a status line every N execs without new behavior
    _STAGNATION_STOP     = 200   # suggest stopping after this many execs without new behavior
    _BUG_STAGNATION_STOP = 500   # suggest stopping after this many execs without a new unique bug

    while time.time() - start < time_budget_secs:
        seed = corpus.select(priority_fn=scheduler.get_seed_priority)
        metrics.record_energy(seed, scheduler.get_seed_priority(seed))

        plan = scheduler.plan_mutation(seed)
        hot_bytes = (
            []
            if no_gradient_guidance
            else getattr(scheduler, "get_hot_bytes", lambda current_seed: [])(seed)
        )

        # 10% of the time run the seed unmodified (all tiers skipped) so valid
        # inputs like 255.255.255.255 reach the parser intact.
        semantic_trace = {"applied": False}
        pass_through = random.random() < 0.20
        if pass_through:
            mutated = seed
            havoc_trace = {"applied": False}
        else:
            mutated = tier1.mutate(seed)

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
                guided_ratio=0.0 if no_gradient_guidance else float(plan.get("guided_ratio", 0.7)),
            )
            havoc_trace = tier3.consume_last_trace()

        execution_clock = time.perf_counter()
        if exec_count == 0:
            print("[*] First execution starting...")
        bitmap, crashed, result = executor.run(mutated)
        execution_ms = _elapsed_ms(execution_clock)
        exec_count += 1
        avg_exec_time_ms = avg_exec_time_ms * 0.95 + execution_ms * 0.05

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

        metrics.record_execution(mutated, result, bitmap)

        is_new = coverage.is_interesting(bitmap)
        metrics.record_oracle_log(mutated, result.bug_type, is_new, execution_ms)
        corpus.record_result(seed, is_new)
        if hasattr(scheduler, "record_mutation_outcome"):
            scheduler.record_mutation_outcome(
                plan=plan,
                discovered_new_behavior=is_new,
                semantic_trace=semantic_trace,
                havoc_trace=havoc_trace,
            )

        # Track stagnation
        current_unique_bugs = metrics.metrics.unique_bug_count
        if is_new:
            execs_since_last_new_behavior = 0
        else:
            execs_since_last_new_behavior += 1

        if current_unique_bugs > last_unique_bug_count:
            execs_since_last_new_bug = 0
            last_unique_bug_count = current_unique_bugs
        else:
            execs_since_last_new_bug += 1

        if execs_since_last_new_behavior > 0 and execs_since_last_new_behavior % _STAGNATION_WARN == 0:
            elapsed = time.time() - start
            print(
                f"[STAGNANT] execs={exec_count:>6} "
                f"no_new_behavior={execs_since_last_new_behavior:>5} execs  "
                f"no_new_bug={execs_since_last_new_bug:>5} execs  "
                f"unique_bugs={current_unique_bugs}  "
                f"elapsed={elapsed:.0f}s"
            )
            if execs_since_last_new_behavior >= _STAGNATION_STOP:
                print(
                    f"[CONVERGED] No new behaviors in {execs_since_last_new_behavior} executions "
                    f"and no new bugs in {execs_since_last_new_bug} executions. "
                    f"Coverage likely saturated — consider stopping."
                )
        if execs_since_last_new_bug >= _BUG_STAGNATION_STOP and execs_since_last_new_bug % _STAGNATION_WARN == 0:
            print(
                f"[BUG_STAGNANT] No new unique bugs in {execs_since_last_new_bug} executions "
                f"({execs_since_last_new_bug * avg_exec_time_ms / 60000:.1f} min)  "
                f"unique_bugs={current_unique_bugs} — likely found all reachable bugs."
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

            if model is not None and not no_retrain and behaviors_since_last_train >= TRAIN_EVERY:
                from dl.trainer import compute_misprediction_rate
                recent_samples = training_buffer[-TRAIN_EVERY:]
                misprediction_rate = compute_misprediction_rate(
                    model, recent_samples, scheduler.device
                )
                print(f"[DL] Training on {len(training_buffer)} samples... (misprediction_rate={misprediction_rate:.3f})")
                training_started_at = time.time()
                loss = train(
                    model,
                    training_buffer,
                    epochs=5,
                    device=scheduler.device,
                    optimizer=model._optimizer,
                    fixed_lr=fixed_lr,
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
                        "misprediction_rate": misprediction_rate,
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

    if model is not None and not no_retrain and training_buffer:
        from dl.trainer import compute_misprediction_rate
        misprediction_rate = compute_misprediction_rate(
            model, training_buffer[-TRAIN_EVERY:], scheduler.device
        )
        print(f"[DL] Final training on {len(training_buffer)} samples... (misprediction_rate={misprediction_rate:.3f})")
        training_started_at = time.time()
        loss = train(
            model,
            training_buffer,
            epochs=5,
            device=scheduler.device,
            optimizer=model._optimizer,
            fixed_lr=fixed_lr,
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
                "misprediction_rate": misprediction_rate,
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
            "evaluation_mode_requested": evaluation_mode,
            "evaluation_mode_resolved": resolved_mode,
            "checkpoint_loaded": checkpoint_loaded,
            "initial_metadata": initial_dl_metadata,
            "final_metadata": final_dl_metadata,
            "training_rounds_this_run": dl_training_rounds_this_run,
            "latest_loss": final_dl_metadata.get("last_training_loss"),
            "behavior_proxy_dim": getattr(model, "COV_DIM", None),
            "behavior_proxy_note": (
                "Compressed proxy target built from observed bitmap positions represented in the model output"
                if model is not None
                else None
            ),
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
        help="Deprecated compatibility flag: forces non-DL evaluation modes",
    )
    parser.add_argument(
        "--evaluation-mode",
        choices=EVALUATION_MODES,
        default="auto",
        help=(
            "Evaluation configuration: auto, havoc_only, semantic_plus_havoc, "
            "static_payoff, or hybrid_dl (default: auto)"
        ),
    )
    parser.add_argument(
        "--fresh-start",
        action="store_true",
        help="Clear results/<target> and models/<target>_surrogate.pt before the run",
    )
    parser.add_argument(
        "--no-gradient-guidance",
        action="store_true",
        help=(
            "Disable gradient-guided hot-byte selection and set guided_ratio=0.0 "
            "while keeping the DL model active for operator-weight learning"
        ),
    )
    parser.add_argument(
        "--no-retrain",
        action="store_true",
        help=(
            "Ablation A4: disable incremental surrogate retraining; "
            "the model is used as-is from the cold-start checkpoint only"
        ),
    )
    parser.add_argument(
        "--fixed-lr",
        action="store_true",
        help=(
            "Ablation A5: replace cosine decay with restarts with a fixed "
            "learning rate (1e-3) during surrogate training"
        ),
    )
    parser.add_argument(
        "--no-qemu",
        action="store_true",
        help="Disable QEMU mode and use Linux behavior-hash mode instead",
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
            evaluation_mode=args.evaluation_mode,
            no_gradient_guidance=args.no_gradient_guidance,
            no_retrain=args.no_retrain,
            fixed_lr=args.fixed_lr,
            no_qemu=args.no_qemu,
        )


if __name__ == "__main__":
    main()
