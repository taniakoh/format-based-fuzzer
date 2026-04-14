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
import concurrent.futures
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter
from pathlib import Path

from evaluation.collect_metrics import MetricsCollector, derive_bug_site
from fuzzer.bootstrap import ensure_bootstrap_profile
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
# Needs at least this many samples before the gradient signal is meaningful.
TRAIN_EVERY = 10
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

    import importlib.util
    if importlib.util.find_spec("torch") is not None:
        return "hybrid_dl"
    return "static_payoff"


def _run_dir(target: str, run_id: str) -> Path:
    """Return the results directory for a given target and optional run_id."""
    return _HERE / "results" / (f"{target}_{run_id}" if run_id else target)


def _checkpoint_key(target: str, run_id: str) -> str:
    """Return the model checkpoint key for a given target and optional run_id."""
    return f"{target}_{run_id}" if run_id else target


def _reset_target_state(target: str, run_id: str = "") -> None:
    """Remove prior run artifacts and model checkpoint for a clean restart."""
    results_dir = _run_dir(target, run_id)
    if results_dir.exists():
        shutil.rmtree(results_dir)
        print(f"[*] Fresh start   : cleared {results_dir}")

    ck = _checkpoint_key(target, run_id)
    checkpoint_path = _HERE / "models" / f"{ck}_surrogate.pt"
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


def _init_dl_for_atheris(
    target: str,
    fmt: dict,
    weights_path: Path,
    run_id: str = "",
) -> tuple:
    """Initialise the DL surrogate for an Atheris target.

    Returns (model, scheduler, device) on success, or (None, None, None) if
    torch is not available.  The initial operator weights are written to
    ``weights_path`` so the harness can read them immediately.
    """
    try:
        import torch
        from dl.surrogate import CoverageSurrogate, DLScheduler
        from dl.trainer import load_checkpoint
        from dl.trustworthiness import is_trustworthy

        model = CoverageSurrogate()
        model._optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        scheduler = DLScheduler(model, is_trustworthy, fmt)
        load_checkpoint(model, _checkpoint_key(target, run_id), scheduler.device)
        model.eval()

        weights = scheduler.get_operator_weights(b"")
        weights_path.write_text(json.dumps(weights, indent=2), encoding="utf-8")
        print(f"[DL-Atheris] Surrogate ready (device={scheduler.device})")
        return model, scheduler, scheduler.device
    except ImportError:
        print("[DL-Atheris] torch not available — running without DL guidance")
        return None, None, None


def _dl_monitor_atheris(
    model,
    scheduler,
    device,
    target: str,
    corpus_dir: Path,
    crashes_dir: Path,
    weights_path: Path,
    stop_event: threading.Event,
    run_id: str = "",
) -> None:
    """Background thread: watches for new corpus/crash files, retrains the
    surrogate, and writes updated operator weights for the harness to pick up."""
    from dl.trainer import compute_misprediction_rate, save_checkpoint, train

    POLL_INTERVAL = 30  # seconds between checks
    seen_files: set[Path] = set(corpus_dir.glob("*")) | set(crashes_dir.glob("*"))
    training_buffer: list[tuple[bytes, list[int]]] = []
    rounds = 0
    run_start = time.time()
    dl_training_path = corpus_dir.parent / "dl_training.jsonl"
    dl_summary_path = corpus_dir.parent / "dl_summary.json"
    dl_training_path.write_text("", encoding="utf-8")

    while not stop_event.is_set():
        stop_event.wait(POLL_INTERVAL)
        if stop_event.is_set():
            break

        new_files: list[Path] = []
        for f in list(corpus_dir.glob("*")) + list(crashes_dir.glob("*")):
            if f.is_file() and f not in seen_files:
                seen_files.add(f)
                new_files.append(f)

        if not new_files:
            continue

        # Build synthetic bitmaps: hash (crash/corpus + content) to bitmap slots
        for f in new_files:
            try:
                data = f.read_bytes()
            except OSError:
                continue
            kind = "crash" if f.parent == crashes_dir else "corpus"
            key = f"{kind}|{hashlib.sha256(data).hexdigest()}"
            digest = hashlib.sha256(key.encode()).digest()
            pos = (digest[0] << 8 | digest[1]) % 65536
            bitmap_positions = [pos]
            if kind == "crash":
                pos2 = (digest[2] << 8 | digest[3]) % 65536
                bitmap_positions.append(pos2)
            training_buffer.append((data, bitmap_positions))

        print(f"[DL-Atheris] Training on {len(training_buffer)} samples ({len(new_files)} new)...")
        try:
            misprediction_rate = compute_misprediction_rate(model, training_buffer, device=device)
            loss = train(model, training_buffer, epochs=5, device=device,
                         optimizer=model._optimizer)
            scheduler.record_training(len(training_buffer), loss)
            rounds += 1

            weights = scheduler.get_operator_weights(b"")
            weights_path.write_text(json.dumps(weights, indent=2), encoding="utf-8")
            save_checkpoint(model, _checkpoint_key(target, run_id), metadata=scheduler.export_runtime_metadata())
            print(f"[DL-Atheris] Round {rounds} done. Loss={loss:.4f}  misprediction={misprediction_rate:.3f}  weights written.")

            with open(dl_training_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "round": rounds,
                    "relative_time_sec": round(time.time() - run_start, 3),
                    "loss": loss,
                    "misprediction_rate": misprediction_rate,
                    "training_buffer_size": len(training_buffer),
                    "new_files": len(new_files),
                    "operator_weights": weights,
                }) + "\n")

            dl_summary_path.write_text(json.dumps({
                "target": target,
                "dl_enabled": True,
                "training_rounds_this_run": rounds,
                "latest_loss": loss,
                "latest_misprediction_rate": misprediction_rate,
                "operator_weights": weights,
            }, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[DL-Atheris] Training error: {exc}")


def _run_atheris_target(
    target: str,
    fmt: dict,
    *,
    time_budget_secs: int,
    seeds_n: int,
    evaluation_mode_requested: str,
    evaluation_mode_resolved: str,
    run_id: str = "",
) -> None:
    """Run an Atheris-backed target in a subprocess-managed campaign."""
    print("[*] Instrumentation: atheris")

    phase_clock = time.perf_counter()
    generator = get_seed_generator(target, fmt)
    seeds = generator.generate_corpus(n=seeds_n)
    print(f"[*] Seed corpus   : {len(seeds)} generated ({_elapsed_ms(phase_clock):7.1f} ms)")

    results_dir = _run_dir(target, run_id)
    corpus_dir = results_dir / "atheris_corpus"
    crashes_dir = results_dir / "crashes"
    log_path = results_dir / "atheris.log"
    stats_path = results_dir / "stats.txt"

    crashes_dir.mkdir(parents=True, exist_ok=True)
    written_seed_count = _write_seed_corpus(seeds, corpus_dir)

    # ── DL initialisation ─────────────────────────────────────────────────────
    dl_weights_path = results_dir / "dl_weights.json"
    dl_model, dl_scheduler, dl_device = _init_dl_for_atheris(target, fmt, dl_weights_path, run_id=run_id)
    dl_enabled = dl_model is not None

    config_payload = {
        "target": target,
        "time_budget_secs": time_budget_secs,
        "seeds_n": seeds_n,
        "evaluation_mode_requested": evaluation_mode_requested,
        "evaluation_mode_resolved": evaluation_mode_resolved,
        "executor_mode": "Atheris",
        "binary_path": None,
        "scheduler": "DLScheduler+Atheris/libFuzzer" if dl_enabled else "Atheris/libFuzzer",
        "scheduler_mode": "atheris",
        "dl_enabled": dl_enabled,
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
        "-u",
        str(_HERE / "fuzzer" / "json_atheris_harness.py"),
        str(corpus_dir),
        f"-artifact_prefix={str(crashes_dir)}{os.sep}",
        f"-max_total_time={time_budget_secs}",
        "-print_final_stats=1",
        "-timeout=5",
        "-ignore_timeouts=1",
    ]
    env = os.environ.copy()
    current_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(_HERE)
        if not current_pythonpath
        else str(_HERE) + os.pathsep + current_pythonpath
    )
    env["PYTHONUNBUFFERED"] = "1"
    if dl_enabled:
        env["ATHERIS_DL_WEIGHTS"] = str(dl_weights_path)

    print(f"[*] Harness       : {cmd[0]} {cmd[1]}")
    print(f"[*] Seed files    : {written_seed_count}")
    print(f"[*] Crash dir     : {crashes_dir}")
    print(f"[*] DL guidance   : {'enabled' if dl_enabled else 'disabled'}")

    # ── Start DL monitor thread ────────────────────────────────────────────────
    stop_event = threading.Event()
    if dl_enabled:
        monitor_thread = threading.Thread(
            target=_dl_monitor_atheris,
            args=(dl_model, dl_scheduler, dl_device, target,
                  corpus_dir, crashes_dir, dl_weights_path, stop_event, run_id),
            daemon=True,
        )
        monitor_thread.start()

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

    stop_event.set()

    crash_count = len(list(crashes_dir.glob("*")))
    corpus_count = len(list(corpus_dir.glob("*")))
    duration = time.time() - start

    stats_lines = [
        f"Target          : {target}",
        f"Eval mode req   : {evaluation_mode_requested}",
        f"Eval mode used  : {evaluation_mode_resolved}",
        f"Wall time       : {duration:.1f}s",
        "Total execs     : Atheris-managed (see atheris.log)",
        "Coverage seen   : Atheris-managed (see atheris.log)",
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

    _postprocess_atheris_results(target, results_dir, crashes_dir, duration)
    print("\n".join(stats_lines))


def _atheris_bug_record(
    bug_type: str,
    exception: str,
    *,
    traceback_text: str = "",
    exc_type: str = "",
) -> dict[str, object]:
    return {
        "bug_type": bug_type,
        "exception": exception,
        "traceback": traceback_text,
        "exc_type": exc_type,
    }


def _classify_atheris_crash(crash_file: Path) -> dict[str, object]:
    """Re-run one Atheris crash input and return bug metadata for deduplication."""
    name = crash_file.name
    if name.startswith("timeout-") or name.startswith("slow-"):
        return _atheris_bug_record("TIMEOUT", "Buggy JSON decoder timed out", exc_type="PerformanceBug")
    if name.startswith("oom-"):
        return _atheris_bug_record("CRASH", "Out of memory", exc_type="MemoryError")

    try:
        import json as _json
        data = crash_file.read_bytes()

        json_root = str(_HERE / "json-decoder-main")
        if json_root not in sys.path:
            sys.path.insert(0, json_root)
        from buggy_json import loads as buggy_loads  # type: ignore
        from buggy_json.decoder_stv import InvalidityBug, JSONDecodeError, PerformanceBug  # type: ignore

        try:
            ref_value = _json.loads(data)
            ref_ok = True
            ref_exc = None
        except Exception as exc:
            ref_ok = False
            ref_exc = exc

        try:
            candidate_value = buggy_loads(data)
            candidate_ok = True
            candidate_exc = None
            candidate_tb = ""
        except PerformanceBug as exc:
            return _atheris_bug_record(
                "TIMEOUT",
                f"PerformanceBug: {exc}",
                traceback_text="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                exc_type=type(exc).__name__,
            )
        except (JSONDecodeError, InvalidityBug, UnicodeDecodeError, ValueError) as exc:
            candidate_ok = False
            candidate_exc = exc
            candidate_tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        except Exception as exc:
            return _atheris_bug_record(
                "CRASH",
                f"Re-classification failed: {exc}",
                traceback_text="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                exc_type=type(exc).__name__,
            )

        if ref_ok and not candidate_ok:
            if isinstance(candidate_exc, InvalidityBug):
                return _atheris_bug_record(
                    "wrong_exception_type",
                    f"buggy_json raised InvalidityBug but should raise JSONDecodeError: {candidate_exc}",
                    traceback_text=candidate_tb,
                    exc_type=type(candidate_exc).__name__,
                )
            return _atheris_bug_record(
                "validity",
                f"stdlib accepted, buggy_json rejected: {candidate_exc}",
                traceback_text=candidate_tb,
                exc_type=type(candidate_exc).__name__,
            )
        if not ref_ok and candidate_ok:
            exc_type = type(ref_exc).__name__ if ref_exc is not None else ""
            return _atheris_bug_record(
                "oracle_mismatch",
                f"stdlib rejected, buggy_json accepted: {ref_exc}",
                exc_type=exc_type,
            )
        if ref_ok and candidate_ok:
            return _atheris_bug_record(
                "oracle_mismatch",
                "Decoded values differ between buggy_json and stdlib",
            )
        return _atheris_bug_record(
            "invalidity",
            "Both stdlib and buggy_json rejected the input",
            traceback_text=candidate_tb,
            exc_type=type(candidate_exc).__name__ if candidate_exc is not None else "",
        )
    except Exception as exc:
        return _atheris_bug_record(
            "CRASH",
            f"Re-classification failed: {exc}",
            traceback_text="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            exc_type=type(exc).__name__,
        )


def _postprocess_atheris_results(
    target: str,
    results_dir: Path,
    crashes_dir: Path,
    duration: float,
) -> None:
    """Generate structured result files from Atheris crash artifacts to match ipv4/ipv6 output."""
    import csv as _csv

    logs_dir = results_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    crash_files = [f for f in crashes_dir.glob("*") if f.is_file()]

    unique_bugs: dict[str, dict] = {}
    unique_findings: dict[str, dict] = {}
    bug_type_counts: Counter[str] = Counter()
    parser_site_bug_signatures: set[str] = set()
    traceback_bug_signatures: set[str] = set()
    bug_count_rows: dict[str, dict[str, object]] = {}

    for crash_file in crash_files:
        try:
            raw = crash_file.read_bytes()
            input_str = raw.decode("latin-1", errors="replace")
        except Exception:
            continue

        bug_record = _classify_atheris_crash(crash_file)
        bug_type = str(bug_record["bug_type"])
        exc_msg = str(bug_record["exception"])
        tb_text = str(bug_record.get("traceback", "") or "")
        exc_type = str(bug_record.get("exc_type", "") or "")
        bug_type_counts[bug_type] += 1
        bug_site = derive_bug_site(
            bug_type=bug_type,
            exception=exc_msg,
            traceback_text=tb_text,
            fallback_exc_type=exc_type,
        )
        site_key = str(bug_site["key"])

        entry = {
            "bug_type": bug_type,
            "exception": exc_msg,
            "example_input": input_str,
            "crash_file": crash_file.name,
            "first_seen_exec": 0,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "traceback": tb_text,
            "oracle": {
                "supported": False,
                "expected_valid": None,
                "reason": "",
                "shape": "",
                "normalized": None,
            },
            "classification": {
                "parser_reported_bug_type": None,
                "parser_reported_message": "",
                "taxonomy_tags": [bug_type],
            },
            "bug_site": {k: v for k, v in bug_site.items() if k != "key"},
            "signature": {
                "bug_type": bug_type,
                "exception": exc_msg,
                "bitmap_digest": "",
            },
            "total_occurrences": 1,
        }
        unique_findings[site_key] = entry
        if bug_type not in ("invalidity",):
            if site_key not in unique_bugs:
                unique_bugs[site_key] = entry
            else:
                unique_bugs[site_key]["total_occurrences"] = int(unique_bugs[site_key].get("total_occurrences", 1)) + 1
            if bug_site.get("dedup_source") == "traceback":
                traceback_bug_signatures.add(site_key)

        row_key = site_key
        if row_key not in bug_count_rows:
            bug_count_rows[row_key] = {
                "bug_type": bug_type,
                "exc_type": str(bug_site.get("exception_class", "") or exc_type),
                "exc_message": exc_msg,
                "filename": str(bug_site.get("filename", "") or ""),
                "lineno": "" if bug_site.get("lineno", None) is None else int(bug_site["lineno"]),
                "count": 0,
            }
        bug_count_rows[row_key]["count"] = int(bug_count_rows[row_key]["count"]) + 1

    # bugs.jsonl
    bugs_jsonl = results_dir / "bugs.jsonl"
    with open(bugs_jsonl, "w", encoding="utf-8") as f:
        for entry in unique_bugs.values():
            f.write(json.dumps(entry) + "\n")

    # unique_bugs.json
    (results_dir / "unique_bugs.json").write_text(
        json.dumps({
            "target": target,
            "count_definition": "Real bugs deduplicated by canonical bug site: traceback exception class plus source filename and line when available, otherwise parser-reported site, otherwise normalized fallback fields, and finally exception text.",
            "unique_bug_count": len(unique_bugs),
            "parser_site_unique_bug_count": len(parser_site_bug_signatures),
            "traceback_unique_bug_count": len(traceback_bug_signatures),
            "entries": list(unique_bugs.values()),
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    # unique_findings.json
    (results_dir / "unique_findings.json").write_text(
        json.dumps({
            "target": target,
            "unique_finding_count": len(unique_findings),
            "entries": list(unique_findings.values()),
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    # bug_coverage_summary.json
    total_crashes = len(crash_files)
    (results_dir / "bug_coverage_summary.json").write_text(
        json.dumps({
            "target": target,
            "run_scalars": {
                "wall_time_secs": round(duration, 1),
                "total_executions": "Atheris-managed",
                "execs_per_sec": "Atheris-managed",
                "coverage_seen": "Atheris-managed",
                "corpus_size": "Atheris-managed",
            },
            "totals": {
                "unique_findings": len(unique_findings),
                "unique_real_bugs": len(unique_bugs),
                "parser_site_unique_real_bugs": len(parser_site_bug_signatures),
                "traceback_unique_bugs": len(traceback_bug_signatures),
                "unique_crashes": total_crashes,
            },
            "by_bug_type": {
                "total": dict(sorted(bug_type_counts.items())),
                "unique": dict(sorted(Counter(entry["bug_type"] for entry in unique_findings.values()).items())),
                "unique_real": dict(sorted(Counter(entry["bug_type"] for entry in unique_bugs.values()).items())),
            },
        }, indent=2) + "\n",
        encoding="utf-8",
    )

    # logs/bug_counts.csv  (matches ipv4/ipv6 format)
    with open(logs_dir / "bug_counts.csv", "w", encoding="utf-8", newline="") as f:
        writer = _csv.writer(f)
        writer.writerow(["bug_type", "exc_type", "exc_message", "filename", "lineno", "count"])
        for row in sorted(
            bug_count_rows.values(),
            key=lambda row: (
                str(row["bug_type"]),
                str(row["filename"]),
                "" if row["lineno"] == "" else f"{int(row['lineno']):09d}",
                str(row["exc_type"]),
                str(row["exc_message"]),
            ),
        ):
            writer.writerow([
                row["bug_type"],
                row["exc_type"],
                row["exc_message"],
                row["filename"],
                row["lineno"],
                row["count"],
            ])

    # minimal plot_data CSV so plot_progress.py can render a chart
    plot_path = results_dir / "plot_data"
    if not plot_path.exists():
        with open(plot_path, "w", encoding="utf-8", newline="") as f:
            writer = _csv.writer(f)
            writer.writerow([
                "relative_time_sec", "total_execs", "coverage_seen",
                "interesting_test_cases", "corpus_size", "unique_bugs", "unique_crashes",
            ])
            writer.writerow([round(duration, 3), 0, 0, 0, 0, len(unique_bugs), total_crashes])

    stats_lines = [
        f"Target          : {target}",
        f"Wall time       : {duration:.1f}s",
        "Total execs     : Atheris-managed (see atheris.log)",
        "Coverage seen   : Atheris-managed (see atheris.log)",
        f"Interesting results: {sum(bug_type_counts.values())}",
        f"Unique bugs     : {len(unique_bugs)}",
        f"Parser-site uniq: {len(parser_site_bug_signatures)}",
        f"Traceback-unique: {len(traceback_bug_signatures)}",
        f"Unique crashes  : {total_crashes}",
    ]
    stats_text = "\n".join(stats_lines) + "\n"
    (results_dir / "stats.txt").write_text(stats_text, encoding="utf-8")
    (results_dir / "fuzzer_stats").write_text(stats_text, encoding="utf-8")

    print(f"[*] Post-processed: {len(unique_bugs)} unique bugs, {total_crashes} crashes → results/{target}/")


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
    run_id: str = "",
    coverage_mode: str = "auto",
) -> None:
    """Run the hybrid fuzzer against one target."""

    label = f"{target}_{run_id}" if run_id else target
    print(f"\n{'=' * 60}")
    print(f"[*] Target        : {label}")
    print(f"[*] Time budget   : {time_budget_secs}s")
    print(f"[*] Havoc iters   : {havoc_iters}")
    print(f"{'=' * 60}\n")

    startup_clock = time.perf_counter()

    if fresh_start:
        phase_clock = time.perf_counter()
        _reset_target_state(target, run_id)
        print(f"[*] Fresh-start cleanup: {_elapsed_ms(phase_clock):7.1f} ms")

    phase_clock = time.perf_counter()
    resolved_mode = _resolve_evaluation_mode(
        evaluation_mode,
        disable_dl=disable_dl,
    )
    print(f"[*] Mode resolved : {_elapsed_ms(phase_clock):7.1f} ms")

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
            run_id=run_id,
        )
        return

    if fmt.get("binary_windows") or fmt.get("binary_linux"):
        register_binary(
            target,
            windows=_HERE / fmt["binary_windows"] if fmt.get("binary_windows") else None,
            linux=_HERE / fmt["binary_linux"] if fmt.get("binary_linux") else None,
            windows_args=fmt.get("binary_windows_args"),
            linux_args=fmt.get("binary_linux_args"),
            input_arg=fmt.get("binary_input_arg"),
            input_encoding=fmt.get("binary_input_encoding"),
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
    _dl_bg_event: threading.Event | None = None
    _dl_bg_result: dict = {}
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
        import importlib.util
        if importlib.util.find_spec("torch") is None:
            if evaluation_mode == "hybrid_dl":
                raise RuntimeError(
                    "evaluation mode 'hybrid_dl' requires torch to be installed"
                )
            scheduler = StaticScheduler(fmt)
            resolved_mode = "static_payoff"
            _dl_bg_event = None
            print(
                f"[*] Scheduler     : StaticScheduler (torch not installed; fell back from auto) "
                f"({_elapsed_ms(phase_clock):7.1f} ms)"
            )
        else:
            # Start with static scheduler immediately; CUDA/DL init runs in background.
            scheduler = StaticScheduler(fmt)
            _dl_bg_result: dict = {}
            _dl_bg_event = threading.Event()

            def _init_dl_background(
                _target=target, _fmt=fmt, _run_id=run_id,
            ) -> None:
                try:
                    import torch as _torch
                    from dl.surrogate import CoverageSurrogate, DLScheduler
                    from dl.trainer import load_checkpoint
                    from dl.trustworthiness import is_trustworthy
                    _m = CoverageSurrogate()
                    _m._optimizer = _torch.optim.Adam(_m.parameters(), lr=1e-3)
                    _s = DLScheduler(_m, is_trustworthy, _fmt)
                    _ck = load_checkpoint(_m, _checkpoint_key(_target, _run_id), _s.device)
                    _m.eval()
                    _dl_bg_result.update({"model": _m, "scheduler": _s, "checkpoint_state": _ck})
                except Exception as _exc:
                    _dl_bg_result["error"] = str(_exc)
                finally:
                    _dl_bg_event.set()

            threading.Thread(
                target=_init_dl_background, daemon=True, name="dl-init"
            ).start()
            print(
                f"[*] Scheduler     : StaticScheduler → DLScheduler (CUDA warming up in background) "
                f"({_elapsed_ms(phase_clock):7.1f} ms)"
            )

    phase_clock = time.perf_counter()
    tier3 = HavocMutator(scheduler.get_operator_weights(b""))
    print(f"[*] Havoc primed  : {_elapsed_ms(phase_clock):7.1f} ms")

    phase_clock = time.perf_counter()
    executor = Executor(target, coverage_mode=coverage_mode)
    coverage = CoverageAnalyzer(use_afl_hit_count_buckets=executor.mode == "Frida")
    metrics = MetricsCollector(target, out_dir=_run_dir(target, run_id))

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
            "dl_enabled": model is not None or _dl_bg_event is not None,
            "dl_init_pending": _dl_bg_event is not None,
            "checkpoint_loaded": checkpoint_loaded,
            "checkpoint_metadata": checkpoint_metadata,
            "semantic_mutation_enabled": resolved_mode != "havoc_only",
            "gradient_guidance_enabled": not no_gradient_guidance,
            "behavior_proxy_dim": getattr(model, "COV_DIM", None),
            "behavior_proxy_note": (
                "DL model learns a compressed behavior proxy, not the full runtime bitmap"
                if model is not None or _dl_bg_event is not None
                else None
            ),
            "format_config": fmt,
        }
    )
    metrics.write_dl_summary(
        {
            "target": target,
            "dl_enabled": model is not None or _dl_bg_event is not None,
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
                if model is not None or _dl_bg_event is not None
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
        # Upgrade from StaticScheduler to DLScheduler once background CUDA init completes.
        if _dl_bg_event is not None and _dl_bg_event.is_set():
            if _dl_bg_result.get("model") is not None and model is None:
                model = _dl_bg_result["model"]
                scheduler = _dl_bg_result["scheduler"]
                _ck_state = _dl_bg_result.get("checkpoint_state", {})
                checkpoint_loaded = bool(_ck_state.get("loaded"))
                checkpoint_metadata = _json_safe_metadata(_ck_state.get("metadata", {}))
                scheduler.load_runtime_metadata(_ck_state.get("metadata"))
                _dl_bg_event = None
                print(
                    f"[DL] Upgraded to DLScheduler (device={scheduler.device}) "
                    f"after {time.time() - start:.0f}s elapsed"
                )
            elif _dl_bg_result.get("error") and model is None:
                print(f"[DL] Background init failed: {_dl_bg_result['error']} — continuing with StaticScheduler")
                _dl_bg_event = None

        generation_clock = time.perf_counter()
        seed = corpus.select(priority_fn=scheduler.get_seed_priority)
        metrics.record_energy(seed, scheduler.get_seed_priority(seed))

        plan = scheduler.plan_mutation(seed)
        hot_bytes = (
            []
            if no_gradient_guidance
            else getattr(scheduler, "get_hot_bytes", lambda current_seed: [])(seed)
        )

        # 5% of the time run the seed unmodified (all tiers skipped) so valid
        # inputs like 255.255.255.255 reach the parser intact.
        # Keep this low: each execution costs ~60 s so replay wastes budget.
        semantic_trace = {"applied": False}
        pass_through = random.random() < 0.05
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

            # Pick a second corpus entry for true cross-seed splice.
            splice_seed = corpus.select() if len(corpus) > 1 else None

            tier3 = HavocMutator(plan["weights"])
            mutated = tier3.mutate(
                mutated,
                iterations=havoc_iters,
                hot_bytes=hot_bytes,
                preferred_indices=preferred_indices,
                field_lookup=field_lookup,
                guided_ratio=0.0 if no_gradient_guidance else float(plan.get("guided_ratio", 0.7)),
                splice_seed=splice_seed,
            )
            havoc_trace = tier3.consume_last_trace()

        generation_ms = _elapsed_ms(generation_clock)
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

        metrics.record_timing(generation_ms, execution_ms)
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
                from dl.trainer import compute_misprediction_rate, save_checkpoint, train
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
                    _checkpoint_key(target, run_id),
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
        from dl.trainer import compute_misprediction_rate, save_checkpoint, train
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
            _checkpoint_key(target, run_id),
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
        f"Coverage: {final.behaviors_covered} | "
        f"Corpus size: {len(corpus)}"
    )


def _fuzz_worker(kwargs: dict) -> None:
    """Top-level worker so ProcessPoolExecutor can pickle it on Windows."""
    random.seed(kwargs.pop("rng_seed"))
    fuzz(**kwargs)


def _bootstrap_target(
    target: str,
    *,
    refresh: bool = False,
    examples_limit: int | None = None,
    model: str | None = None,
) -> None:
    fmt = load_format(target)
    profile, path = ensure_bootstrap_profile(
        target,
        fmt,
        refresh=refresh,
        examples_limit=examples_limit,
        model=model,
    )
    valid_count = len(profile.get("seed_examples_valid", []))
    invalid_count = len(profile.get("seed_examples_invalid", []))
    print(f"[*] Bootstrap target : {target}")
    print(f"[*] Bootstrap path   : {path}")
    print(f"[*] Bootstrap source : {profile.get('source', 'unknown')}")
    print(f"[*] Format kind      : {profile.get('format_kind', 'text')}")
    print(f"[*] Seed encoding    : {profile.get('seed_encoding', 'utf-8')}")
    print(f"[*] Seeds            : {valid_count} valid / {invalid_count} invalid")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Coverage-Guided Format Fuzzer")
    parser.add_argument(
        "target",
        help=(
            "Parser to fuzz (e.g. ipv4, ipv6, json, or any registered format; "
            "'all' runs ipv4+ipv6+cidrize; use 'bootstrap <target>' to cache "
            "LLM/manual seed profiles for new formats)"
        ),
    )
    parser.add_argument(
        "bootstrap_target",
        nargs="?",
        help="Target name for the bootstrap subcommand",
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
        "--instances",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Run N parallel instances of each target, each with a distinct RNG seed "
            "and writing to results/<target>_run1/, results/<target>_run2/, … "
            "(default: 1, writes to results/<target>/)"
        ),
    )
    parser.add_argument(
        "--refresh-bootstrap",
        action="store_true",
        help="Regenerate config/<target>_bootstrap.json even if it already exists",
    )
    parser.add_argument(
        "--bootstrap-examples-limit",
        type=int,
        default=None,
        help="Maximum total examples to request or emit during bootstrap generation",
    )
    parser.add_argument(
        "--bootstrap-model",
        default=None,
        help="Optional OpenAI model override for bootstrap generation",
    )
    parser.add_argument(
        "--coverage",
        choices=["auto", "frida", "hash"],
        default="auto",
        help=(
            "Coverage instrumentation mode: "
            "'auto' selects Frida on Linux with a linux binary, else behavior-hash; "
            "'frida' forces Frida edge coverage (requires Linux + linux binary); "
            "'hash' forces behavior-hash bitmap regardless of platform (default: auto)"
        ),
    )
    args = parser.parse_args()

    random.seed(args.seed)

    if args.target == "bootstrap":
        if not args.bootstrap_target:
            parser.error("bootstrap requires a target name, e.g. 'python main.py bootstrap pdf'")
        _bootstrap_target(
            args.bootstrap_target,
            refresh=args.refresh_bootstrap,
            examples_limit=args.bootstrap_examples_limit,
            model=args.bootstrap_model,
        )
        return

    fuzz_kwargs = dict(
        havoc_iters=args.havoc_iters,
        time_budget_secs=args.time_budget,
        seeds_n=args.seeds_n,
        disable_dl=args.no_dl,
        fresh_start=args.fresh_start,
        evaluation_mode=args.evaluation_mode,
        no_gradient_guidance=args.no_gradient_guidance,
        no_retrain=args.no_retrain,
        fixed_lr=args.fixed_lr,
        coverage_mode=args.coverage,
    )

    def _expand_worker_kwargs(targets: list[str]) -> list[dict]:
        """Expand a list of targets by --instances, assigning unique run_ids and seeds."""
        instances = args.instances
        if instances <= 1:
            return [{"target": t, "rng_seed": args.seed, **fuzz_kwargs} for t in targets]
        result = []
        for t in targets:
            for i in range(1, instances + 1):
                result.append({
                    "target": t,
                    "run_id": f"run{i}",
                    "rng_seed": args.seed + i - 1,
                    **fuzz_kwargs,
                })
        return result

    def _run_parallel(worker_kwargs_list: list[dict]) -> None:
        labels = [
            f"{kw['target']}_{kw['run_id']}" if kw.get("run_id") else kw["target"]
            for kw in worker_kwargs_list
        ]
        print(f"[*] Running {len(labels)} workers in parallel: {labels}")
        with concurrent.futures.ProcessPoolExecutor(max_workers=len(worker_kwargs_list)) as pool:
            futures = {pool.submit(_fuzz_worker, kw): label for kw, label in zip(worker_kwargs_list, labels)}
            for fut in concurrent.futures.as_completed(futures):
                label = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    print(f"[ERROR] {label} failed: {exc}")

    if args.target == "all":
        targets = ["ipv4", "ipv6", "cidrize", "json"]
        worker_kwargs = _expand_worker_kwargs(targets)
        _run_parallel(worker_kwargs)
    elif "," in args.target:
        targets = [t.strip() for t in args.target.split(",") if t.strip()]
        worker_kwargs = _expand_worker_kwargs(targets)
        _run_parallel(worker_kwargs)
    elif args.instances > 1:
        worker_kwargs = _expand_worker_kwargs([args.target])
        _run_parallel(worker_kwargs)
    else:
        fuzz(target=args.target, **fuzz_kwargs)


if __name__ == "__main__":
    main()
