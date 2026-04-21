"""Replay a JSON Atheris corpus through coverage.py to measure source coverage."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
JSON_TARGET_ROOT = ROOT / "json-decoder-main"
_PER_INPUT_TIMEOUT_SECS = 12


def _select_mode(data: bytes) -> str:
    """Mirror the JSON Atheris harness' decoder-mode selection."""
    if not data:
        return "default"
    selector = data[0] % 10
    if selector <= 5:
        return "default"
    if selector <= 7:
        return "strict_false"
    if selector == 8:
        return "string_numbers"
    return "pairs_hook"


def _load_buggy_json():
    if str(JSON_TARGET_ROOT) not in sys.path:
        sys.path.insert(0, str(JSON_TARGET_ROOT))

    from buggy_json import loads  # type: ignore
    from buggy_json.decoder_stv import InvalidityBug, JSONDecodeError, PerformanceBug  # type: ignore

    return loads, PerformanceBug, InvalidityBug, JSONDecodeError


def _candidate_loads(loads, data: bytes, mode: str):
    if mode == "strict_false":
        return loads(data, strict=False)
    if mode == "string_numbers":
        return loads(data, parse_int=str, parse_float=str)
    if mode == "pairs_hook":
        return loads(data, object_pairs_hook=list)
    return loads(data)


def _json_report_totals(cov) -> dict[str, float]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        report_path = Path(tmp.name)
    try:
        cov.json_report(outfile=str(report_path))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    finally:
        report_path.unlink(missing_ok=True)

    totals = report.get("totals", {})
    num_statements = int(totals.get("num_statements", 0) or 0)
    covered_lines = int(totals.get("covered_lines", 0) or 0)
    num_branches = int(totals.get("num_branches", 0) or 0)
    covered_branches = int(totals.get("covered_branches", 0) or 0)
    total_items = num_statements + num_branches
    covered_items = covered_lines + covered_branches
    percent_covered = (covered_items / total_items * 100.0) if total_items else 100.0

    return {
        "num_statements": float(num_statements),
        "covered_lines": float(covered_lines),
        "num_branches": float(num_branches),
        "covered_branches": float(covered_branches),
        "covered_items": float(covered_items),
        "total_items": float(total_items),
        "percent_statements_covered": float(totals.get("percent_statements_covered", 0.0) or 0.0),
        "percent_branches_covered": float(totals.get("percent_branches_covered", 0.0) or 0.0),
        "percent_covered": percent_covered,
    }


def _sorted_corpus_files(corpus_dir: Path) -> list[Path]:
    return sorted(
        [path for path in corpus_dir.iterdir() if path.is_file()],
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )


def generate_json_atheris_replay_coverage(results_dir: Path) -> Path | None:
    """Replay the saved JSON Atheris corpus and persist cumulative source coverage."""
    import coverage

    corpus_dir = results_dir / "atheris_corpus"
    if not corpus_dir.exists():
        return None

    corpus_files = _sorted_corpus_files(corpus_dir)
    if not corpus_files:
        return None

    loads, PerformanceBug, InvalidityBug, JSONDecodeError = _load_buggy_json()
    output_path = results_dir / "coverage_replay.json"
    data_file = results_dir / ".coverage_buggy_json_replay"
    data_file.unlink(missing_ok=True)

    cov = coverage.Coverage(
        data_file=str(data_file),
        source=["buggy_json"],
        branch=True,
    )

    rows: list[dict[str, float | int | str]] = []
    alarm_supported = hasattr(signal, "SIGALRM") and hasattr(signal, "alarm")
    old_alarm_handler = signal.getsignal(signal.SIGALRM) if alarm_supported else None

    def _timeout_handler(signum, frame):
        raise TimeoutError("coverage replay timed out")

    try:
        for corpus_size, corpus_file in enumerate(corpus_files, start=1):
            data = corpus_file.read_bytes()
            mode = _select_mode(data)

            cov.start()
            try:
                if alarm_supported:
                    signal.signal(signal.SIGALRM, _timeout_handler)
                    signal.alarm(_PER_INPUT_TIMEOUT_SECS)
                _candidate_loads(loads, data, mode)
            except (
                TimeoutError,
                PerformanceBug,
                InvalidityBug,
                JSONDecodeError,
                UnicodeDecodeError,
                ValueError,
                TypeError,
                RecursionError,
            ):
                pass
            finally:
                if alarm_supported:
                    signal.alarm(0)
                cov.stop()

            totals = _json_report_totals(cov)
            rows.append(
                {
                    "corpus_size": corpus_size,
                    "filename": corpus_file.name,
                    **totals,
                }
            )
    finally:
        if alarm_supported and old_alarm_handler is not None:
            signal.signal(signal.SIGALRM, old_alarm_handler)

    cov.save()
    payload = {
        "target": results_dir.name,
        "coverage_kind": "coverage.py combined source coverage",
        "denominator": "All statements and branches reported by coverage.py for buggy_json",
        "corpus_order": "atheris_corpus files sorted by mtime then filename",
        "coverage_data_file": str(data_file),
        "generated_from": str(corpus_dir),
        "generated_rows": len(rows),
        "final": rows[-1] if rows else _json_report_totals(cov),
        "rows": rows,
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return output_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay a JSON Atheris corpus and write cumulative coverage.py totals.",
    )
    parser.add_argument(
        "target_or_results_dir",
        help="Target name like 'json' or a direct path to results/<target>.",
    )
    return parser.parse_args()


def _resolve_results_dir(target_or_results_dir: str) -> Path:
    candidate = Path(target_or_results_dir)
    if candidate.exists():
        return candidate
    return RESULTS_DIR / target_or_results_dir


def main() -> None:
    args = _parse_args()
    results_dir = _resolve_results_dir(args.target_or_results_dir)
    output_path = generate_json_atheris_replay_coverage(results_dir)
    if output_path is None:
        raise SystemExit(f"No Atheris corpus found under {results_dir}")
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
