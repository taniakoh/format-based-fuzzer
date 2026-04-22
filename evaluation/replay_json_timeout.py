"""Replay a saved JSON timeout artifact against both reference and buggy decoders.

Usage:
    python evaluation/replay_json_timeout.py path/to/timeout-<sha1>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSON_TARGET_ROOT = ROOT / "json-decoder-main"


def _select_mode(data: bytes) -> str:
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


def _safe_json_loads_with_mode(data: bytes, mode: str):
    text = data.decode("utf-8", errors="strict")
    if mode == "strict_false":
        return json.loads(text, strict=False)
    if mode == "string_numbers":
        return json.loads(text, parse_int=str, parse_float=str)
    if mode == "pairs_hook":
        return json.loads(text, object_pairs_hook=list)
    return json.loads(text)


def _preview(data: bytes, limit: int = 160) -> str:
    text = data.decode("latin-1", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return text[:limit]


def _run_with_timeout(label: str, timeout_secs: int, thunk):
    alarm_supported = hasattr(signal, "SIGALRM") and hasattr(signal, "alarm")
    old_handler = signal.getsignal(signal.SIGALRM) if alarm_supported else None

    def _handler(signum, frame):
        raise TimeoutError(f"{label} timed out after {timeout_secs}s")

    try:
        if alarm_supported:
            signal.signal(signal.SIGALRM, _handler)
            signal.alarm(timeout_secs)
        value = thunk()
        return ("ok", value)
    except Exception as exc:  # noqa: BLE001
        return ("error", exc)
    finally:
        if alarm_supported:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a JSON timeout artifact.")
    parser.add_argument("artifact", help="Path to a timeout-* artifact file")
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-parser timeout in seconds for this replay (default: 30)",
    )
    args = parser.parse_args()

    artifact_path = Path(args.artifact).expanduser().resolve()
    if not artifact_path.exists():
        raise SystemExit(f"Artifact not found: {artifact_path}")

    data = artifact_path.read_bytes()
    digest = hashlib.sha1(data).hexdigest()
    mode = _select_mode(data)

    print(f"artifact: {artifact_path}")
    print(f"size: {len(data)} bytes")
    print(f"sha1: {digest}")
    print(f"mode: {mode}")
    print(f"preview: {_preview(data)}")

    loads, _PerformanceBug, _InvalidityBug, _JSONDecodeError = _load_buggy_json()

    ref_status, ref_value = _run_with_timeout(
        "reference json.loads",
        args.timeout,
        lambda: _safe_json_loads_with_mode(data, mode),
    )
    if ref_status == "ok":
        print(f"reference: ok ({type(ref_value).__name__})")
    else:
        print(f"reference: {type(ref_value).__name__}: {ref_value}")

    candidate_status, candidate_value = _run_with_timeout(
        "buggy_json.loads",
        args.timeout,
        lambda: _candidate_loads(loads, data, mode),
    )
    if candidate_status == "ok":
        print(f"candidate: ok ({type(candidate_value).__name__})")
        return 0

    print(f"candidate: {type(candidate_value).__name__}: {candidate_value}")
    if isinstance(candidate_value, TimeoutError):
        return 124
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
