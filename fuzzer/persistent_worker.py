"""Persistent worker for extracted Linux parser bundles."""

from __future__ import annotations

import argparse
import importlib
import importlib.machinery
import importlib.util
import json
import sys
import traceback
from pathlib import Path


def _load_pyc_module(module_name: str, pyc_path: Path):
    loader = importlib.machinery.SourcelessFileLoader(module_name, str(pyc_path))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None:
        raise ImportError(f"Could not create spec for {module_name} from {pyc_path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _load_module_with_source_fallback(module_name: str, pyc_path: Path, hidden_sys_path: Path | None = None):
    try:
        return _load_pyc_module(module_name, pyc_path)
    except ImportError as exc:
        source_path = pyc_path.with_suffix(".py")
        if not source_path.exists():
            raise
        spec = importlib.util.spec_from_file_location(module_name, source_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not create spec for {module_name} from {source_path}") from exc
        module = importlib.util.module_from_spec(spec)
        hidden_entry = str(hidden_sys_path.resolve()) if hidden_sys_path is not None else None
        removed_indexes: list[int] = []
        if hidden_entry is not None:
            removed_indexes = [i for i, entry in enumerate(sys.path) if Path(entry or ".").resolve() == Path(hidden_entry)]
            for i in reversed(removed_indexes):
                sys.path.pop(i)
        try:
            spec.loader.exec_module(module)
        finally:
            if hidden_entry is not None:
                for i in removed_indexes:
                    sys.path.insert(i, hidden_entry)
        return module


def _build_runtime(target: str) -> dict[str, object]:
    root = Path(__file__).resolve().parent.parent
    if target == "ipv4":
        bundle_root = root / "linux-ipv4-parser_extracted" / "PYZ.pyz_extracted"
        if str(bundle_root) not in sys.path:
            sys.path.append(str(bundle_root))
        parser_mod = _load_pyc_module(
            "buggy_ipyparse.ipv4_stv",
            bundle_root / "buggy_ipyparse" / "ipv4_stv.pyc",
        )
        return {
            "parser": parser_mod.IPv4,
            "custom_map": {
                "InvalidityBug": "invalidity",
                "FunctionalBug": "functional",
                "BoundaryBug": "boundary",
                "PerformanceBug": "performance",
                "ParseException": "invalidity",
            },
        }
    if target == "ipv6":
        bundle_root = root / "linux-ipv6-parser_extracted" / "PYZ.pyz_extracted"
        # Append (not insert) so system site-packages take precedence over bundled
        # .pyc files (which may have a different Python version's magic number).
        if str(bundle_root) not in sys.path:
            sys.path.append(str(bundle_root))
        parser_mod = _load_module_with_source_fallback(
            "buggy_ipyparse.ipv6_mstv",
            bundle_root / "buggy_ipyparse" / "ipv6_mstv.pyc",
            hidden_sys_path=bundle_root,
        )
        return {
            "parser": parser_mod.IPv6,
            "custom_map": {
                "InvalidityBug": "invalidity",
                "FunctionalBug": "functional",
                "BoundaryBug": "boundary",
                "PerformanceBug": "performance",
                "ReliabilityBug": "reliability",
                "ParseException": "invalidity",
            },
        }
    raise ValueError(f"persistent worker does not support target {target!r}")


def _handle_case(runtime: dict[str, object], input_str: str) -> dict[str, object]:
    parser = runtime["parser"]
    custom_map = runtime["custom_map"]
    try:
        result = parser.parse_string(input_str, parse_all=True)
        return {
            "bug_type": "PASS",
            "exception_msg": "",
            "traceback": "",
            "stdout": f"Output: {result}",
            "stderr": "",
            "exit_code": 0,
            "parser_reported_bug_type": None,
            "parser_reported_message": "",
            "parser_reported_exc_type": "",
            "parser_reported_filename": "",
            "parser_reported_lineno": None,
        }
    except Exception as exc:
        exc_type = type(exc).__name__
        tb_text = traceback.format_exc()
        frames = traceback.extract_tb(exc.__traceback__)
        last_frame = frames[-1] if frames else None
        parser_bug_type = custom_map.get(exc_type, "bonus")
        return {
            "bug_type": parser_bug_type,
            "exception_msg": str(exc),
            "traceback": tb_text,
            "stdout": "",
            "stderr": "",
            "exit_code": 1,
            "parser_reported_bug_type": parser_bug_type,
            "parser_reported_message": str(exc),
            "parser_reported_exc_type": exc_type,
            "parser_reported_filename": last_frame.filename if last_frame else "",
            "parser_reported_lineno": last_frame.lineno if last_frame else None,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Persistent parser worker")
    parser.add_argument("--target", required=True, choices=("ipv4", "ipv6"))
    args = parser.parse_args()

    runtime = _build_runtime(args.target)
    print(json.dumps({"status": "ready", "target": args.target}), flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        command = request.get("command", "run")
        if command == "shutdown":
            print(json.dumps({"status": "bye"}), flush=True)
            return 0
        if command != "run":
            print(json.dumps({"status": "error", "error": f"unknown command {command!r}"}), flush=True)
            continue
        response = _handle_case(runtime, str(request.get("input", "")))
        response["status"] = "ok"
        print(json.dumps(response), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
