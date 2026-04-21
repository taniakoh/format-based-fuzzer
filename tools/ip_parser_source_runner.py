#!/usr/bin/env python3
"""
Run the extracted IPv4/IPv6 parser logic directly from the PyInstaller payload.

This bypasses the heavyweight top-level packaged CLI wrappers so the parser can
be instrumented from source-ish Python bytecode inside WSL/Linux.

Examples
--------
python3 tools/ip_parser_source_runner.py ipv4 --ipstr 1.2.3.4
printf '2001:db8::1' | python3 tools/ip_parser_source_runner.py ipv6 --stdin

Optional python-afl usage
-------------------------
py-afl-fuzz -i corpus -o findings -- \
    python3 tools/ip_parser_source_runner.py ipv4 --stdin --persistent 1000
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import sys
import traceback
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACTED_DIRS = {
    "ipv4": REPO_ROOT / "linux-ipv4-parser_extracted" / "PYZ.pyz_extracted",
    "ipv6": REPO_ROOT / "linux-ipv6-parser_extracted" / "PYZ.pyz_extracted",
}


def _configure_import_path(target: str) -> None:
    extracted_dir = EXTRACTED_DIRS[target]
    if not extracted_dir.exists():
        raise FileNotFoundError(
            f"Expected extracted parser payload at {extracted_dir}. "
            "Run pyinstxtractor against the Linux parser binary first."
        )
    sys.path.insert(0, str(extracted_dir))


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


def _load_parser(target: str):
    _configure_import_path(target)
    if target == "ipv4":
        from buggy_ipyparse.ipv4_stv import IPv4  # type: ignore

        return IPv4

    parser_mod = _load_module_with_source_fallback(
        "buggy_ipyparse.ipv6_mstv",
        EXTRACTED_DIRS[target] / "buggy_ipyparse" / "ipv6_mstv.pyc",
        hidden_sys_path=EXTRACTED_DIRS[target],
    )
    return parser_mod.IPv6


def _read_input(args: argparse.Namespace) -> str:
    if args.stdin:
        data = sys.stdin.buffer.read()
        return data.decode("latin-1", errors="replace")
    return args.ipstr


def _run_once(parser_obj, target: str, input_str: str, quiet: bool) -> int:
    if not quiet:
        print(f"Running the {target.upper()} parser with ipstr: {input_str}")

    try:
        result = parser_obj.parse_string(input_str)
    except Exception as exc:
        print("============================================================")
        print("TRACEBACK")
        print("============================================================")
        traceback.print_exc()
        print("============================================================")
        print(f"Exception type: {type(exc).__name__}")
        print(f"Exception message: {exc}")
        return 1

    if not quiet:
        print(f"Output: {result}")
        print("No bugs found. Skipping CSV creation")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the extracted IPv4/IPv6 parser module directly for source-level "
            "instrumentation in Linux/WSL."
        )
    )
    parser.add_argument("target", choices=("ipv4", "ipv6"))
    parser.add_argument("--ipstr", default="", help="Input string to parse")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read the parser input from stdin instead of --ipstr",
    )
    parser.add_argument(
        "--persistent",
        type=int,
        default=0,
        metavar="N",
        help="Use python-afl persistent mode for N iterations per fork",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only emit parse results or tracebacks",
    )
    args = parser.parse_args()

    parser_obj = _load_parser(args.target)

    if args.persistent:
        try:
            import afl  # type: ignore
        except ImportError as exc:
            raise SystemExit(
                "--persistent requires the python-afl module inside WSL/Linux"
            ) from exc

        while afl.loop(args.persistent):
            sys.stdin.seek(0)
            input_str = _read_input(args)
            _run_once(parser_obj, args.target, input_str, args.quiet)
        return 0

    input_str = _read_input(args)
    return _run_once(parser_obj, args.target, input_str, args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
