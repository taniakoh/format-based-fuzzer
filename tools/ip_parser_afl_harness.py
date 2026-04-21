#!/usr/bin/env python3
"""
Minimal persistent AFL harness for the extracted IPv4/IPv6 parser modules.

This is intentionally leaner than ip_parser_source_runner.py:
- no per-input status output
- parser module imported once up front
- stdin-driven hot path for AFL/python-afl
- only expected invalid-input exceptions are swallowed
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import os
import sys
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


def _load_target(target: str):
    _configure_import_path(target)
    import pyparsing  # type: ignore

    if target == "ipv4":
        from buggy_ipyparse.ipv4_stv import IPv4, IPv4ParsingError, InvalidityBug  # type: ignore

        expected = (pyparsing.ParseException, IPv4ParsingError, InvalidityBug)
        return IPv4, expected

    parser_mod = _load_module_with_source_fallback(
        "buggy_ipyparse.ipv6_mstv",
        EXTRACTED_DIRS[target] / "buggy_ipyparse" / "ipv6_mstv.pyc",
        hidden_sys_path=EXTRACTED_DIRS[target],
    )

    expected = (
        pyparsing.ParseException,
        parser_mod.InvalidHexLength,
        parser_mod.InvalidIPLength,
        parser_mod.InvalidityBug,
    )
    return parser_mod.IPv6, expected


def _read_stdin_text() -> str:
    data = sys.stdin.buffer.read()
    return data.decode("latin-1", errors="replace")


def _run_once(parser_obj, expected_exceptions: tuple[type[BaseException], ...]) -> int:
    data = _read_stdin_text()
    try:
        parser_obj.parse_string(data)
    except expected_exceptions:
        return 0
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Persistent python-afl harness for the extracted IP parsers."
    )
    parser.add_argument("target", choices=("ipv4", "ipv6"))
    parser.add_argument(
        "--persistent",
        type=int,
        default=1000,
        metavar="N",
        help="Inputs per fork when running under python-afl (default: 1000)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single stdin input without AFL, useful for smoke tests",
    )
    parser.add_argument(
        "--fast-exit",
        action="store_true",
        help="Use os._exit(0) after completion to skip interpreter cleanup",
    )
    args = parser.parse_args()

    parser_obj, expected_exceptions = _load_target(args.target)

    if args.once:
        rc = _run_once(parser_obj, expected_exceptions)
        if args.fast_exit:
            os._exit(rc)
        return rc

    try:
        import afl  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "python-afl is required for persistent mode. Install it inside WSL/Linux."
        ) from exc

    while afl.loop(args.persistent):
        try:
            sys.stdin.seek(0)
        except (AttributeError, OSError):
            pass
        _run_once(parser_obj, expected_exceptions)

    if args.fast_exit:
        os._exit(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
