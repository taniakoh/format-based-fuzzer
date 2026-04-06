"""
Module 4 — Execution Engine.

Wraps the parser binaries and returns a (behavior_bitmap, crashed, result)
triple that mirrors the AFL++ interface described in the implementation guide.

Coverage modes
--------------
Three modes are selected automatically at startup:

  QEMU      Linux binary + afl-showmap -Q available
            → real 65536-byte edge-coverage bitmap from AFL++ QEMU
              instrumentation.  Thousands of unique edges possible.
              Timeout: 5 s (no PyInstaller overhead).

  Linux     Linux binary present but afl-showmap not found
            → behavior-hash bitmap (same as Windows mode) but with
              faster execution.  Timeout: 5 s.

  Windows   Opaque PyInstaller .exe bundles (win-ipv4/ipv6-parser.exe)
            → behavior-hash bitmap: each unique (bug_type, exception_msg)
              pair is SHA-256 hashed to a stable slot in the bitmap.
              Timeout: 60 s (PyInstaller unpacks to a temp dir at startup).

The Executor.mode property exposes which mode is active so callers can
log it at startup.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from fuzzer.oracle import OracleVerdict, evaluate_target_input

_HERE = Path(__file__).parent.parent

# Timeouts
TIMEOUT_SECONDS_WIN   = 60   # PyInstaller bundles need ~20-30 s to unpack
TIMEOUT_SECONDS_LINUX = 30   # Native ELF — no unpack overhead

BITMAP_SIZE = 65536

# ── Binary registry ───────────────────────────────────────────────────────────

_WINDOWS_BINARIES: dict[str, Path] = {
    "ipv4": _HERE / "ipv4ipv6" / "win-ipv4-parser.exe",
    "ipv6": _HERE / "ipv4ipv6" / "win-ipv6-parser.exe",
}

_LINUX_BINARIES: dict[str, Path] = {
    "ipv4": _HERE / "ipv4ipv6" / "linux-ipv4-parser",
    "ipv6": _HERE / "ipv4ipv6" / "linux-ipv6-parser",
}

_WINDOWS_ARGS: dict[str, list[str]] = {}
_LINUX_ARGS: dict[str, list[str]] = {}


def register_binary(
    target: str,
    windows: str | Path | None = None,
    linux: str | Path | None = None,
    windows_args: list[str] | None = None,
    linux_args: list[str] | None = None,
) -> None:
    """Register binary paths for a new target format.

    Call this before constructing an ``Executor`` for the target, or supply
    ``binary_windows`` / ``binary_linux`` keys in the format config JSON and
    let ``main.py`` call this automatically.
    """
    if windows is not None:
        _WINDOWS_BINARIES[target.lower()] = Path(windows)
    if linux is not None:
        _LINUX_BINARIES[target.lower()] = Path(linux)
    if windows_args is not None:
        _WINDOWS_ARGS[target.lower()] = list(windows_args)
    if linux_args is not None:
        _LINUX_ARGS[target.lower()] = list(linux_args)

# ── Platform helpers ──────────────────────────────────────────────────────────

_IS_LINUX = sys.platform != "win32"


def _afl_showmap() -> str | None:
    """Return the path to afl-showmap if installed AND QEMU mode is available.

    QEMU mode requires the ``afl-qemu-trace`` binary alongside ``afl-showmap``.
    If that helper is absent, running ``afl-showmap -Q`` fails immediately with
    "Program 'afl-qemu-trace' not found", so we treat the whole capability as
    unavailable and fall back to Linux behavior-hash mode.
    """
    showmap = shutil.which("afl-showmap")
    if showmap is None:
        return None
    # afl-qemu-trace lives in the same directory as afl-showmap
    showmap_dir = Path(showmap).parent
    qemu_trace = showmap_dir / "afl-qemu-trace"
    if not qemu_trace.exists() and shutil.which("afl-qemu-trace") is None:
        return None
    return showmap


def _ensure_executable(path: Path) -> None:
    """Make sure a Linux binary has the execute bit set."""
    if _IS_LINUX:
        try:
            current = path.stat().st_mode
            path.chmod(current | 0o111)
        except PermissionError:
            pass  # /mnt/c (NTFS) doesn't support chmod; file is already executable


# ── Output parsing ────────────────────────────────────────────────────────────

_TRACEBACK_BLOCK_RE = re.compile(
    r"={60}\s*\nTRACEBACK\s*\n={60}\s*\n(.*?)\n={60}",
    re.DOTALL,
)
_TRACEBACK_LAST_LINE_RE = re.compile(r"^\s*([\w.]+):\s*(.*)$")
_STDERR_TRACEBACK_RE = re.compile(r"(Traceback \(most recent call last\):.*)", re.DOTALL)
_PARSER_VALIDITY_RE = re.compile(r"\bA validity bug has been triggered:\s*(.+)", re.IGNORECASE)
_PARSER_INVALIDITY_RE = re.compile(r"\bAn invalidity bug has been triggered:\s*(.+)", re.IGNORECASE)
_PARSER_FINAL_BUG_RE = re.compile(r"\('(?P<kind>validity|invalidity|bonus|syntactic|reliability)'", re.IGNORECASE)


class BugType:
    PASS       = "PASS"
    VALIDITY   = "validity"
    INVALIDITY = "invalidity"
    SYNTACTIC  = "syntactic"
    RELIABILITY = "reliability"
    BONUS      = "bonus"
    CRASH      = "CRASH"
    TIMEOUT    = "TIMEOUT"
    ORACLE_MISMATCH = "oracle_mismatch"
    ORACLE_UNKNOWN_ACCEPT = "oracle_unknown_accept"
    ORACLE_UNKNOWN_REJECT = "oracle_unknown_reject"


@dataclass
class RunResult:
    input_str:     str
    bug_type:      str
    exit_code:     int | None
    stdout:        str
    stderr:        str
    exception_msg: str = ""
    traceback:     str = ""
    oracle:        OracleVerdict | None = None
    parser_reported_bug_type: str | None = None
    parser_reported_message: str = ""

    @property
    def is_interesting(self) -> bool:
        return self.bug_type != BugType.PASS

    @property
    def is_validity_bug(self) -> bool:
        return self.bug_type == BugType.VALIDITY

    @property
    def is_crash(self) -> bool:
        return self.bug_type in (BugType.CRASH, BugType.TIMEOUT)

    @property
    def is_real_bug(self) -> bool:
        return self.bug_type in (
            BugType.VALIDITY,
            BugType.BONUS,
            BugType.RELIABILITY,
            BugType.CRASH,
            BugType.TIMEOUT,
            BugType.ORACLE_MISMATCH,
        )


def _parse_output(stdout: str, stderr: str) -> tuple[str, str]:
    combined = stdout + "\n" + stderr

    tb_match       = _TRACEBACK_BLOCK_RE.search(combined)
    traceback_text = tb_match.group(1).strip() if tb_match else ""
    if not traceback_text:
        stderr_tb = _STDERR_TRACEBACK_RE.search(stderr)
        if stderr_tb:
            traceback_text = stderr_tb.group(1).strip()

    exception_msg = ""
    if traceback_text:
        lines = [l for l in traceback_text.splitlines() if l.strip()]
        if lines:
            exception_msg = lines[-1].strip()
    if not exception_msg:
        exception_msg = _summarize_process_failure(stdout, stderr, None)
        if exception_msg == "process failed before reporting an exit code":
            exception_msg = ""

    return exception_msg, traceback_text


def _parser_reported_bug(stdout: str) -> tuple[str | None, str]:
    """Extract the parser-declared bug family and message from stdout."""
    match = _PARSER_VALIDITY_RE.search(stdout)
    if match:
        return BugType.VALIDITY, match.group(1).strip()

    match = _PARSER_INVALIDITY_RE.search(stdout)
    if match:
        return BugType.INVALIDITY, match.group(1).strip()

    match = _PARSER_FINAL_BUG_RE.search(stdout)
    if match:
        return match.group("kind").lower(), ""

    return None, ""


def _taxonomy_tags(result: "RunResult") -> list[str]:
    tags: list[str] = []

    if result.parser_reported_bug_type == BugType.VALIDITY or result.bug_type == BugType.VALIDITY:
        tags.append("ValidityBug")
    elif result.parser_reported_bug_type == BugType.INVALIDITY or result.bug_type == BugType.INVALIDITY:
        tags.append("InvalidityBug")
    elif result.parser_reported_bug_type == BugType.SYNTACTIC or result.bug_type == BugType.SYNTACTIC:
        tags.append("SyntacticBug")

    if result.bug_type == BugType.ORACLE_MISMATCH:
        tags.append("FunctionalBug")
    if result.is_crash or result.bug_type == BugType.RELIABILITY:
        tags.append("ReliabilityBug")
        if result.bug_type == BugType.TIMEOUT:
            tags.append("PerformanceBug")
    if result.bug_type == BugType.BONUS:
        tags.append("Bonus/UntrackedBugs")
    if _is_boundary_input(result.input_str):
        tags.append("BoundaryBug")

    # Keep tag order stable while preventing duplicates.
    return list(dict.fromkeys(tags))


_IPV6_BOUNDARY_ADDRS = {
    "::",                                              # all-zeros
    "::1",                                             # loopback
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",        # all-ones
    "::ffff:0:0",                                      # IPv4-mapped base
    "::ffff:ffff:ffff",                                # IPv4-mapped top
    "fe80::",                                          # link-local base
    "fec0::",                                          # site-local base (deprecated)
    "ff00::",                                          # multicast base
}

_CIDR_BOUNDARY_PREFIXES = {"0", "32", "128"}


def _is_boundary_input(input_str: str) -> bool:
    # IPv4: boundary octets (0, 1, 254, 255)
    parts = input_str.split(".")
    if len(parts) == 4:
        try:
            octets = [int(part, 10) for part in parts]
            if any(octet in {0, 1, 254, 255} for octet in octets):
                return True
        except ValueError:
            pass

    # IPv6: known boundary addresses
    if input_str.lower() in _IPV6_BOUNDARY_ADDRS:
        return True

    # CIDR: boundary prefix lengths (/0, /32, /128) or boundary base addresses
    if "/" in input_str:
        base, _, prefix = input_str.partition("/")
        if prefix.strip() in _CIDR_BOUNDARY_PREFIXES:
            return True
        # Base is a boundary IPv4 address
        base_parts = base.strip().split(".")
        if len(base_parts) == 4:
            try:
                base_octets = [int(p, 10) for p in base_parts]
                if any(o in {0, 255} for o in base_octets):
                    return True
            except ValueError:
                pass

    return False


def _traceback_exception_type(traceback_text: str) -> str:
    """Return the exception class name from the traceback footer when present."""
    if not traceback_text:
        return ""
    lines = [line.strip() for line in traceback_text.splitlines() if line.strip()]
    if not lines:
        return ""
    match = _TRACEBACK_LAST_LINE_RE.match(lines[-1])
    if not match:
        return ""
    return match.group(1)


def _cli_safe_input(input_data: bytes) -> str:
    """Render fuzz bytes as a CLI-safe text argument.

    The parser targets accept text via ``--ipstr``. Some byte sequences, most
    notably ``0x00``, cannot be transported through argv at all and would cause
    Python's subprocess layer to fail before the target launches. We therefore
    keep printable ASCII as-is and escape everything else into a stable textual
    representation.
    """
    return input_data.decode("latin-1", errors="replace").encode(
        "unicode_escape"
    ).decode("ascii")


def _summarize_process_failure(
    stdout: str, stderr: str, returncode: int | None
) -> str:
    """Extract a stable crash signature for launcher/runtime failures."""
    for stream in (stderr, stdout):
        for line in stream.splitlines():
            message = line.strip()
            if message:
                return message[:200]
    if returncode is None:
        return "process failed before reporting an exit code"
    return f"process exited with code {returncode}"


# ── Behavior bitmap (fallback for non-QEMU modes) ─────────────────────────────

def _result_to_bitmap(result: RunResult) -> bytes:
    """
    Map a RunResult to a sparse behavior bitmap (no AFL++ required).

    A PASS returns an all-zero bitmap (no new information).
    Any other result sets a single byte determined by hashing the
    (bug_type, exception_msg) pair — giving each unique error a stable slot.
    """
    bitmap = bytearray(BITMAP_SIZE)
    if result.bug_type == BugType.PASS:
        return bytes(bitmap)
    return _overlay_result_signal(bitmap, result)


def _overlay_result_signal(bitmap: bytearray, result: RunResult) -> bytes:
    """Overlay stable fallback signals onto an existing bitmap.

    This keeps behavior-hash mode and QEMU mode consistent for outcomes where
    coverage alone is not a reliable notion of "interesting", especially for
    crashes/timeouts and oracle-backed validity failures.

    Slot allocation (to avoid collisions):
      bytes 0-1 : behavior hash  (bug_type + sha256(exception_msg))
      bytes 2-3 : extra slot for CRASH/TIMEOUT/VALIDITY
      bytes 4-5 : traceback hash (bug_type + full traceback text)
    """
    if result.bug_type == BugType.PASS:
        return bytes(bitmap)

    key = f"{result.bug_type}|{hashlib.sha256(result.exception_msg.encode()).hexdigest()}"
    digest = hashlib.sha256(key.encode()).digest()
    pos = (digest[0] << 8 | digest[1]) % BITMAP_SIZE
    bitmap[pos] = 1

    if result.bug_type in (BugType.CRASH, BugType.TIMEOUT, BugType.VALIDITY):
        pos2 = (digest[2] << 8 | digest[3]) % BITMAP_SIZE
        bitmap[pos2] = 1

    # Separate traceback-based slot: distinguishes bugs with the same exception
    # message but different call stacks (e.g. same ParseException at different lines).
    if result.traceback:
        tb_key = f"traceback|{result.bug_type}|{result.traceback.strip()[:256]}"
        tb_digest = hashlib.sha256(tb_key.encode()).digest()
        tb_pos = (tb_digest[4] << 8 | tb_digest[5]) % BITMAP_SIZE
        bitmap[tb_pos] = 1

    return bytes(bitmap)


# ── Executor ──────────────────────────────────────────────────────────────────

class Executor:
    """
    Execution engine for the IP-address parser binaries.

    Selects QEMU / Linux / Windows mode automatically based on the
    current platform and available tools.  The public interface is always:

        bitmap, crashed, result = executor.run(input_bytes)

    Check ``executor.mode`` after construction to see which mode is active.
    """

    def __init__(self, target: str, timeout_seconds: int | None = None, use_qemu: bool = True):
        self.target = target

        # ── Select binary and mode ────────────────────────────────────────────
        linux_bin = _LINUX_BINARIES.get(target)
        win_bin   = _WINDOWS_BINARIES.get(target)

        if linux_bin is None and win_bin is None:
            registered = sorted(set(_WINDOWS_BINARIES) | set(_LINUX_BINARIES))
            raise ValueError(
                f"No binary registered for target '{target}'. "
                f"Registered targets: {registered}. "
                f"Call register_binary('{target}', windows=..., linux=...) "
                f"or add 'binary_windows'/'binary_linux' to config/{target}_format.json."
            )

        afl = _afl_showmap() if use_qemu else None

        if _IS_LINUX and linux_bin is not None and linux_bin.exists():
            self.binary  = linux_bin
            self._fixed_args = list(_LINUX_ARGS.get(target, []))
            _ensure_executable(linux_bin)
            self.timeout = timeout_seconds or TIMEOUT_SECONDS_LINUX
            if afl is not None:
                self._mode        = "QEMU"
                self._afl_showmap = afl
            else:
                self._mode        = "Linux"
                self._afl_showmap = None
        else:
            if win_bin is None or not win_bin.exists():
                raise FileNotFoundError(
                    f"No binary found for target '{target}'. "
                    f"Expected {win_bin} or {linux_bin}."
                )
            self.binary           = win_bin
            self._fixed_args      = list(_WINDOWS_ARGS.get(target, []))
            self.timeout          = timeout_seconds or TIMEOUT_SECONDS_WIN
            self._mode            = "Windows"
            self._afl_showmap     = None

    @property
    def mode(self) -> str:
        """One of 'QEMU', 'Linux', or 'Windows'."""
        return self._mode

    # ── Public run method ─────────────────────────────────────────────────────

    def run(self, input_data: bytes) -> tuple[bytes, bool, RunResult]:
        """
        Execute the parser with the given input.

        Returns
        -------
        (behavior_bitmap, crashed, result)
        """
        input_str = _cli_safe_input(input_data)

        if self._mode == "QEMU":
            return self._run_with_qemu(input_str)

        result = self._run_binary(input_str)
        bitmap = _result_to_bitmap(result)
        return bitmap, result.is_crash, result

    # ── QEMU mode ─────────────────────────────────────────────────────────────

    def _run_with_qemu(self, input_str: str) -> tuple[bytes, bool, RunResult]:
        """
        Run under ``afl-showmap -Q`` to obtain a real AFL++ edge-coverage bitmap.

        afl-showmap writes a raw BITMAP_SIZE-byte file to a temp path.
        The target's stdout/stderr pass through for bug-type parsing.
        """
        bitmap_fd, bitmap_path = tempfile.mkstemp(suffix=".afl_bitmap")
        os.close(bitmap_fd)

        cmd = [
            self._afl_showmap,
            "-Q",                            # QEMU instrumentation — no source needed
            "-b",                            # write raw binary bitmap (not ASCII tuples)
            "-o", bitmap_path,
            "-t", str(self.timeout * 1000),  # afl-showmap takes milliseconds
            "-q",                            # suppress afl-showmap's own banner/progress
            "--",
            str(self.binary),
            *self._fixed_args,
            f"--ipstr={input_str}",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                errors="replace",
                timeout=self.timeout + 5,   # outer Python timeout > inner AFL timeout
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            # Read the raw edge-coverage bitmap written by afl-showmap
            try:
                with open(bitmap_path, "rb") as f:
                    raw = f.read()
                # Normalise to exactly BITMAP_SIZE bytes
                if len(raw) >= BITMAP_SIZE:
                    bitmap = bytes(raw[:BITMAP_SIZE])
                else:
                    bitmap = raw + b"\x00" * (BITMAP_SIZE - len(raw))
            except (FileNotFoundError, OSError):
                # afl-showmap may not write the file if the binary crashed
                # immediately — fall back to an empty bitmap
                bitmap = bytes(BITMAP_SIZE)

        except subprocess.TimeoutExpired:
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.TIMEOUT,
                exit_code=None,
                stdout="", stderr="",
                exception_msg="Process timed out",
            )
            return _result_to_bitmap(result), True, result

        except Exception as exc:
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="", stderr="",
                exception_msg=str(exc),
            )
            return _result_to_bitmap(result), True, result

        finally:
            try:
                os.unlink(bitmap_path)
            except OSError:
                pass

        exc_msg, tb = _parse_output(stdout, stderr)
        if proc.returncode == 2:
            # afl-showmap exit code 2 = internal timeout
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.TIMEOUT,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                exception_msg="Process timed out (afl-showmap)",
            )
            return _result_to_bitmap(result), True, result
        elif proc.returncode not in (0, 1):
            bug_type = BugType.CRASH
            exc_msg = _summarize_process_failure(stdout, stderr, proc.returncode)
        else:
            bug_type = BugType.PASS

        result = RunResult(
            input_str=input_str,
            bug_type=bug_type,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            exception_msg=exc_msg,
            traceback=tb,
        )
        parser_bug_type, parser_bug_message = _parser_reported_bug(stdout)
        result.parser_reported_bug_type = parser_bug_type
        result.parser_reported_message = parser_bug_message
        result = self._apply_oracle(result)
        enriched_bitmap = _overlay_result_signal(bytearray(bitmap), result)
        return enriched_bitmap, result.is_crash, result

    # ── Shared binary runner (Linux-no-AFL and Windows) ───────────────────────

    def _run_binary(self, input_str: str) -> RunResult:
        cmd = [str(self.binary), *self._fixed_args, f"--ipstr={input_str}"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                input_str=input_str,
                bug_type=BugType.TIMEOUT,
                exit_code=None,
                stdout="", stderr="",
                exception_msg="Process timed out",
            )
        except Exception as exc:
            return RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="", stderr="",
                exception_msg=str(exc),
            )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        exc_msg, tb = _parse_output(stdout, stderr)

        if proc.returncode not in (0, 1):
            bug_type = BugType.CRASH
            exc_msg = _summarize_process_failure(stdout, stderr, proc.returncode)
        else:
            bug_type = BugType.PASS

        result = RunResult(
            input_str=input_str,
            bug_type=bug_type,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            exception_msg=exc_msg,
            traceback=tb,
        )
        parser_bug_type, parser_bug_message = _parser_reported_bug(stdout)
        result.parser_reported_bug_type = parser_bug_type
        result.parser_reported_message = parser_bug_message
        return self._apply_oracle(result)

    def _apply_oracle(self, result: RunResult) -> RunResult:
        verdict = evaluate_target_input(self.target, result.input_str)
        result.oracle = verdict
        if result.bug_type in (BugType.CRASH, BugType.TIMEOUT):
            return result

        # In QEMU mode afl-showmap does not forward the target's stdout/stderr,
        # so result.traceback is always empty even when the parser raised a
        # ParseException and exited with code 1.  Use exit_code == 1 as a
        # supplementary rejection signal; afl-showmap does pass the target's
        # exit code through unchanged.
        observed_rejection = bool(result.traceback) or result.exit_code == 1
        exc_type = _traceback_exception_type(result.traceback)
        is_parse_rejection = exc_type.endswith("ParseException") or result.exit_code == 1

        if result.parser_reported_bug_type == BugType.VALIDITY:
            # Oracle cross-check: if the oracle knows this input is invalid,
            # the parser is correctly rejecting it — not a validity bug.
            if verdict.supported and verdict.expected_valid is False:
                result.bug_type = BugType.INVALIDITY
                detail = result.parser_reported_message or result.exception_msg or ""
                result.exception_msg = detail
                return result
            result.bug_type = BugType.VALIDITY
            detail = result.parser_reported_message or result.exception_msg or "Parser reported a validity bug"
            result.exception_msg = f"{detail} [oracle={verdict.reason}]"
            return result

        if result.parser_reported_bug_type == BugType.INVALIDITY:
            # Oracle cross-check: if the oracle considers this input valid, the
            # parser is wrongly rejecting it → reclassify as a ValidityBug.
            if verdict.supported and verdict.expected_valid is True:
                result.bug_type = BugType.VALIDITY
                detail = (
                    result.parser_reported_message
                    or "Parser reported invalidity but oracle considers input valid"
                )
                result.exception_msg = f"{detail} [oracle={verdict.reason}]"
                return result
            result.bug_type = BugType.INVALIDITY
            detail = result.parser_reported_message or result.exception_msg or "Parser reported an invalidity bug"
            result.exception_msg = detail
            return result

        if result.parser_reported_bug_type == BugType.SYNTACTIC:
            # Oracle cross-check: if the oracle considers this input valid, the
            # parser is wrongly rejecting it with a syntactic error → reclassify
            # as a ValidityBug.
            if verdict.supported and verdict.expected_valid is True:
                result.bug_type = BugType.VALIDITY
                detail = (
                    result.parser_reported_message
                    or "Parser reported syntactic error but oracle considers input valid"
                )
                result.exception_msg = f"{detail} [oracle={verdict.reason}]"
                return result
            result.bug_type = BugType.SYNTACTIC
            detail = result.parser_reported_message or result.exception_msg or "Parser reported a syntactic bug"
            result.exception_msg = detail
            return result

        if result.parser_reported_bug_type == BugType.RELIABILITY:
            # Reliability bugs are real bugs regardless of oracle verdict —
            # they indicate unexpected parser failure (e.g. unhandled exception,
            # crash, or resource exhaustion).  Oracle context is appended but
            # does not demote the classification.
            result.bug_type = BugType.RELIABILITY
            detail = result.parser_reported_message or result.exception_msg or "Parser reported a reliability bug"
            result.exception_msg = f"{detail} [oracle={verdict.reason}]" if verdict.supported else detail
            return result

        if not verdict.supported:
            if observed_rejection:
                result.bug_type = BugType.ORACLE_UNKNOWN_REJECT
                detail = result.exception_msg or "Parser rejected oracle-unsupported input"
                result.exception_msg = f"{detail} [oracle={verdict.reason}]"
            else:
                result.bug_type = BugType.ORACLE_UNKNOWN_ACCEPT
                result.exception_msg = f"Oracle unsupported for accepted input ({verdict.reason})"
            return result

        if verdict.expected_valid is True:
            if observed_rejection:
                result.bug_type = BugType.VALIDITY
                detail = result.exception_msg or "Parser rejected oracle-valid input"
                result.exception_msg = f"{detail} [oracle={verdict.reason}]"
            else:
                result.bug_type = BugType.PASS
            return result

        if verdict.expected_valid is False:
            if not observed_rejection:
                result.bug_type = BugType.ORACLE_MISMATCH
                result.exception_msg = (
                    "Oracle expected rejection, but parser accepted the input "
                    f"({verdict.reason})"
                )
            elif is_parse_rejection:
                result.bug_type = BugType.INVALIDITY
            else:
                result.bug_type = BugType.BONUS
                detail = result.exception_msg or "Parser raised a non-ParseException"
                result.exception_msg = f"{detail} [oracle={verdict.reason}]"
            return result

        return result


def result_taxonomy_tags(result: RunResult) -> list[str]:
    """Return user-facing taxonomy labels for a classified run result."""
    return _taxonomy_tags(result)
