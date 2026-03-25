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

_HERE = Path(__file__).parent.parent

# Timeouts
TIMEOUT_SECONDS_WIN   = 60   # PyInstaller bundles need ~20-30 s to unpack
TIMEOUT_SECONDS_LINUX = 5    # Native ELF — no unpack overhead

BITMAP_SIZE = 65536

# ── Binary registry ───────────────────────────────────────────────────────────

_WINDOWS_BINARIES = {
    "ipv4": _HERE / "ipv4ipv6" / "win-ipv4-parser.exe",
    "ipv6": _HERE / "ipv4ipv6" / "win-ipv6-parser.exe",
}

_LINUX_BINARIES = {
    "ipv4": _HERE / "ipv4ipv6" / "linux-ipv4-parser",
    "ipv6": _HERE / "ipv4ipv6" / "linux-ipv6-parser",
}

# ── Platform helpers ──────────────────────────────────────────────────────────

_IS_LINUX = sys.platform != "win32"


def _afl_showmap() -> str | None:
    """Return the path to afl-showmap, or None if not installed."""
    return shutil.which("afl-showmap")


def _ensure_executable(path: Path) -> None:
    """Make sure a Linux binary has the execute bit set."""
    if _IS_LINUX:
        current = path.stat().st_mode
        path.chmod(current | 0o111)


# ── Output parsing ────────────────────────────────────────────────────────────

_TRACEBACK_BLOCK_RE = re.compile(
    r"={60}\s*\nTRACEBACK\s*\n={60}\s*\n(.*?)\n={60}",
    re.DOTALL,
)
_BUG_COUNT_RE  = re.compile(r"Final bug count:\s*defaultdict\([^,]+,\s*(\{.*?\})\)")
_BUG_TYPE_RE   = re.compile(r"\('(validity|invalidity|bonus)'")
_BUG_KEY_MSG_RE = re.compile(r"\('[^']+',\s*[^,]+,\s*\"(.*?)\"", re.DOTALL)


class BugType:
    PASS       = "PASS"
    VALIDITY   = "validity"
    INVALIDITY = "invalidity"
    BONUS      = "bonus"
    CRASH      = "CRASH"
    TIMEOUT    = "TIMEOUT"


@dataclass
class RunResult:
    input_str:     str
    bug_type:      str
    exit_code:     int | None
    stdout:        str
    stderr:        str
    exception_msg: str = ""
    traceback:     str = ""

    @property
    def is_interesting(self) -> bool:
        return self.bug_type != BugType.PASS

    @property
    def is_validity_bug(self) -> bool:
        return self.bug_type == BugType.VALIDITY

    @property
    def is_crash(self) -> bool:
        return self.bug_type in (BugType.CRASH, BugType.TIMEOUT)


def _parse_output(stdout: str, stderr: str) -> tuple[str, str, str]:
    combined = stdout + "\n" + stderr

    tb_match       = _TRACEBACK_BLOCK_RE.search(combined)
    traceback_text = tb_match.group(1).strip() if tb_match else ""

    exception_msg = ""
    bc_match = _BUG_COUNT_RE.search(combined)
    if bc_match:
        count_dict_str = bc_match.group(1)
        bt_match = _BUG_TYPE_RE.search(count_dict_str)
        if bt_match:
            bug_type = bt_match.group(1)
        else:
            bug_type = BugType.BONUS if traceback_text else BugType.PASS
        msg_match = _BUG_KEY_MSG_RE.search(count_dict_str)
        if msg_match:
            exception_msg = msg_match.group(1).strip()
    elif "No bugs found" in combined:
        bug_type = BugType.PASS
    elif traceback_text:
        bug_type = BugType.BONUS
    else:
        bug_type = BugType.PASS

    if not exception_msg and traceback_text:
        lines = [l for l in traceback_text.splitlines() if l.strip()]
        if lines:
            exception_msg = lines[-1].strip()

    return bug_type, exception_msg, traceback_text


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

    key    = f"{result.bug_type}|{result.exception_msg[:128]}"
    digest = hashlib.sha256(key.encode()).digest()
    pos    = (digest[0] << 8 | digest[1]) % BITMAP_SIZE
    bitmap[pos] = 1

    # Crashes and validity bugs get a second distinct slot so they are always
    # flagged as interesting even if that exception message was seen before.
    if result.bug_type in (BugType.CRASH, BugType.TIMEOUT, BugType.VALIDITY):
        pos2 = (digest[2] << 8 | digest[3]) % BITMAP_SIZE
        bitmap[pos2] = 1

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

    def __init__(self, target: str, timeout_seconds: int | None = None):
        self.target = target

        # ── Select binary and mode ────────────────────────────────────────────
        linux_bin = _LINUX_BINARIES.get(target)
        win_bin   = _WINDOWS_BINARIES.get(target)

        if linux_bin is None and win_bin is None:
            raise ValueError(f"Unknown target '{target}'. Choose 'ipv4' or 'ipv6'.")

        afl = _afl_showmap()

        if _IS_LINUX and linux_bin is not None and linux_bin.exists():
            self.binary  = linux_bin
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
        input_str = input_data.decode("latin-1", errors="replace")
        input_str = input_str.encode("ascii", errors="backslashreplace").decode("ascii")

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
            "--ipstr", input_str,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
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
            return bytes(BITMAP_SIZE), True, result

        except Exception as exc:
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="", stderr="",
                exception_msg=str(exc),
            )
            return bytes(BITMAP_SIZE), True, result

        finally:
            try:
                os.unlink(bitmap_path)
            except OSError:
                pass

        bug_type, exc_msg, tb = _parse_output(stdout, stderr)
        if proc.returncode not in (0, 1) and bug_type == BugType.PASS:
            bug_type = BugType.CRASH

        result = RunResult(
            input_str=input_str,
            bug_type=bug_type,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            exception_msg=exc_msg,
            traceback=tb,
        )
        return bytes(bitmap), result.is_crash, result

    # ── Shared binary runner (Linux-no-AFL and Windows) ───────────────────────

    def _run_binary(self, input_str: str) -> RunResult:
        cmd = [str(self.binary), "--ipstr", input_str]
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
        bug_type, exc_msg, tb = _parse_output(stdout, stderr)

        if proc.returncode not in (0, 1) and bug_type == BugType.PASS:
            bug_type = BugType.CRASH

        return RunResult(
            input_str=input_str,
            bug_type=bug_type,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            exception_msg=exc_msg,
            traceback=tb,
        )
