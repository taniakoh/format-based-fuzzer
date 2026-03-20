"""
Module 4 — Execution Engine.

Wraps the win-ipv4-parser.exe and win-ipv6-parser.exe PyInstaller binaries.
Returns a (behavior_bitmap, crashed) pair that mirrors the AFL++ interface
described in the implementation guide.

Coverage notes
--------------
These binaries are opaque PyInstaller one-file bundles; we cannot inject AFL
shared-memory instrumentation.  Instead we derive a *behavior bitmap*:

  - The 65536-byte bitmap is initialised to zeros.
  - Each unique (bug_type, exception_key) observation is hashed to a stable
    byte position and that position is set to 1.
  - The CoverageAnalyzer then treats any newly-set position as a "new edge",
    giving us a meaningful interesting-input signal without real code coverage.

Timeout is set to 60 s because PyInstaller bundles take ~20-30 s to unpack.
"""

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).parent.parent

TIMEOUT_SECONDS = 60
BITMAP_SIZE = 65536

_BINARIES = {
    "ipv4": _HERE / "ipv4ipv6" / "win-ipv4-parser.exe",
    "ipv6": _HERE / "ipv4ipv6" / "win-ipv6-parser.exe",
}

# ── Output parsing ────────────────────────────────────────────────────────────

_TRACEBACK_BLOCK_RE = re.compile(
    r"={60}\s*\nTRACEBACK\s*\n={60}\s*\n(.*?)\n={60}",
    re.DOTALL,
)
_BUG_COUNT_RE = re.compile(r"Final bug count:\s*defaultdict\([^,]+,\s*(\{.*?\})\)")
_BUG_TYPE_RE = re.compile(r"\('(validity|invalidity|bonus)'")
_BUG_KEY_MSG_RE = re.compile(r"\('[^']+',\s*[^,]+,\s*\"(.*?)\"", re.DOTALL)


class BugType:
    PASS = "PASS"
    VALIDITY = "validity"
    INVALIDITY = "invalidity"
    BONUS = "bonus"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"


@dataclass
class RunResult:
    input_str: str
    bug_type: str
    exit_code: int | None
    stdout: str
    stderr: str
    exception_msg: str = ""
    traceback: str = ""

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

    tb_match = _TRACEBACK_BLOCK_RE.search(combined)
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


# ── Behavior bitmap helpers ───────────────────────────────────────────────────

def _result_to_bitmap(result: RunResult) -> bytes:
    """
    Map a RunResult to a sparse behavior bitmap.

    A PASS returns an all-zero bitmap (no new information).
    Any other result sets a single byte determined by hashing the
    (bug_type, exception_msg) pair — giving each unique error a stable slot.
    """
    bitmap = bytearray(BITMAP_SIZE)
    if result.bug_type == BugType.PASS:
        return bytes(bitmap)

    key = f"{result.bug_type}|{result.exception_msg[:128]}"
    digest = hashlib.sha256(key.encode()).digest()
    # Use first two bytes as a 16-bit index into the bitmap
    pos = (digest[0] << 8 | digest[1]) % BITMAP_SIZE
    bitmap[pos] = 1

    # Crashes and validity bugs get a second, distinct slot so they are always
    # flagged as interesting even if that exception message was seen before.
    if result.bug_type in (BugType.CRASH, BugType.TIMEOUT, BugType.VALIDITY):
        pos2 = (digest[2] << 8 | digest[3]) % BITMAP_SIZE
        bitmap[pos2] = 1

    return bytes(bitmap)


# ── Executor ──────────────────────────────────────────────────────────────────

class Executor:
    """
    Execution engine for the IP-address parser binaries.

    Interface mirrors the guide's Executor: run() returns
    (behavior_bitmap: bytes, crashed: bool).
    """

    def __init__(self, target: str, timeout_seconds: int = TIMEOUT_SECONDS):
        self.target = target
        self.timeout = timeout_seconds
        binary = _BINARIES.get(target)
        if binary is None:
            raise ValueError(f"Unknown target '{target}'. Choose 'ipv4' or 'ipv6'.")
        if not binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary}")
        self.binary = binary

    def run(self, input_data: bytes) -> tuple[bytes, bool, "RunResult"]:
        """
        Execute the parser with the given input (decoded as a latin-1 string).

        Returns
        -------
        (behavior_bitmap, crashed, result)
            Callers receive all three values in one binary invocation.
        """
        input_str = input_data.decode("latin-1", errors="replace")
        input_str = input_str.encode("ascii", errors="backslashreplace").decode("ascii")

        result = self._run_binary(input_str)
        bitmap = _result_to_bitmap(result)
        return bitmap, result.is_crash, result

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
                stdout="",
                stderr="",
                exception_msg="Process timed out",
            )
        except Exception as exc:
            return RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="",
                stderr="",
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
