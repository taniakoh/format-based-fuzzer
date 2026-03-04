"""
Test driver for IPv4 / IPv6 parser binaries.

Runs the target binary with a given input string, captures its output,
and classifies the result into one of:
  - PASS      : valid input, parser succeeded
  - INVALIDITY: parser raised a ParseException (expected/caught error)
  - BONUS     : parser raised an unexpected exception (more interesting)
  - CRASH     : process returned non-zero exit code or timed out

Usage (standalone):
    python test_driver.py ipv4 "1.2.3.4"
    python test_driver.py ipv6 "2001:db8::1"
"""

import subprocess
import sys
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# ── Binary paths ──────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
_BINARIES = {
    "ipv4": _HERE / "ipv4ipv6" / "win-ipv4-parser.exe",
    "ipv6": _HERE / "ipv4ipv6" / "win-ipv6-parser.exe",
}

# How long (seconds) to wait for the binary before killing it.
# NOTE: the win-*.exe binaries are PyInstaller one-file bundles.
# Each invocation unpacks ~24 MB of Python to a temp dir, taking
# ~20-30 s per run. Increase this if you see spurious TIMEOUT results.
TIMEOUT_SECONDS = 60


# ── Result types ──────────────────────────────────────────────────────────────

class BugType:
    PASS = "PASS"
    VALIDITY = "validity"          # Valid input falsely rejected (real bug!)
    INVALIDITY = "invalidity"      # ParseException – parser caught it
    BONUS = "bonus"                # Unexpected exception
    CRASH = "CRASH"                # Non-zero exit / timeout / signal
    TIMEOUT = "TIMEOUT"


@dataclass
class RunResult:
    input_str: str                 # The exact string passed to --ipstr
    bug_type: str                  # One of BugType.*
    exit_code: int | None
    stdout: str
    stderr: str
    exception_msg: str = ""        # Extracted exception message (if any)
    traceback: str = ""            # Full traceback block (if any)

    @property
    def is_interesting(self) -> bool:
        """True for anything that isn't a clean PASS."""
        return self.bug_type != BugType.PASS

    @property
    def is_validity_bug(self) -> bool:
        """True when a supposedly valid input was falsely rejected."""
        return self.bug_type == BugType.VALIDITY

    @property
    def is_crash(self) -> bool:
        return self.bug_type in (BugType.CRASH, BugType.TIMEOUT)


# ── Output parsing helpers ────────────────────────────────────────────────────

_TRACEBACK_BLOCK_RE = re.compile(
    r"={60}\s*\nTRACEBACK\s*\n={60}\s*\n(.*?)\n={60}",
    re.DOTALL,
)
# Matches the whole Final bug count line, capturing the dict literal
_BUG_COUNT_RE = re.compile(r"Final bug count:\s*defaultdict\([^,]+,\s*(\{.*?\})\)")
_BUG_TYPE_RE = re.compile(r"\('(validity|invalidity|bonus)'")
# Extracts the exception message string (3rd element of the bug-key tuple)
_BUG_KEY_MSG_RE = re.compile(r"\('[^']+',\s*[^,]+,\s*\"(.*?)\"", re.DOTALL)


def _parse_output(stdout: str, stderr: str) -> tuple[str, str, str]:
    """
    Returns (bug_type, exception_msg, traceback_text).
    """
    combined = stdout + "\n" + stderr

    # Check for TRACEBACK block (may be empty in this binary build)
    tb_match = _TRACEBACK_BLOCK_RE.search(combined)
    traceback_text = tb_match.group(1).strip() if tb_match else ""

    # Determine bug type from Final bug count line
    exception_msg = ""
    bc_match = _BUG_COUNT_RE.search(combined)
    if bc_match:
        count_dict_str = bc_match.group(1)
        bt_match = _BUG_TYPE_RE.search(count_dict_str)
        if bt_match:
            bug_type = bt_match.group(1)
        else:
            bug_type = BugType.BONUS if traceback_text else BugType.PASS

        # Extract exception message from the 3rd element of the bug-key tuple
        msg_match = _BUG_KEY_MSG_RE.search(count_dict_str)
        if msg_match:
            exception_msg = msg_match.group(1).strip()
    elif "No bugs found" in combined:
        bug_type = BugType.PASS
    elif traceback_text:
        bug_type = BugType.BONUS
    else:
        bug_type = BugType.PASS

    # Fall back to last line of traceback block if msg still empty
    if not exception_msg and traceback_text:
        lines = [l for l in traceback_text.splitlines() if l.strip()]
        if lines:
            exception_msg = lines[-1].strip()

    return bug_type, exception_msg, traceback_text


# ── Main driver function ───────────────────────────────────────────────────────

def run(target: str, input_str: str) -> RunResult:
    """
    Run the target binary with --ipstr <input_str> and return a RunResult.

    Parameters
    ----------
    target : "ipv4" or "ipv6"
    input_str : the string to pass as --ipstr (may contain arbitrary bytes)
    """
    binary = _BINARIES.get(target)
    if binary is None:
        raise ValueError(f"Unknown target '{target}'. Choose 'ipv4' or 'ipv6'.")
    if not binary.exists():
        raise FileNotFoundError(f"Binary not found: {binary}")

    cmd = [str(binary), "--ipstr", input_str]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            stdin=subprocess.DEVNULL,   # prevent binary from blocking on stdin
            text=True,                  # decode stdout/stderr as text
            errors="replace",           # replace undecodable bytes instead of crashing
            timeout=TIMEOUT_SECONDS,
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

    # Non-zero exit that wasn't caught as a ParseException = crash
    if proc.returncode not in (0, 1):
        bug_type, exc_msg, tb = _parse_output(stdout, stderr)
        # Override if exit code suggests hard crash
        if bug_type == BugType.PASS:
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

    bug_type, exc_msg, tb = _parse_output(stdout, stderr)
    return RunResult(
        input_str=input_str,
        bug_type=bug_type,
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        exception_msg=exc_msg,
        traceback=tb,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_driver.py <ipv4|ipv6> <input_string>")
        sys.exit(1)

    target_arg = sys.argv[1]
    ipstr_arg = sys.argv[2]

    result = run(target_arg, ipstr_arg)
    print(f"Input    : {result.input_str!r}")
    print(f"Bug type : {result.bug_type}")
    print(f"Exit code: {result.exit_code}")
    if result.exception_msg:
        print(f"Exception: {result.exception_msg}")
    if result.traceback:
        print("Traceback:")
        print(result.traceback)
    print("--- stdout ---")
    print(result.stdout)
    if result.stderr:
        print("--- stderr ---")
        print(result.stderr)
