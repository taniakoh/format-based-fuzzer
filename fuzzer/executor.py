"""
Module 4 - Execution Engine.

Wraps the parser binaries and returns a (behavior_bitmap, crashed, result)
triple that mirrors the rest of the fuzzer pipeline.

Coverage modes
--------------
Two modes are selected automatically at startup:

  Frida     Linux binary + Frida available
            -> native Linux execution with Frida Stalker block coverage.
               The observed basic-block addresses are hashed into the
               existing 65536-byte bitmap and fed through AFL-style novelty
               tracking. Timeout: 30 s.

  Windows   Opaque PyInstaller .exe bundles (win-ipv4/ipv6-parser.exe)
            -> behavior-hash bitmap: each unique (bug_type, exception_msg)
               pair is SHA-256 hashed to a stable slot in the bitmap.
               Timeout: 60 s (PyInstaller unpacks to a temp dir at startup).

The Executor.mode property exposes which mode is active so callers can
log it at startup.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import signal
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fuzzer.oracle import OracleVerdict, evaluate_target_input

_HERE = Path(__file__).parent.parent

TIMEOUT_SECONDS_WIN = 60
TIMEOUT_SECONDS_LINUX = 30

BITMAP_SIZE = 65536

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
_INPUT_ARGS: dict[str, str] = {}
_INPUT_ENCODINGS: dict[str, str] = {}

_IS_LINUX = sys.platform != "win32"
_FRIDA_MODULE: Any | None = None
_FRIDA_DEBUG = os.environ.get("FRIDA_DEBUG_FUZZER", "").strip().lower() not in ("", "0", "false", "no")

_FRIDA_AGENT_SOURCE = r"""
const targetPath = %TARGET_PATH%;
const targetName = %TARGET_NAME%;
const BITMAP_SIZE = 65536;
const batchSize = 512;
let edgeBuffer = [];
let prevLoc = 0;

function matchesTargetModule(module) {
  if (module.path === targetPath)
    return true;
  if (module.name === targetName)
    return true;
  if (module.path.indexOf(targetName) !== -1)
    return true;
  return false;
}

function flushEdges() {
  if (edgeBuffer.length === 0)
    return;
  send({
    type: "edges",
    edges: edgeBuffer
  });
  edgeBuffer = [];
}

function recordEdge(slot) {
  edgeBuffer.push(slot);
  if (edgeBuffer.length >= batchSize)
    flushEdges();
}

const modules = Process.enumerateModules();
const targetModule = modules.find(matchesTargetModule) || modules[0];
send({
  type: "debug",
  event: "target-module",
  moduleName: targetModule ? targetModule.name : null,
  modulePath: targetModule ? targetModule.path : null,
  moduleCount: modules.length
});

modules.forEach(module => {
  if (module.base.equals(targetModule.base))
    return;
  Stalker.exclude(module);
});

function startFollowing(threadId) {
  Stalker.follow(threadId, {
    events: {
      call: false,
      ret: false,
      exec: false,
      block: true,
      compile: false
    },
    onReceive(events) {
      send({
        type: "debug",
        event: "stalker-batch",
        byteLength: events.byteLength || 0
      });
      const parsed = Stalker.parse(events, {
        annotate: true,
        stringify: true
      });

      parsed.forEach(event => {
        if (!Array.isArray(event) || event.length < 2)
          return;
        if (event[0] !== "block")
          return;
        // AFL-QEMU edge hash: curLoc = (pc >> 4) ^ (pc >> 8), then XOR with prevLoc.
        // Use BigInt for 64-bit addresses, keep lower 32 bits to avoid float precision loss.
        const lower32 = Number(BigInt(event[1]) & BigInt(0xFFFFFFFF));
        const curLoc = ((lower32 >>> 4) ^ (lower32 >>> 8)) & (BITMAP_SIZE - 1);
        const slot = (curLoc ^ prevLoc) & (BITMAP_SIZE - 1);
        prevLoc = (curLoc >>> 1) & (BITMAP_SIZE - 1);
        recordEdge(slot);
      });
    }
  });
}

const threads = Process.enumerateThreads();
send({
  type: "debug",
  event: "thread-scan",
  threadCount: threads.length,
  threadIds: threads.map(thread => thread.id)
});

threads.forEach(thread => {
  try {
    startFollowing(thread.id);
    send({
      type: "debug",
      event: "follow-thread",
      threadId: thread.id
    });
  } catch (e) {
    send({
      type: "debug",
      event: "follow-thread-error",
      threadId: thread.id,
      error: String(e)
    });
  }
});

rpc.exports.flush = function () {
  flushEdges();
  return true;
};
"""


def register_binary(
    target: str,
    windows: str | Path | None = None,
    linux: str | Path | None = None,
    windows_args: list[str] | None = None,
    linux_args: list[str] | None = None,
    input_arg: str | None = None,
    input_encoding: str | None = None,
) -> None:
    if windows is not None:
        _WINDOWS_BINARIES[target.lower()] = Path(windows)
    if linux is not None:
        _LINUX_BINARIES[target.lower()] = Path(linux)
    if windows_args is not None:
        _WINDOWS_ARGS[target.lower()] = list(windows_args)
    if linux_args is not None:
        _LINUX_ARGS[target.lower()] = list(linux_args)
    if input_arg is not None:
        _INPUT_ARGS[target.lower()] = input_arg
    if input_encoding is not None:
        _INPUT_ENCODINGS[target.lower()] = input_encoding


def _load_frida() -> Any:
    global _FRIDA_MODULE
    if _FRIDA_MODULE is not None:
        return _FRIDA_MODULE
    try:
        import frida as frida_module
    except ImportError as exc:
        raise RuntimeError(
            "Frida instrumentation is required for Linux black-box targets. "
            "Install it in the active environment with 'pip install frida frida-tools'."
        ) from exc
    _FRIDA_MODULE = frida_module
    return frida_module


def _frida_debug(message: str) -> None:
    if _FRIDA_DEBUG:
        print(f"[FRIDA-DEBUG] {message}", file=sys.stderr, flush=True)


def _ensure_executable(path: Path) -> None:
    if _IS_LINUX:
        try:
            current = path.stat().st_mode
            path.chmod(current | 0o111)
        except PermissionError:
            pass


def _frida_agent_source(binary_path: Path) -> str:
    return (
        _FRIDA_AGENT_SOURCE.replace("%TARGET_PATH%", repr(str(binary_path)))
        .replace("%TARGET_NAME%", repr(binary_path.name))
    )


def _edge_slots_to_bitmap(edge_slots: list[int]) -> bytes:
    """Build a hit-count bitmap from pre-computed AFL-style edge slot numbers."""
    bitmap = bytearray(BITMAP_SIZE)
    counts: Counter[int] = Counter(edge_slots)
    for slot, count in counts.items():
        bitmap[slot] = min(count, 255)
    return bytes(bitmap)


_TRACEBACK_BLOCK_RE = re.compile(
    r"={60}\s*\nTRACEBACK\s*\n={60}\s*\n(.*?)\n={60}",
    re.DOTALL,
)
_TRACEBACK_LAST_LINE_RE = re.compile(r"^\s*([\w.]+):\s*(.*)$")
_STDERR_TRACEBACK_RE = re.compile(r"(Traceback \(most recent call last\):.*)", re.DOTALL)
_PARSER_VALIDITY_RE = re.compile(r"\bA validity bug has been triggered:\s*(.+)", re.IGNORECASE)
_PARSER_INVALIDITY_RE = re.compile(r"\bAn invalidity bug has been triggered:\s*(.+)", re.IGNORECASE)
_PARSER_FINAL_BUG_RE = re.compile(
    r"\('(?P<kind>validity|invalidity|bonus|syntactic|reliability|functional|performance)'\s*,\s*"
    r"<class '(?P<exc_type>[^']+)'>\s*,\s*"
    r"(?P<message>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")\s*,\s*"
    r"'(?P<filename>[^']+)'\s*,\s*(?P<lineno>\d+)\)",
    re.IGNORECASE,
)


class BugType:
    PASS = "PASS"
    VALIDITY = "validity"
    INVALIDITY = "invalidity"
    SYNTACTIC = "syntactic"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    FUNCTIONAL = "functional"
    BONUS = "bonus"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    ORACLE_MISMATCH = "oracle_mismatch"
    ORACLE_UNKNOWN_ACCEPT = "oracle_unknown_accept"
    ORACLE_UNKNOWN_REJECT = "oracle_unknown_reject"


_INSTRUMENTATION_NOISE_PATTERNS = (
    "loader crashed",
    "process not found",
    "the connection is closed",
    "unexpected crash while trying to allocate memory",
)


def _is_instrumentation_noise_message(message: str) -> bool:
    lowered = (message or "").strip().lower()
    return any(pattern in lowered for pattern in _INSTRUMENTATION_NOISE_PATTERNS)


@dataclass
class RunResult:
    input_str: str
    bug_type: str
    exit_code: int | None
    stdout: str
    stderr: str
    exception_msg: str = ""
    traceback: str = ""
    oracle: OracleVerdict | None = None
    parser_reported_bug_type: str | None = None
    parser_reported_message: str = ""
    parser_reported_exc_type: str = ""
    parser_reported_filename: str = ""
    parser_reported_lineno: int | None = None

    @property
    def is_interesting(self) -> bool:
        return self.bug_type != BugType.PASS

    @property
    def is_validity_bug(self) -> bool:
        return self.bug_type == BugType.VALIDITY

    @property
    def is_crash(self) -> bool:
        return self.bug_type in (BugType.CRASH, BugType.TIMEOUT) and not self.is_instrumentation_noise

    @property
    def is_instrumentation_noise(self) -> bool:
        return self.bug_type == BugType.CRASH and _is_instrumentation_noise_message(self.exception_msg)

    @property
    def is_real_bug(self) -> bool:
        if self.is_instrumentation_noise:
            return False
        return self.bug_type in (
            BugType.VALIDITY,
            BugType.BONUS,
            BugType.RELIABILITY,
            BugType.PERFORMANCE,
            BugType.FUNCTIONAL,
            BugType.CRASH,
            BugType.TIMEOUT,
        )


def _parse_output(stdout: str, stderr: str) -> tuple[str, str]:
    combined = stdout + "\n" + stderr
    tb_match = _TRACEBACK_BLOCK_RE.search(combined)
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


def _normalize_parser_bug_kind(kind: str) -> str:
    normalized = kind.lower()
    if normalized == "functional":
        return BugType.FUNCTIONAL
    return normalized


def _parser_reported_bug(stdout: str) -> dict[str, object]:
    match = _PARSER_VALIDITY_RE.search(stdout)
    if match:
        return {"kind": BugType.VALIDITY, "message": match.group(1).strip(), "exc_type": "", "filename": "", "lineno": None}

    match = _PARSER_INVALIDITY_RE.search(stdout)
    if match:
        return {"kind": BugType.INVALIDITY, "message": match.group(1).strip(), "exc_type": "", "filename": "", "lineno": None}

    match = _PARSER_FINAL_BUG_RE.search(stdout)
    if match:
        message_token = match.group("message")
        try:
            message = ast.literal_eval(message_token)
        except (SyntaxError, ValueError):
            message = message_token.strip("'\"")
        return {
            "kind": _normalize_parser_bug_kind(match.group("kind")),
            "message": str(message),
            "exc_type": match.group("exc_type"),
            "filename": match.group("filename"),
            "lineno": int(match.group("lineno")),
        }

    return {"kind": None, "message": "", "exc_type": "", "filename": "", "lineno": None}


def _taxonomy_tags(result: "RunResult") -> list[str]:
    tags: list[str] = []
    if result.parser_reported_bug_type == BugType.VALIDITY or result.bug_type == BugType.VALIDITY:
        tags.append("ValidityBug")
    elif result.parser_reported_bug_type == BugType.INVALIDITY or result.bug_type == BugType.INVALIDITY:
        tags.append("InvalidityBug")
    elif result.parser_reported_bug_type == BugType.SYNTACTIC or result.bug_type == BugType.SYNTACTIC:
        tags.append("SyntacticBug")

    if result.parser_reported_bug_type == BugType.FUNCTIONAL or result.bug_type == BugType.FUNCTIONAL:
        tags.append("FunctionalBug")
    if result.is_crash or result.bug_type == BugType.RELIABILITY:
        tags.append("ReliabilityBug")
    if result.is_instrumentation_noise:
        tags.append("InstrumentationNoise")
    if result.bug_type in (BugType.TIMEOUT, BugType.PERFORMANCE):
        tags.append("PerformanceBug")
    if result.bug_type == BugType.BONUS:
        tags.append("Bonus/UntrackedBugs")
    if _is_boundary_input(result.input_str):
        tags.append("BoundaryBug")
    return list(dict.fromkeys(tags))


_IPV6_BOUNDARY_ADDRS = {
    "::",
    "::1",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:0:0",
    "::ffff:ffff:ffff",
    "fe80::",
    "fec0::",
    "ff00::",
}

_CIDR_BOUNDARY_PREFIXES = {"0", "32", "128"}


def _is_boundary_input(input_str: str) -> bool:
    parts = input_str.split(".")
    if len(parts) == 4:
        try:
            octets = [int(part, 10) for part in parts]
            if any(octet in {0, 1, 254, 255} for octet in octets):
                return True
        except ValueError:
            pass

    if input_str.lower() in _IPV6_BOUNDARY_ADDRS:
        return True

    if "/" in input_str:
        base, _, prefix = input_str.partition("/")
        if prefix.strip() in _CIDR_BOUNDARY_PREFIXES:
            return True
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
    if not traceback_text:
        return ""
    lines = [line.strip() for line in traceback_text.splitlines() if line.strip()]
    if not lines:
        return ""
    match = _TRACEBACK_LAST_LINE_RE.match(lines[-1])
    if not match:
        return ""
    return match.group(1)


def _cli_safe_input(input_data: bytes, encoding: str = "cli_escape") -> str:
    if encoding == "raw":
        return input_data.replace(b"\x00", b"").decode("latin-1", errors="replace")
    return input_data.decode("latin-1", errors="replace").encode("unicode_escape").decode("ascii")


def _summarize_process_failure(stdout: str, stderr: str, returncode: int | None) -> str:
    for stream in (stderr, stdout):
        for line in stream.splitlines():
            message = line.strip()
            if message:
                return message[:200]
    if returncode is None:
        return "process failed before reporting an exit code"
    return f"process exited with code {returncode}"


def _result_to_bitmap(result: RunResult) -> bytes:
    bitmap = bytearray(BITMAP_SIZE)
    if result.bug_type == BugType.PASS:
        return bytes(bitmap)
    return _overlay_result_signal(bitmap, result)


def _overlay_result_signal(bitmap: bytearray, result: RunResult) -> bytes:
    if result.bug_type == BugType.PASS:
        return bytes(bitmap)

    key = f"{result.bug_type}|{hashlib.sha256(result.exception_msg.encode()).hexdigest()}"
    digest = hashlib.sha256(key.encode()).digest()
    pos = (digest[0] << 8 | digest[1]) % BITMAP_SIZE
    bitmap[pos] = 1

    if result.bug_type in (BugType.CRASH, BugType.TIMEOUT, BugType.VALIDITY):
        pos2 = (digest[2] << 8 | digest[3]) % BITMAP_SIZE
        bitmap[pos2] = 1

    if result.traceback:
        tb_key = f"traceback|{result.bug_type}|{result.traceback.strip()[:256]}"
        tb_digest = hashlib.sha256(tb_key.encode()).digest()
        tb_pos = (tb_digest[4] << 8 | tb_digest[5]) % BITMAP_SIZE
        bitmap[tb_pos] = 1

    return bytes(bitmap)


class Executor:
    def __init__(
        self,
        target: str,
        timeout_seconds: int | None = None,
        coverage_mode: str = "auto",
    ):
        """
        Parameters
        ----------
        coverage_mode : "auto" | "frida" | "hash"
            "auto"  – Frida when on Linux with a linux binary present, else hash.
            "frida" – Force Frida instrumentation; raises if unavailable.
            "hash"  – Force behavior-hash bitmap regardless of platform.
        """
        if coverage_mode not in ("auto", "frida", "hash"):
            raise ValueError(f"coverage_mode must be 'auto', 'frida', or 'hash'; got {coverage_mode!r}")

        self.target = target
        self._cwd = _HERE / "results" / target
        self._cwd.mkdir(parents=True, exist_ok=True)

        linux_bin = _LINUX_BINARIES.get(target)
        win_bin = _WINDOWS_BINARIES.get(target)

        if linux_bin is None and win_bin is None:
            registered = sorted(set(_WINDOWS_BINARIES) | set(_LINUX_BINARIES))
            raise ValueError(
                f"No binary registered for target '{target}'. "
                f"Registered targets: {registered}. "
                f"Call register_binary('{target}', windows=..., linux=...) "
                f"or add 'binary_windows'/'binary_linux' to config/{target}_format.json."
            )

        use_frida = (
            coverage_mode == "frida"
            or (coverage_mode == "auto" and _IS_LINUX and linux_bin is not None and linux_bin.exists())
        )

        if coverage_mode == "frida" and not (_IS_LINUX and linux_bin is not None and linux_bin.exists()):
            raise RuntimeError(
                f"coverage_mode='frida' requires a Linux binary for target '{target}' "
                f"and a Linux host. Binary path: {linux_bin}"
            )

        if use_frida:
            _load_frida()
            self.binary = linux_bin
            self._fixed_args = list(_LINUX_ARGS.get(target, []))
            _ensure_executable(linux_bin)
            self.timeout = timeout_seconds or TIMEOUT_SECONDS_LINUX
            self._mode = "Frida"
        else:
            if _IS_LINUX and linux_bin is not None and linux_bin.exists():
                self.binary = linux_bin
                self._fixed_args = list(_LINUX_ARGS.get(target, []))
                _ensure_executable(linux_bin)
                self.timeout = timeout_seconds or TIMEOUT_SECONDS_LINUX
                self._mode = "Linux"
            else:
                if win_bin is None or not win_bin.exists():
                    raise FileNotFoundError(
                        f"No binary found for target '{target}'. Expected {win_bin} or {linux_bin}."
                    )
                self.binary = win_bin
                self._fixed_args = list(_WINDOWS_ARGS.get(target, []))
                self.timeout = timeout_seconds or TIMEOUT_SECONDS_WIN
                self._mode = "Windows"

        if str(self.binary).endswith(".py"):
            self._fixed_args = [str(self.binary)] + self._fixed_args
            self.binary = Path(sys.executable)

        self._input_arg = _INPUT_ARGS.get(target, "--ipstr")
        self._input_encoding = _INPUT_ENCODINGS.get(target, "cli_escape")

    @property
    def mode(self) -> str:
        return self._mode

    def run(self, input_data: bytes) -> tuple[bytes, bool, RunResult]:
        input_str = _cli_safe_input(input_data, self._input_encoding)
        if self._mode == "Frida":
            return self._run_with_frida(input_str)
        result = self._run_binary(input_str)
        bitmap = _result_to_bitmap(result)
        return bitmap, result.is_crash, result

    def _run_with_frida(self, input_str: str) -> tuple[bytes, bool, RunResult]:
        frida = _load_frida()
        cmd = [str(self.binary), *self._fixed_args, f"{self._input_arg}={input_str}"]
        edge_slots: list[int] = []

        def on_message(message: dict[str, Any], _data: bytes | None) -> None:
            msg_type = message.get("type")
            if msg_type != "send":
                _frida_debug(f"script message type={msg_type}: {message}")
                return
            payload = message.get("payload") or {}
            if payload.get("type") == "edges":
                new_edges = [int(s) for s in payload.get("edges", [])]
                edge_slots.extend(new_edges)
                _frida_debug(
                    f"received {len(new_edges)} edge slots (total={len(edge_slots)})"
                )
            elif payload.get("type") == "debug":
                _frida_debug(f"agent debug: {payload}")

        popen_kwargs: dict[str, Any] = {
            "args": cmd,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "errors": "replace",
            "cwd": self._cwd,
        }

        try:
            proc = subprocess.Popen(**popen_kwargs)
            _frida_debug(f"spawned pid={proc.pid} cmd={cmd!r}")
        except Exception as exc:
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="",
                stderr="",
                exception_msg=str(exc),
            )
            return bytes(BITMAP_SIZE), True, result

        session = None
        script = None
        try:
            session = frida.get_local_device().attach(proc.pid)
            _frida_debug(f"attached to pid={proc.pid}")
            script = session.create_script(_frida_agent_source(self.binary))
            _frida_debug(f"created script for binary={self.binary}")
            script.on("message", on_message)
            script.load()
            _frida_debug("script loaded")

            try:
                stdout, stderr = proc.communicate(timeout=self.timeout)
                _frida_debug(
                    f"process exited rc={proc.returncode} stdout_len={len(stdout or '')} "
                    f"stderr_len={len(stderr or '')}"
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", ""
                _frida_debug(
                    f"process timeout pid={proc.pid} partial_edges={len(edge_slots)}"
                )
                result = RunResult(
                    input_str=input_str,
                    bug_type=BugType.TIMEOUT,
                    exit_code=None,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    exception_msg="Process timed out",
                )
                return _edge_slots_to_bitmap(edge_slots), True, result

            if script is not None:
                try:
                    script.exports_sync.flush()
                    _frida_debug(f"flush completed; total edge slots={len(edge_slots)}")
                except Exception:
                    _frida_debug("flush failed")
                    pass

            exc_msg, tb = _parse_output(stdout or "", stderr or "")
            if proc.returncode not in (0, 1):
                bug_type = BugType.CRASH
                exc_msg = _summarize_process_failure(stdout or "", stderr or "", proc.returncode)
            elif _traceback_exception_type(tb) == "PerformanceBug":
                bug_type = BugType.PERFORMANCE
            else:
                bug_type = BugType.PASS

            result = RunResult(
                input_str=input_str,
                bug_type=bug_type,
                exit_code=proc.returncode,
                stdout=stdout or "",
                stderr=stderr or "",
                exception_msg=exc_msg,
                traceback=tb,
            )
            parser_bug = _parser_reported_bug(result.stdout)
            result.parser_reported_bug_type = parser_bug["kind"]
            result.parser_reported_message = str(parser_bug["message"])
            result.parser_reported_exc_type = str(parser_bug["exc_type"])
            result.parser_reported_filename = str(parser_bug["filename"])
            result.parser_reported_lineno = parser_bug["lineno"]
            result = self._apply_oracle(result)
            return _edge_slots_to_bitmap(edge_slots), result.is_crash, result

        except Exception as exc:
            _frida_debug(f"Frida execution failed: {exc!r}")
            try:
                proc.kill()
                proc.communicate(timeout=5)
            except Exception:
                pass
            result = RunResult(
                input_str=input_str,
                bug_type=BugType.CRASH,
                exit_code=None,
                stdout="",
                stderr="",
                exception_msg=str(exc),
            )
            return bytes(BITMAP_SIZE), True, result
        finally:
            if script is not None:
                try:
                    script.unload()
                except Exception:
                    pass
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

    def _run_binary(self, input_str: str) -> RunResult:
        cmd = [str(self.binary), *self._fixed_args, f"{self._input_arg}={input_str}"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                errors="replace",
                timeout=self.timeout,
                cwd=self._cwd,
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
        exc_msg, tb = _parse_output(stdout, stderr)

        if proc.returncode not in (0, 1):
            bug_type = BugType.CRASH
            exc_msg = _summarize_process_failure(stdout, stderr, proc.returncode)
        elif _traceback_exception_type(tb) == "PerformanceBug":
            bug_type = BugType.PERFORMANCE
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
        parser_bug = _parser_reported_bug(stdout)
        result.parser_reported_bug_type = parser_bug["kind"]
        result.parser_reported_message = str(parser_bug["message"])
        result.parser_reported_exc_type = str(parser_bug["exc_type"])
        result.parser_reported_filename = str(parser_bug["filename"])
        result.parser_reported_lineno = parser_bug["lineno"]
        return self._apply_oracle(result)

    def _apply_oracle(self, result: RunResult) -> RunResult:
        verdict = evaluate_target_input(self.target, result.input_str)
        result.oracle = verdict

        parser_type = result.parser_reported_bug_type
        if parser_type:
            result.bug_type = str(parser_type)
            result.exception_msg = (
                result.parser_reported_message
                or result.exception_msg
                or f"Parser reported a {result.bug_type} bug"
            )
            return result

        if result.bug_type in (BugType.CRASH, BugType.TIMEOUT):
            return result

        observed_rejection = bool(result.traceback) or result.exit_code == 1
        exc_type = _traceback_exception_type(result.traceback)
        is_parse_rejection = exc_type.endswith("ParseException") or result.exit_code == 1

        if result.bug_type == BugType.PERFORMANCE:
            result.exception_msg = result.exception_msg or "PerformanceBug"
            return result

        if observed_rejection and is_parse_rejection:
            result.bug_type = BugType.INVALIDITY
            result.exception_msg = result.exception_msg or "Parser rejected input"
            return result

        if observed_rejection:
            result.bug_type = BugType.BONUS
            result.exception_msg = (
                result.exception_msg
                or f"Parser raised {exc_type or 'an unexpected exception'}"
            )
            return result

        result.bug_type = BugType.PASS
        return result


def result_taxonomy_tags(result: RunResult) -> list[str]:
    return _taxonomy_tags(result)
