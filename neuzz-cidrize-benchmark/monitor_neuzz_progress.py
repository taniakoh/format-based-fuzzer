from __future__ import annotations

import argparse
import os
import re
import signal
import sys
import time
from pathlib import Path


def infer_target_name(workspace: Path) -> str:
    name = workspace.name
    if name.startswith("neuzz-") and name.endswith("-benchmark"):
        return name[len("neuzz-") : -len("-benchmark")].upper()
    return "BENCHMARK"


def count_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for child in path.iterdir() if child.is_file() and not child.name.startswith("."))


def file_mtime_text(path: Path) -> str:
    if not path.exists():
        return "n/a"
    return time.strftime("%H:%M:%S", time.localtime(path.stat().st_mtime))


def read_tail(path: Path, max_lines: int = 120) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return text.splitlines()[-max_lines:]


def parse_trainer_status(lines: list[str]) -> str:
    epoch = None
    feature = None
    for line in lines:
        match = re.search(r"Epoch\s+(\d+)/(\d+)", line)
        if match:
            epoch = f"{match.group(1)}/{match.group(2)}"
        match = re.search(r"number of feature\s+(\d+)", line)
        if match:
            feature = match.group(1)

    if feature is not None:
        return f"generating gradients (feature {feature})"
    if epoch is not None:
        return f"training model (epoch {epoch})"
    if any("connected by neuzz execution module" in line for line in lines):
        return "trainer connected"
    if lines:
        return "starting"
    return "waiting for logs"


def parse_neuzz_status(lines: list[str]) -> str:
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        if "edge num" in line or "dry run" in line or "fast stage" in line or "slow stage" in line:
            return line
    return "waiting for fuzzing output"


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def format_elapsed(seconds: float) -> str:
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def render(args: argparse.Namespace) -> None:
    workspace = Path(args.workspace).resolve()
    target_name = infer_target_name(workspace)
    start = time.time()
    neuzz_log = workspace / "logs" / "neuzz.log"
    nn_log = workspace / "logs" / "nn.log"
    gradient_info = workspace / "gradient_info_p"
    weights = workspace / "hard_label.weights.h5"
    seeds_dir = workspace / "seeds"
    crashes_dir = workspace / "crashes"
    vari_dir = workspace / "vari_seeds"
    results_crashes_dir = workspace / "results" / "crashes"

    while process_alive(args.pid):
        nn_lines = read_tail(nn_log)
        neuzz_lines = read_tail(neuzz_log)

        trainer_status = parse_trainer_status(nn_lines)
        neuzz_status = parse_neuzz_status(neuzz_lines)

        seed_count = count_files(seeds_dir)
        crash_count = count_files(crashes_dir)
        vari_count = count_files(vari_dir)
        result_crash_count = count_files(results_crashes_dir)

        display = [
            "\033[2J\033[H",
            f"Neuzz {target_name} Live Progress",
            "=" * 60,
            f"elapsed                : {format_elapsed(time.time() - start)}",
            f"trainer status         : {trainer_status}",
            f"neuzz status           : {neuzz_status}",
            f"seed corpus files      : {seed_count}",
            f"vari_seeds files       : {vari_count}",
            f"neuzz crash files      : {crash_count}",
            f"result bug artifacts   : {result_crash_count}",
            f"gradient file          : {'yes' if gradient_info.exists() else 'no'} (updated {file_mtime_text(gradient_info)})",
            f"weights file           : {'yes' if weights.exists() else 'no'} (updated {file_mtime_text(weights)})",
            f"nn log updated         : {file_mtime_text(nn_log)}",
            f"neuzz log updated      : {file_mtime_text(neuzz_log)}",
            "",
            "Recent trainer lines",
            "-" * 60,
        ]

        display.extend(nn_lines[-6:] if nn_lines else ["<no trainer log yet>"])
        display.extend(["", "Recent neuzz lines", "-" * 60])
        display.extend(neuzz_lines[-6:] if neuzz_lines else ["<no neuzz log yet>"])
        display.append("")
        display.append("Logs: logs/nn.log and logs/neuzz.log")

        sys.stdout.write("\n".join(display))
        sys.stdout.flush()
        time.sleep(args.interval)

    sys.stdout.write("\nNeuzz run finished.\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a live Neuzz benchmark progress dashboard.")
    parser.add_argument("--workspace", default=".", help="Benchmark workspace root.")
    parser.add_argument("--pid", required=True, type=int, help="PID of the Neuzz timeout wrapper to monitor.")
    parser.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds.")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    render(args)


if __name__ == "__main__":
    main()
