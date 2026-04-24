from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    workspace = Path(sys.argv[1]).resolve()
    input_path = Path(sys.argv[2]).resolve()
    python_bin = str((workspace / ".venv" / "bin" / "python").resolve())
    target_script = str((workspace / "neuzz_target.py").resolve())

    import_check = subprocess.run(
        [str((workspace / ".venv" / "bin" / "python").resolve()), "-c", "import afl; print(afl.__file__)"],
        capture_output=True,
        text=True,
        check=False,
    )
    print(f"afl_import_returncode={import_check.returncode}")
    print("afl_import_stdout:")
    print(import_check.stdout.strip())
    print("afl_import_stderr:")
    print(import_check.stderr.strip())

    proc = subprocess.run(
        [
            os.environ.get("NEUZZ_AFL_SHOWMAP", "afl-showmap"),
            "-q",
            "-e",
            "-o",
            "/dev/stdout",
            "-m",
            "512",
            "-t",
            "30000",
            python_bin,
            target_script,
            str(input_path),
        ],
        capture_output=True,
        text=True,
        env=dict(os.environ, AFL_QUIET="1"),
        check=False,
    )

    print(f"returncode={proc.returncode}")
    print(f"stdout_lines={len(proc.stdout.splitlines())}")
    print(f"stderr_lines={len(proc.stderr.splitlines())}")
    print("stdout_head:")
    for line in proc.stdout.splitlines()[:10]:
        print(line)
    print("stderr_head:")
    for line in proc.stderr.splitlines()[:10]:
        print(line)


if __name__ == "__main__":
    main()
