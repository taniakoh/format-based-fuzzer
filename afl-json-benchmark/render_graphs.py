from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent


def main() -> None:
    plot_data = ROOT / "plot_data"
    subprocess.run([sys.executable, str(ROOT / "export_plot_data.py"), "--output", str(plot_data)], check=True)
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "evaluation" / "plot_progress.py"),
            str(plot_data),
            "--output",
            str(ROOT / "progress.svg"),
        ],
        check=True,
    )
    print(f"Wrote {ROOT / 'progress.svg'}")
    print(f"Wrote {ROOT / 'eval_graphs.svg'}")


if __name__ == "__main__":
    main()
