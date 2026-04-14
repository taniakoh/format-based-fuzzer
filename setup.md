# Setup Guide

## WSL (Ubuntu 24.04)

## Quick Start For Each Session

Use this when you are starting fresh and just want to get into the project quickly.

### From Windows PowerShell

Open WSL:

```powershell
wsl -d Ubuntu-24.04
```

### Inside WSL

Go to the project:

```bash
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
```

Activate the virtual environment:

```bash
source fuzzer-venv/bin/activate
```

Check that it worked:

```bash
which python
python --version  # should be 3.11.x
```

### Optional: run the fuzzer

```bash
python main.py ipv4 --time-budget 300 --fresh-start
```

---

## First-Time Setup

### Prerequisites

Ensure you are running Ubuntu 24.04 in WSL. To set it as default from PowerShell:

```powershell
wsl --set-default Ubuntu-24.04
```

### Install system dependencies

```bash
sudo apt update
sudo apt install python3-full python3-venv python3.11 python3.11-venv python3.11-dev -y
```

### Install uv (fast package manager)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc  # or restart the shell
```

### Create venv with Python 3.11

The venv lives inside the project directory. Python 3.11 is required for Atheris (the JSON fuzzing target).

```bash
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
uv venv fuzzer-venv --python 3.11
source fuzzer-venv/bin/activate
```

If uv cannot find Python 3.11, let it fetch it:

```bash
uv python install 3.11
uv venv fuzzer-venv --python 3.11
```

### Install dependencies

```bash
uv pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cu121 --index-strategy unsafe-best-match
```

### Install Frida (for black-box instrumentation)

Linux black-box coverage now comes from Frida Stalker for the IPv4, IPv6, cidrize, and cJSON targets.

Install the Python bindings and CLI tools inside the active project venv:

```bash
uv pip install frida frida-tools
```

Verify it installed:

```bash
python -c "import frida; print(frida.__version__)"
```

If WSL blocks local process attachment, relax ptrace restrictions:

```bash
sudo sysctl kernel.yama.ptrace_scope=0
```

Once installed, Linux binary targets will start in Frida mode and print `[*] Executor mode : Frida`.

### Make binaries executable

```bash
chmod +x cidrize-runner-main/bin/linux-cidrize-runner
chmod +x ipv4ipv6/linux-ipv4-parser
chmod +x ipv4ipv6/linux-ipv6-parser
chmod +x cjson/cjson_driver_asan
```

### Verify GPU (optional)

```bash
python -c "import torch; print(torch.__version__); print(torch.cuda.is_available())"
```

Should print `True` for CUDA if your NVIDIA driver is installed on Windows.

---

## Full Startup Sequence (copy/paste)

```powershell
wsl -d Ubuntu-24.04
```

```bash
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
source fuzzer-venv/bin/activate
python --version
```

## Run the Fuzzer

```bash
# Single target
python main.py ipv4 --time-budget 300 --fresh-start
python main.py ipv6 --time-budget 300 --fresh-start
python main.py cidrize --time-budget 300 --fresh-start
python main.py cjson --time-budget 300 --fresh-start
python main.py json --time-budget 300 --fresh-start

# All targets in parallel (ipv4, ipv6, cidrize, json run simultaneously)
python main.py all --time-budget 300 --fresh-start
```

## Post-Run Analysis

After the run completes, run these in order:

```bash
# 1. Stats summary (already written automatically)
type results/ipv4/stats.txt

# 2. Coverage plot (SVG)
python evaluation/plot_progress.py ipv4
python evaluation/plot_progress.py ipv6

# 3. Traceback analysis
python -m evaluation.traceback_analysis ipv4
python -m evaluation.traceback_analysis ipv6

# 4. Evaluation graphs
python evaluation/plot_progress.py ipv4
```

## Example 3-Hour Hybrid DL Runs

```bash
python main.py ipv4 --evaluation-mode hybrid_dl --fresh-start --time-budget 10800 --seed 1
python main.py ipv6 --evaluation-mode hybrid_dl --fresh-start --time-budget 10800 --seed 1
python main.py cidrize --evaluation-mode hybrid_dl --fresh-start --time-budget 10800 --seed 1
python main.py json --evaluation-mode hybrid_dl --fresh-start --time-budget 10800 --seed 1
python main.py json_direct --evaluation-mode hybrid_dl --fresh-start --time-budget 10800 --seed 1
```

## Example 6-Hour Havoc-Only Runs

```bash
python main.py ipv4 --evaluation-mode havoc_only --fresh-start --time-budget 21600 --seed 1
python main.py ipv6 --evaluation-mode havoc_only --fresh-start --time-budget 21600 --seed 1
python main.py cidrize --evaluation-mode havoc_only --fresh-start --time-budget 21600 --seed 1
python main.py json --evaluation-mode havoc_only --fresh-start --time-budget 21600 --seed 1
python main.py json_direct --evaluation-mode havoc_only --fresh-start --time-budget 21600 --seed 1
```

---

## Performance: Copy Linux Binaries to Native WSL Storage

The parser binaries live on `/mnt/c` (NTFS), which is accessed through WSL's DrvFs layer. Each fuzzing run reads a large PyInstaller bundle from the Windows filesystem. This cross-filesystem I/O is significantly slower than native Linux paths.

**One-time setup** (do this once per WSL install):

```bash
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/ipv4ipv6/linux-ipv4-parser ~/linux-ipv4-parser
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/ipv4ipv6/linux-ipv6-parser ~/linux-ipv6-parser
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/cidrize-runner-main/bin/linux-cidrize-runner ~/linux-cidrize-runner
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/cjson/cjson_driver_asan ~/cjson_driver_asan
chmod +x ~/linux-ipv4-parser ~/linux-ipv6-parser ~/linux-cidrize-runner ~/cjson_driver_asan
```

Then update the binary paths in the format configs to use the native copies:

- `config/ipv4_format.json` -> `"binary_linux": "/home/<user>/linux-ipv4-parser"`
- `config/ipv6_format.json` -> `"binary_linux": "/home/<user>/linux-ipv6-parser"`
- `config/cidrize_format.json` -> `"binary_linux": "/home/<user>/linux-cidrize-runner"`
- `config/cjson_format.json` -> `"binary_linux": "/home/<user>/cjson_driver_asan"`

> **Why this matters:** WSL2 cross-filesystem calls (Windows <-> Linux) go through a translation layer. For large binaries that are re-read on every subprocess spawn, this adds measurable latency per execution compared to binaries stored under `~/` on the native ext4 filesystem.
