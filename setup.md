# Setup Guide

This guide is written for both the original development machine and other
people's computers. Replace any example paths with the path where you actually
cloned the repository.

## Recommended Environment

- Windows 11 with WSL2
- Ubuntu 24.04 inside WSL
- Python 3.11
- The repository cloned somewhere on the Windows filesystem or directly inside
  the WSL filesystem

## Before You Start

Decide where your repository lives. In the examples below, use one of these
patterns:

- If the repo is on the Windows filesystem:
  `/mnt/c/Users/<your-windows-user>/path/to/format-based-fuzzer`
- If the repo is inside the Linux home directory:
  `~/format-based-fuzzer`

You can check your current location with:

```bash
pwd
```

If you are unsure, `cd` into the repo and run `pwd`, then reuse that exact path
throughout the guide.

---

## Quick Start For Each Session

Use this when the project has already been set up once and you just want to
start working.

### From Windows PowerShell

Open WSL:

```powershell
wsl -d Ubuntu-24.04
```

### Inside WSL

Go to the project:

```bash
cd /path/to/format-based-fuzzer
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

Optional smoke test:

```bash
python main.py ipv4 --time-budget 300 --fresh-start
```

---

## First-Time Setup

### 1. Install WSL Ubuntu 24.04

If needed, install or select Ubuntu 24.04 from Windows PowerShell:

```powershell
wsl --set-default Ubuntu-24.04
```

### 2. Install system dependencies

Inside WSL:

```bash
sudo apt update
sudo apt install python3-full python3-venv python3.11 python3.11-venv python3.11-dev curl -y
```

### 3. Install uv

Inside WSL:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

If `uv` is still not found, close and reopen the shell.

### 4. Create a Python 3.11 virtual environment

The venv lives inside the project directory. Python 3.11 is required for
Atheris, which is used by the JSON fuzzing target.

```bash
cd /path/to/format-based-fuzzer
uv venv fuzzer-venv --python 3.11
source fuzzer-venv/bin/activate
```

If `uv` cannot find Python 3.11, let it fetch it and retry:

```bash
uv python install 3.11
uv venv fuzzer-venv --python 3.11
source fuzzer-venv/bin/activate
```

### 5. Install Python dependencies

```bash
uv pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cu121 --index-strategy unsafe-best-match
```

Notes:

- The PyTorch packages in `requirements.txt` are CUDA-enabled builds.
- If you do not have a compatible NVIDIA setup, PyTorch may still install but
  CUDA will not be available.
- GPU support is optional for basic fuzzing.

### 6. Install Frida for Linux binary instrumentation

Linux black-box coverage for the IPv4, IPv6, cidrize, and cJSON targets uses
Frida Stalker.

Install it in the active virtual environment:

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

When Frida mode is active, Linux binary targets print:

```text
[*] Executor mode : Frida
```

### 7. Make shipped Linux binaries executable

```bash
chmod +x cidrize-runner-main/bin/linux-cidrize-runner
chmod +x ipv4ipv6/linux-ipv4-parser
chmod +x ipv4ipv6/linux-ipv6-parser
chmod +x cjson/cjson_driver_asan
```

### 8. Verify the environment

```bash
python --version
python -c "import torch; print(torch.__version__); print(torch.cuda.is_available())"
```

`torch.cuda.is_available()` returning `False` is acceptable if you are running
CPU-only.

---

## Portable Default Setup

For most people, the easiest setup is to use the binaries directly from the
repository without editing any config files.

This works best when the target configs use repository-relative `binary_linux`
paths. If a config currently points to a machine-specific absolute path such as
`/home/<user>/...`, update it for your machine before running.

The most important files to check are:

- `config/ipv4_format.json`
- `config/ipv6_format.json`
- `config/cidrize_format.json`
- `config/cjson_format.json`

If you want a portable, repo-local path, use values like:

- `ipv4`: `"binary_linux": "ipv4ipv6/linux-ipv4-parser"`
- `ipv6`: `"binary_linux": "ipv4ipv6/linux-ipv6-parser"`
- `cidrize`: `"binary_linux": "cidrize-runner-main/bin/linux-cidrize-runner"`
- `cjson`: `"binary_linux": "cjson/cjson_driver_asan"`

If you are sharing this repository with another person, ask them to confirm
these paths before their first run.

---

## Full Startup Sequence

```powershell
wsl -d Ubuntu-24.04
```

```bash
cd /path/to/format-based-fuzzer
source fuzzer-venv/bin/activate
python --version
```

## Run the Fuzzer

```bash
# Single target
python main.py ipv4 --time-budget 3600 --fresh-start
python main.py ipv6 --time-budget 3600 --fresh-start
python main.py cidrize --time-budget 3600 --fresh-start
python main.py cjson --time-budget 300 --fresh-start
python main.py json --time-budget 3600 --fresh-start
python main.py xml --time-budget 3600 --fresh-start

# Default multi-target run (ipv4, ipv6, cidrize, json run simultaneously)
python main.py all --time-budget 300 --fresh-start
```

## Post-Run Analysis

After a run completes, useful follow-up commands are:

```bash
# 1. Stats summary (already written automatically)
cat results/ipv4/stats.txt

# 2. Coverage plots
python evaluation/plot_progress.py ipv4
python evaluation/plot_progress.py ipv6

# 3. JSON source-coverage replay and plot refresh
# This computes absolute coverage.py statement+branch coverage for buggy_json
# from the saved Atheris corpus and updates progress.svg to use it.
python evaluation/json_coverage_replay.py json
python evaluation/plot_progress.py json

# 4. Traceback analysis
python -m evaluation.traceback_analysis ipv4
python -m evaluation.traceback_analysis ipv6
```

For future `python main.py json ...` runs, the JSON replay step is triggered
automatically at the end of the campaign when `coverage` is installed in the
same WSL virtual environment. The manual `evaluation/json_coverage_replay.py`
command is mainly for backfilling older `results/json/` runs.

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

## Optional Performance Optimization: Copy Linux Binaries to Native WSL Storage

This section is optional. The default repo-local setup is simpler and more
portable. Use this only if you want faster Linux binary startup under WSL.

The parser binaries may live on `/mnt/c` if the repository is stored on the
Windows filesystem. WSL accesses that path through DrvFs, which is slower than
native Linux storage for repeated subprocess launches.

### One-time setup

First, change into your repository and confirm the path:

```bash
cd /path/to/format-based-fuzzer
pwd
```

Then copy the Linux binaries into your Linux home directory:

```bash
cp /path/to/format-based-fuzzer/ipv4ipv6/linux-ipv4-parser ~/linux-ipv4-parser
cp /path/to/format-based-fuzzer/ipv4ipv6/linux-ipv6-parser ~/linux-ipv6-parser
cp /path/to/format-based-fuzzer/cidrize-runner-main/bin/linux-cidrize-runner ~/linux-cidrize-runner
cp /path/to/format-based-fuzzer/cjson/cjson_driver_asan ~/cjson_driver_asan
chmod +x ~/linux-ipv4-parser ~/linux-ipv6-parser ~/linux-cidrize-runner ~/cjson_driver_asan
```

### Config changes for the optimization

If you use the copied binaries, update the format configs to point to your own
Linux home directory:

- `config/ipv4_format.json` -> `"binary_linux": "/home/<your-linux-user>/linux-ipv4-parser"`
- `config/ipv6_format.json` -> `"binary_linux": "/home/<your-linux-user>/linux-ipv6-parser"`
- `config/cidrize_format.json` -> `"binary_linux": "/home/<your-linux-user>/linux-cidrize-runner"`
- `config/cjson_format.json` -> `"binary_linux": "/home/<your-linux-user>/cjson_driver_asan"`

You can discover your Linux username with:

```bash
whoami
echo $HOME
```

> Why this matters: WSL2 cross-filesystem calls go through a translation layer.
> For large binaries that are re-read on each subprocess spawn, storing them
> under `~/` on the native ext4 filesystem can reduce launch overhead.

---

## Sharing Checklist For Another Computer

Before handing this repo to someone else, verify these items:

- They know the exact repo path on their machine.
- They are using WSL Ubuntu 24.04 or a similar Linux environment.
- They created and activated `fuzzer-venv` with Python 3.11.
- They installed `requirements.txt`.
- They installed `frida` and `frida-tools`.
- The shipped Linux binaries are executable.
- Any `binary_linux` entries that use absolute paths were updated for their
  username and home directory.

If those are all true, the project should run on another person's computer.
