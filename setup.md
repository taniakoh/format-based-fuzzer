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
source ~/fuzzer-venv/bin/activate
```

Check that it worked:

```bash
which python3
python3 --version
```

If the venv is active, the Python path should point to `~/fuzzer-venv/bin/python3`.

### Optional: run the fuzzer

```bash
python3 main.py ipv4 --time-budget 300 --fresh-start
```

### Prerequisites

Ensure you are running Ubuntu 24.04 in WSL. To set it as default from PowerShell:
```powershell
wsl --set-default Ubuntu-24.04
```

### Install system dependencies
```bash
sudo apt update
sudo apt install python3-full python3-venv -y
```

### Install AFL++ (for QEMU instrumentation)

AFL++ provides `afl-showmap`, which upgrades the fuzzer from behavior-hash mode to real edge-coverage mode for the IPv4/IPv6/cidrize targets.

```bash
sudo apt install afl++ -y
```

Verify it installed:
```bash
which afl-showmap
afl-showmap --help 2>&1 | head -5
```

Once installed, the fuzzer will automatically use QEMU mode — you'll see `[*] Executor mode : QEMU` at startup instead of `Linux`.

### Create venv

The project directory is on `/mnt/c` (NTFS), which does not support the permissions required for a venv. Create it in your Linux home directory instead:

```bash
python3 -m venv ~/fuzzer-venv
source ~/fuzzer-venv/bin/activate
```

### Install dependencies
```bash
pip install -r requirements.txt
pip install torch --index-url https://download.pytorch.org/whl/cu124
```

> **CUDA note:** The above installs PyTorch with CUDA 12.4 support, which is compatible with CUDA 13.x drivers (RTX 3050). Verify with:
> ```bash
> python3 -c "import torch; print(torch.__version__); print(torch.cuda.is_available())"
> ```

### Activate venv (each session)
```bash
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
source ~/fuzzer-venv/bin/activate
```

### Full startup sequence (copy/paste)

```powershell
wsl -d Ubuntu-24.04
```

```bash
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
source ~/fuzzer-venv/bin/activate
python3 --version
```

### Run the fuzzer
```bash
python3 main.py ipv4 --time-budget 300 --fresh-start
```

## Performance: Copy Linux Binaries to Native WSL Storage

The parser binaries live on `/mnt/c` (NTFS), which is accessed through WSL's DrvFs layer. Each fuzzing run reads a ~56 MB PyInstaller bundle from the Windows filesystem — this cross-filesystem I/O is significantly slower than native Linux paths.

**One-time setup** (do this once per WSL install):

```bash
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/ipv4ipv6/linux-ipv4-parser ~/linux-ipv4-parser
cp /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer/ipv4ipv6/linux-ipv6-parser ~/linux-ipv6-parser
chmod +x ~/linux-ipv4-parser ~/linux-ipv6-parser
```

Then tell the fuzzer to use the native copies by setting `FUZZER_LINUX_IPV4` and `FUZZER_LINUX_IPV6` (if supported), or by passing the paths at runtime:

```bash
LINUX_IPV4=~/linux-ipv4-parser LINUX_IPV6=~/linux-ipv6-parser python3 main.py ipv4 --time-budget 300
```

If `main.py` does not yet read those env vars, you can register the paths directly in a one-liner before the main loop, or add `"binary_linux": "/home/<user>/linux-ipv4-parser"` to `config/ipv4_format.json`.

> **Why this matters:** WSL2 cross-filesystem calls (Windows ↔ Linux) go through a translation layer. For large binaries that are re-read on every subprocess spawn, this adds measurable latency per execution compared to binaries stored under `~/` on the native ext4 filesystem.
