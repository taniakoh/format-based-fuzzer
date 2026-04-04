# Setup Guide

## WSL (Ubuntu 24.04)

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
source ~/fuzzer-venv/bin/activate
cd /mnt/c/Users/tanta/Downloads/Code/softwaretesting/format-based-fuzzer
```

### Run the fuzzer
```bash
python3 main.py ipv4 --time-budget 300 --fresh-start
```
