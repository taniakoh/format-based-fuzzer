# AFL Cidrize Benchmark

This folder is a standalone AFL benchmark workspace for the repository's cidrize target.

It is isolated from the main hybrid fuzzer code. The original implementation was not modified.

## What this setup uses

- `config/cidrize_format.json`: copied from the repo's cidrize format config
- `linux-cidrize-runner_extracted/PYZ.pyz_extracted`: existing extracted cidrize parser payload from the repo root

## Setup

```bash
cd afl-cidrize-benchmark
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python prepare_seed_corpus.py
chmod +x run_afl_2h.sh
```

## Run AFL

```bash
./run_afl_2h.sh
```

## Measure the cidrize AFL corpus

```bash
python measure_afl_corpus.py --afl-out afl-out/default --include-queue
```

## Replay AFL findings

```bash
python replay_afl_findings.py --afl-out afl-out/default
```

## Generate graphs

```bash
python render_graphs.py
```
