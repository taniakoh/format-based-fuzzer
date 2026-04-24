# AFL IPv6 Benchmark

This folder is a standalone AFL benchmark workspace for the repository's IPv6 target.

It is isolated from the main hybrid fuzzer code. The original implementation was not modified.

## What this setup uses

- `config/ipv6_format.json`: copied from the repo's IPv6 format config
- `linux-ipv6-parser_extracted/PYZ.pyz_extracted`: existing extracted IPv6 parser payload from the repo root

Unlike the JSON benchmark, this folder does not copy the extracted payload because it is large. The harnesses here load the already-extracted IPv6 parser from the repo root.

## Files

- `afl_ipv6_harness.py`: stdin-based AFL target harness
- `ipv6_case_runner.py`: replay a single input with project-style wording
- `replay_afl_findings.py`: replay AFL crashes and hangs through the runner
- `measure_afl_corpus.py`: produce oracle-based bug metrics from AFL outputs
- `export_plot_data.py`: convert AFL plot data into project-style plot_data
- `render_graphs.py`: render `progress.svg` from the converted plot data
- `prepare_seed_corpus.py`: create AFL seed files for IPv6

## Setup

```bash
cd afl-ipv6-benchmark
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

## Measure the IPv6 AFL corpus

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
