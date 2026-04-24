# AFL IPv4 Benchmark

This folder is a standalone AFL benchmark workspace for the repository's IPv4 target.

It is isolated from the main hybrid fuzzer code. The original implementation was not modified.

## What this setup uses

- `config/ipv4_format.json`: copied from the repo's IPv4 format config
- `linux-ipv4-parser_extracted/PYZ.pyz_extracted`: existing extracted IPv4 parser payload from the repo root

Unlike the JSON benchmark, this folder does not copy the extracted payload because it is large. The harnesses here load the already-extracted IPv4 parser from the repo root.

## What this setup does

- uses the extracted IPv4 parser logic as the AFL target
- uses a standalone seed corpus aligned with the IPv4 format used by the hybrid fuzzer
- runs a separate `python-afl` harness for benchmarking
- logs findings into local `results/` files
- provides replay and summary scripts with project-style wording

## Files

- `afl_ipv4_harness.py`: stdin-based AFL target harness
- `ipv4_case_runner.py`: replay a single input with project-style wording
- `replay_afl_findings.py`: replay AFL crashes and hangs through the runner
- `measure_afl_corpus.py`: produce oracle-based bug metrics from AFL outputs
- `export_plot_data.py`: convert AFL plot data into project-style plot_data
- `render_graphs.py`: render `progress.svg` from the converted plot data
- `prepare_seed_corpus.py`: create AFL seed files for IPv4
- `results/`: local logs and reproducer artifacts created at runtime

## Setup

```bash
cd afl-ipv4-benchmark
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python prepare_seed_corpus.py
chmod +x run_afl_1h.sh
```

## Run AFL

```bash
chmod +x run_afl_2h.sh
./run_afl_2h.sh
```

## Replay AFL findings

```bash
python replay_afl_findings.py --afl-out afl-out/default
```

Replay queue entries too:

```bash
python replay_afl_findings.py --afl-out afl-out/default --include-queue
```

## Measure the IPv4 AFL corpus

```bash
python measure_afl_corpus.py --afl-out afl-out/default --include-queue
```

This summary is oracle-driven and AFL-stats-driven. It is not a source-level `coverage.py` report like the JSON benchmark.

## Generate graphs

```bash
python export_plot_data.py --output plot_data
python ../evaluation/plot_progress.py plot_data --output progress.svg
```

Or use the wrapper:

```bash
python render_graphs.py
```
