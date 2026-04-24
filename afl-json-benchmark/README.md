# AFL JSON Benchmark

This folder is a standalone AFL benchmark workspace for the repository's JSON target.

It is isolated from the main hybrid fuzzer code. The original implementation was not modified.

## What is copied here

- `target/buggy_json/`: copied from `json-decoder-main/buggy_json`
- `config/json_format.json`: copied from the repo's JSON format config
- `corpus_src/json_seeds.txt`: copied from the repo's JSON seed list

## What this setup does

- uses the same JSON target family as the main project
- uses the same starter seed material
- runs a separate `python-afl` harness for benchmarking
- logs findings into local `results/` files
- provides a replay script whose wording matches the existing JSON runner style as closely as possible

## Important limit

The AFL live UI will still look like AFL.

What this setup can match is the per-input replay output, bug wording, local artifact layout, and bug-count logging style. That is the practical way to make the benchmark outputs comparable without changing AFL itself.

## Files

- `afl_json_harness.py`: stdin-based AFL target harness
- `json_case_runner.py`: replay a single input with project-style wording
- `replay_afl_findings.py`: replay AFL crashes and hangs through the runner
- `measure_afl_corpus.py`: produce source-level coverage and bug metrics from AFL outputs
- `prepare_seed_corpus.py`: convert the copied seed list into AFL input files
- `results/`: local logs and reproducer artifacts created at runtime

## Expected environment

- Linux
- Python interpreter that can import `afl`
- AFL installed so `py-afl-fuzz` is available

The `python-afl` README describes the required integration pattern and recommends `py-afl-fuzz` with a persistent loop:
https://github.com/jwilk/python-afl

## Setup

1. Install dependencies for this folder.

```bash
cd afl-json-benchmark
pip install -r requirements.txt
```

2. Generate AFL seed files from the copied JSON seed material.

```bash
python prepare_seed_corpus.py
```

This creates `afl_in/` with one file per seed.

## Run AFL

Fixed 1-hour benchmark run:

```bash
cd afl-json-benchmark
chmod +x run_afl_1h.sh
./run_afl_1h.sh
```

Equivalent explicit command:

```bash
cd afl-json-benchmark
mkdir -p afl-out
timeout 3600s py-afl-fuzz -i afl_in -o afl-out -- python afl_json_harness.py
```

This makes the AFL campaign run for 1 hour total. The harness still keeps the per-input timeout at 3 seconds by default.

## Replay AFL findings with project-style wording

Replay crashes and hangs:

```bash
python replay_afl_findings.py --afl-out afl-out/default
```

Measure directly comparable corpus-level metrics:

```bash
python measure_afl_corpus.py --afl-out afl-out/default --include-queue
```

This is the command to use when you want source-level `coverage.py` metrics and a bug-type summary that you can compare against the hybrid fuzzer more fairly than AFL's bitmap density.

Replay queue entries too:

```bash
python replay_afl_findings.py --afl-out afl-out/default --include-queue
```

## Single-input replay

```bash
python json_case_runner.py --input-file afl-out/default/crashes/id:000000,...
```

or

```bash
python json_case_runner.py --str-json '{"json":"obj"}'
```

## Output layout

- `results/logs/bug_counts.csv`
- `results/logs/tracebacks.log`
- `results/crashes/`

These are local to this benchmark folder so they do not mix with your existing fuzzer outputs.
