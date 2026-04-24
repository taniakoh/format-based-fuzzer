# Neuzz JSON Benchmark

This folder is a standalone Neuzz benchmark workspace for the repository's JSON target.

It is isolated from the main hybrid fuzzer code. Existing code paths were not modified.

## What is copied here

- `target/buggy_json/`: copied from the existing isolated JSON benchmark target
- `config/json_format.json`: copied from the repo's JSON format config
- `corpus_src/json_seeds.txt`: copied from the repo's JSON seed list
- `neuzz.c`: upstream Neuzz execution engine copied from `https://github.com/Dongdongshe/neuzz`

## What is adapted here

- `nn.py`: a local Python 3 / TensorFlow 2 adaptation of the upstream Neuzz trainer so it can be wired to this repo's JSON target
- `neuzz_json_target.py`: a file-based `python-afl` harness for the same buggy JSON decoder used by the AFL benchmark
- replay and measurement scripts that mirror the existing JSON benchmark output wording and result layout

## Important limit

Neuzz was originally published against Python 2.7, TensorFlow 1.8, and Keras 2.2.3 on Ubuntu 16.04/18.04.

This workspace keeps the upstream algorithm shape, but modern execution still depends on having compatible runtime packages installed in WSL:

- `python-afl`
- `numpy`
- `tensorflow`
- `afl-showmap`
- `gcc`

The replay and measurement scripts are immediately usable once Python dependencies are installed. The live Neuzz campaign also needs the training stack.

## Files

- `prepare_seed_corpus.py`: convert the copied seed list into Neuzz input files
- `build_neuzz.sh`: compile `neuzz.c`
- `run_neuzz_1h.sh`: launch a fixed 1-hour Neuzz campaign against the JSON target
- `neuzz_json_target.py`: file-based target harness for Neuzz and `afl-showmap`
- `replay_neuzz_findings.py`: replay Neuzz corpus outputs through the project-style runner
- `measure_neuzz_corpus.py`: produce source-level coverage and bug metrics from Neuzz outputs
- `json_case_runner.py`: replay a single input with project-style wording
- `results/`: local logs and reproducer artifacts created at runtime

## Setup

1. Install dependencies for this folder inside WSL.

```bash
cd neuzz-json-benchmark
python3 -m pip install -r requirements.txt
```

If you follow that command inside this folder's `.venv`, `run_neuzz_1h.sh` will pick it up automatically.

2. Generate Neuzz seed files from the copied JSON seed material.

```bash
python3 prepare_seed_corpus.py
```

3. Build the Neuzz engine.

```bash
chmod +x build_neuzz.sh run_neuzz_1h.sh
./build_neuzz.sh
```

## Run Neuzz

Fixed 1-hour benchmark run:

```bash
cd neuzz-json-benchmark
./run_neuzz_1h.sh
```

This script:

- computes the mutation length from the copied seed corpus
- starts the Neuzz trainer in the background
- runs the Neuzz engine for 1 hour against the JSON target
- stores campaign logs under `logs/`

## Replay findings with project-style wording

Replay crashes and saved seeds:

```bash
python3 replay_neuzz_findings.py --workspace .
```

Replay `vari_seeds` too:

```bash
python3 replay_neuzz_findings.py --workspace . --include-vari-seeds
```

Measure directly comparable corpus-level metrics:

```bash
python3 measure_neuzz_corpus.py --workspace . --include-vari-seeds
```

This is the command to use when you want source-level `coverage.py` metrics and a bug-type summary that you can compare against the hybrid fuzzer more fairly than Neuzz's raw edge counter.

## Single-input replay

```bash
python3 json_case_runner.py --input-file seeds/id_0_0_000000
```

or

```bash
python3 json_case_runner.py --str-json '{"json":"obj"}'
```

## Output layout

- `results/logs/bug_counts.csv`
- `results/logs/tracebacks.log`
- `results/crashes/`
- `logs/neuzz.log`
- `logs/nn.log`

These are local to this benchmark folder so they do not mix with your existing fuzzer outputs.
