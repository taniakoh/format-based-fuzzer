# Neuzz Text Benchmark Workspace

This folder is a standalone Neuzz benchmark workspace for the target encoded by
the folder name, for example `neuzz-ipv4-benchmark` or
`neuzz-cidrize-benchmark`.

It reuses the same Neuzz engine layout as the JSON benchmark, but points the
target harness at the extracted Python payloads from the Linux parser binaries.

## Files

- `prepare_seed_corpus.py`: builds the Neuzz input corpus from local config and seed files
- `build_neuzz.sh`: compiles `neuzz.c`
- `run_neuzz_1h.sh`: runs a timed Neuzz campaign, honoring `NEUZZ_BENCHMARK_SECONDS`
- `neuzz_target.py`: file-based `python-afl` harness for the extracted parser target
- `text_case_runner.py`: replay a single input with project-style wording
- `replay_neuzz_findings.py`: replay saved Neuzz findings
- `measure_neuzz_corpus.py`: summarize Neuzz findings and replayed bitmap coverage
- `render_graphs.py`: generate `progress.svg` and `eval_graphs.svg`

## Typical flow

```bash
python3 prepare_seed_corpus.py
./build_neuzz.sh
NEUZZ_BENCHMARK_SECONDS=10800 ./run_neuzz_1h.sh
./.venv/bin/python measure_neuzz_corpus.py --workspace . --include-vari-seeds
python render_graphs.py
```
