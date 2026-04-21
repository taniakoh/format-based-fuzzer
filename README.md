# Hybrid Coverage-Guided Fuzzer

A format-aware fuzzer targeting IPv4, IPv6, cidrize, cJSON, a bundled JSON decoder,
and an XML target backed by stdlib parsers.
For binary targets, the executor now supports three runtime modes: Windows
behavior hashing, Linux behavior hashing, and AFL++ QEMU edge coverage when
`afl-showmap` is available. The `cjson` target uses the ASan-enabled Linux
driver by default.

## Project Structure

```text
format-based-fuzzer/
|- config/                    # Format configs (fields, semantic rules, havoc weights)
|  |- ipv4_format.json
|  |- ipv6_format.json
|  |- cidrize_format.json
|  `- json_format.json
|- corpus/                    # Optional hand-picked seed corpora
|  |- cidrize_seeds.txt
|  `- json_seeds.txt
|- fuzzer/                    # Core fuzzer modules
|  |- seed_generator.py       # Grammar-based valid seed generation
|  |- mutation/
|  |  |- tier1_structure.py   # Structural mutations (pass-through today)
|  |  |- tier2_semantic.py    # Semantic-span-guided string mutations
|  |  `- tier3_havoc.py       # Stochastic byte-level mutations with optional hot-byte bias
|  |- executor.py             # Wraps platform-specific parser binaries
|  |- json_atheris_harness.py # Atheris harness for the JSON decoder
|  |- coverage.py             # Behavior-based coverage tracking
|  |- corpus.py               # Seed queue with priority selection
|  `- scheduler.py            # Static + payoff-tracking scheduler primitives
|- dl/                        # Hybrid DL scheduler (optional, requires torch)
|  |- surrogate.py            # Neural surrogate model + hybrid scheduler
|  |- trainer.py              # Training loop + checkpoint save/load
|  `- trustworthiness.py      # Confidence gate
|- evaluation/
|  |- collect_metrics.py      # Metrics collection and stats output
|  `- plot_progress.py        # SVG plot generation from plot_data
|- models/                    # Saved model checkpoints (created at runtime)
|- results/                   # Fuzzing output (created at runtime)
|- ipv4ipv6/                  # Target binaries
|- cidrize-runner-main/       # Cidrize target binaries/wrappers
|- json-decoder-main/         # Bundled JSON decoder target
`- main.py                    # Entry point
```

---

## Why Add a New Format?

Adding a new format is mainly about testing whether the fuzzer's design really
generalizes beyond the formats it already knows.

- It checks the repository's main architectural claim: new targets should be
  onboarded mostly through config, seeds, and lightweight target-specific
  semantics, not by rewriting the engine.
- It broadens evaluation across different input shapes, which makes it easier
  to tell whether a scheduler or mutation strategy is genuinely format-agnostic
  or only tuned to one parser family.
- It helps expose where the current pipeline is too brittle, such as when a new
  target needs deeper structural mutations, a stronger oracle, or a different
  seed-generation strategy.
- It increases the practical value of the project by showing that the same
  corpus, coverage, and scheduling machinery can transfer to additional real
  parsers with limited manual work.

In short, a new format is useful when it strengthens the evidence that this is
an extensible format-aware fuzzing framework rather than a set of one-off
target integrations.

---

## Requirements

**Python 3.11+** is the primary supported setup for the binary targets.

The repository also ships a `requirements.txt` with pinned optional dependencies used by the DL and JSON paths.

### Phase 2 (DL Scheduler) - optional

Requires PyTorch. The fuzzer auto-detects CUDA; if unavailable it falls back to CPU.

**CPU-only:**

```bash
pip install torch
```

**CUDA (recommended if you have an NVIDIA GPU):**

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

Verify CUDA is detected:

```bash
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

> `hybrid_dl` requires torch. The explicit evaluation modes let you run fixed
> baselines (`havoc_only`, `semantic_plus_havoc`), payoff-tracking without DL
> (`static_payoff`), or the guarded learned scheduler (`hybrid_dl`).

### Linux edge coverage with AFL++ QEMU - optional

On Linux, if the target has a registered `binary_linux` path and `afl-showmap`
is installed, the executor switches to `QEMU` mode automatically and records a
real 65,536-byte AFL++ edge bitmap instead of the fallback behavior hash.

If `afl-showmap` is not installed, Linux still runs natively, but coverage
falls back to the same behavior-hash model used on Windows.

### JSON and XML target requirements

The `json` and `xml` targets use [Atheris](https://github.com/google/atheris) for instrumentation.

- Official Atheris support is documented for Linux/macOS and Python 3.6-3.11.
- The harness in this repo exits early with a clear error on unsupported environments such as Windows or Python 3.12+.
- Install it with `pip install atheris` in a compatible interpreter.

---

## Running the Fuzzer

### Basic usage

```bash
python main.py <target> [options]
```

| Argument | Values | Description |
|---|---|---|
| `target` | `ipv4`, `ipv6`, `cidrize`, `cjson`, `json`, `xml`, `all` | Which parser to fuzz (`all` runs `ipv4`, `ipv6`, `cidrize`, and `json` in parallel) |
| `--havoc-iters N` | int (default: `8`) | Byte-level mutations applied per execution |
| `--time-budget S` | int (default: `86400`) | Total fuzzing time in seconds |
| `--seed RNG` | int (default: `42`) | RNG seed for reproducibility |
| `--seeds-n N` | int (default: `100`) | Initial corpus size loaded at startup |
| `--evaluation-mode MODE` | `auto`, `havoc_only`, `semantic_plus_havoc`, `static_payoff`, `hybrid_dl` | Explicit evaluation configuration |
| `--coverage MODE` | `auto`, `frida`, `hash` (default: `auto`) | Coverage instrumentation mode: `auto` picks Frida on Linux when a linux binary is present, else falls back to behavior-hash; `frida` forces Frida (Linux + linux binary required); `hash` forces behavior-hash and skips Frida entirely |
| `--persistent` | flag | For Linux `ipv4`/`ipv6`, reuse a long-lived Python worker backed by the extracted parser bundle to avoid per-input startup cost. This mode uses behavior-hash coverage instead of Frida |
| `--no-dl` | flag | Compatibility flag that forces a non-DL mode |
| `--fresh-start` | flag | Clear `results/<target>/` and `models/<target>_surrogate.pt` before the run |

### Examples

```bash
# Quick smoke test (~5 min)
python main.py ipv4 --time-budget 300

# Fuzz IPv4 for 1 hour
python main.py ipv4 --time-budget 3600

# Fuzz IPv6 for 1 hour with more havoc mutations per call
python main.py ipv6 --time-budget 3600 --havoc-iters 16

# Fuzz cidrize for 1 hour
python3 main.py cidrize --time-budget 3600

# Fuzz cJSON with the ASan-enabled driver
python3 main.py cjson --time-budget 3600

# Fuzz the bundled JSON decoder with Atheris for 10 minutes
python main.py json --time-budget 600

# Fuzz the XML parser pair with Atheris for 10 minutes
python main.py xml --time-budget 600

# Fuzz the default multi-target set (`ipv4`, `ipv6`, `cidrize`, `json`) in parallel
python main.py all --time-budget 86400

# Reproducible run
python main.py ipv4 --time-budget 3600 --seed 123

# Pure havoc-only baseline
python main.py ipv4 --time-budget 3600 --evaluation-mode havoc_only

# Semantic mutations without payoff tracking or DL
python main.py ipv4 --time-budget 3600 --evaluation-mode semantic_plus_havoc

# Static payoff-tracking scheduler
python main.py ipv4 --time-budget 3600 --evaluation-mode static_payoff

# Hybrid DL scheduler
python main.py ipv4 --time-budget 3600 --evaluation-mode hybrid_dl

# Oracle regression checks
python evaluation/oracle_checks.py

# Start from a clean slate
python3 main.py ipv4 --time-budget 100 --fresh-start

python3 main.py ipv6 --time-budget 100 --fresh-start

```

> On Linux, Frida Stalker now prefers symbolicated source-line hits for the binary targets when `frida` is installed, hashing `(file, line)` locations into the 65,536-slot bitmap. When debug symbols are unavailable it falls back to block-edge hashing. Pass `--coverage hash` to skip Frida entirely and use behavior-hash mode on any platform.

> For throughput-focused Linux runs on the extracted `ipv4` and `ipv6` bundles, pass `--persistent --coverage hash` to keep the parser loaded in a long-lived worker process instead of paying startup cost on every testcase.

> On Windows, the parser bundles are PyInstaller one-file executables. Each
> execution can take about 20-30 seconds to unpack, so expect much lower exec/s
> than on Linux.

> The `cjson` target is Linux-only in this repository and defaults to
> `cjson/cjson_driver_asan`, so AddressSanitizer findings surface as crashes
> during fuzzing without any extra runtime flag.

> The `json` and `xml` targets are different: they launch Atheris/libFuzzer campaigns in `results/json/` and `results/xml/` and let Atheris manage corpus growth and coverage guidance directly.

---

## Hybrid Static + DL Scheduling

The scheduler now treats static behavior as a first-class policy, not a one-time bootstrap. This is deliberate and follows the same conservative lesson emphasized by Neuzz++: when the learned model is noisy, sparse, or temporarily misleading, the fuzzer should reduce learned influence instead of committing to it.

That matters especially in this repository because:

- coverage is hashed parser behavior on fallback paths, not true edge coverage
- the parser binaries are opaque
- executions are slow, so training data arrives slowly
- the model can overfit a small set of observed behaviors

The model is intentionally scoped as a compressed behavior proxy rather than a
full surrogate for the runtime bitmap. The proxy head is 128-dimensional, so
DL guidance is best understood as a routing hint layered on top of stronger
mutation baselines, not as a complete learned coverage objective.

### Policy

The runtime policy is hybrid rather than "DL on forever":

- if the model confidence is below the trust threshold, mutation stays static
- if the model is still undertrained, mutation stays static
- once the model has enough data, operator weights are blended with static priors instead of replacing them
- if recent guided decisions underperform recent static decisions, guided influence is reduced automatically
- seed prioritization also keeps a static baseline, and only adds a DL boost when guidance is currently trusted

Current gating thresholds in code:

- confidence threshold: `0.75`
- warm-up samples: `20`
- warm-up training rounds: `2`

In practice the schedule is intentionally conservative:

- early run: mostly static
- after enough training: partially guided
- if guidance helps: its blend weight grows
- if guidance becomes unstable: the scheduler falls back toward static behavior

This is a better fit for the project than a hard mode switch because the ML signal here is useful but imperfect. Neuzz++ motivates exactly this kind of guarded hybridization: learned guidance should augment a strong mutation baseline, not replace it unconditionally.

---

## Guided Mutation Routing

The DL model now acts as a routing signal instead of trying to replace the
format-specific mutators.

### How it works

1. The surrogate ranks input byte positions by gradient importance.
2. If the confidence gate trusts that guidance, the scheduler exposes those hot
   byte indices to the mutators.
3. Tier 2 maps hot bytes back to semantic spans and prefers mutating those
   spans first.
4. Tier 3 keeps its normal weighted havoc operators, but biases mutation
   positions toward hot bytes with a 70/30 guided-vs-random mix.

This keeps the model in an "attention" role:

- the model says "look here"
- the semantic mutator says "apply a structured edit here"
- the havoc mutator says "spend more byte-level budget here, but keep exploring"

### Semantic spans

`tier2_semantic.py` now exposes a generic `SemanticSpan` abstraction. A format
mutator can describe regions such as:

- IPv4 octets
- IPv6 groups or `::` separators
- JSON keys, values, arrays, or punctuation
- any other structured text region for a future format

That means the guidance path is no longer hard-coded to IP addresses. To add a
new structured format such as stringified JSON, implement:

1. `get_semantic_spans(data)` to map byte positions to meaningful regions
2. `mutate(data, hot_bytes=...)` so the mutator can bias edits toward those
   regions
3. a config file with the format's semantic rules and havoc priors

### Current behavior

For the built-in targets:

- IPv4 hot bytes bias Tier 2 toward the corresponding octet
- IPv6 hot bytes bias Tier 2 toward the corresponding group or nearby separator
- Cidrize hot bytes bias Tier 2 toward address tokens, CIDR prefixes, ranges, or wildcard regions depending on the current input shape
- Tier 3 biases `bit_flip`, `byte_substitute`, `arithmetic`, `delete_range`,
  `insert_random`, and `interesting_byte` toward hot byte positions when
  guidance is available
- if the model is not trusted, both tiers fall back to their existing static
  behavior

This is the main Neuzz-inspired extension in the codebase: use gradients to
focus mutation effort, but let structured mutators stay in control of the
actual edit.

---

## Execution Modes and Bug Classification

Binary targets now go through an oracle-assisted executor path:

- `QEMU`: Linux binary plus `afl-showmap -Q`, yielding real AFL++ edge coverage
- `Linux`: native Linux binary execution with fallback behavior hashing
- `Windows`: PyInstaller `.exe` execution with fallback behavior hashing

For the binary targets, bug types are derived from process state plus an
independent oracle:

- `validity`: the oracle says the input should be valid, but the parser rejects it
- `invalidity`: the oracle says the input should be invalid and the parser raises a `ParseException`
- `oracle_mismatch`: the oracle says the input should be invalid, but the parser accepts it
- `bonus`: unexpected exception on an oracle-invalid input
- `oracle_unknown_accept`: oracle does not support the shape, parser accepted it
- `oracle_unknown_reject`: oracle does not support the shape, parser rejected it
- `CRASH` / `TIMEOUT`: process failure or timeout

Current built-in oracles cover IPv4, IPv6, cidrize, and XML. The JSON target
uses a separate stdlib-JSON oracle inside the Atheris harness, while the XML
target uses `xml.etree.ElementTree` as its reference parser and compares it
against a stdlib `minidom` target parser inside the Atheris harness.

The binary-target oracle now records a parsed `shape` family and optional
`normalized` form for accepted inputs. For `cidrize`, the oracle classifies
documented families such as networks, full ranges, partial IPv4 ranges, and
IPv4 wildcard forms before validating them semantically, which reduces
overfitting to the current seed examples.

---

## Output

All results are written to `results/<target>/`:

| File | Contents |
|---|---|
| `bugs.jsonl` | One JSON record per interesting result, including the saved bug signature and captured output |
| `unique_bugs.json` | Deduplicated bug signatures with first-seen execution, oracle context, and one example input |
| `crashes/crash_NNNNNN.txt` | One file per crashing input |
| `queue/id_NNNNNN.txt` | Interesting inputs re-added to the corpus, with exec number and priority |
| `plot_data` | CSV progress samples over time (`relative_time_sec`, `total_execs`, `coverage_seen`, `coverage_percent`, `interesting_test_cases`, `corpus_size`, `unique_bugs`, `unique_crashes`) |
| `progress.svg` | Optional chart generated from `plot_data` with `evaluation/plot_progress.py` |
| `fuzzer_config` | JSON snapshot of the effective run configuration |
| `fuzzer_stats` | Duplicate of the end-of-run text summary for AFL/Neuzz-style tooling |
| `mutation_stats.json` | Learned payoff statistics for operators, fields, stages, and seed families |
| `dl_training.jsonl` | One JSON record per periodic/final DL training event |
| `dl_summary.json` | Final DL/checkpoint summary for the run, including proxy-target metadata |
| `stats.txt` | Final summary printed and saved at the end of each run, including corrected first-seen timings |

For the `json` and `xml` targets specifically:

- `atheris.log` stores the Atheris/libFuzzer session output
- `atheris_corpus/` stores the on-disk corpus used to seed and resume the run
- `crashes/` receives Atheris artifacts via `-artifact_prefix`

### Bug types

| Type | Meaning |
|---|---|
| `validity` | Valid input falsely rejected by the parser - real bug |
| `bonus` | Unexpected exception raised - real bug |
| `oracle_mismatch` | Oracle expected rejection, but the parser accepted the input - real bug |
| `invalidity` | Expected `ParseException` on an invalid input |
| `oracle_unknown_accept` / `oracle_unknown_reject` | Oracle cannot classify the shape; visible in logs, not counted as headline bugs |
| `CRASH` / `TIMEOUT` | Non-zero exit code or process exceeded the executor timeout for that mode |

### Console output

```text
[NEW]         execs=     3 behaviors=   4 corpus=  83 input=b'1:555S.5.'
[VALIDITY    ] execs=     4 input=b'255.255.255.255'
[INVALIDITY  ] execs=     5 input=b'999.0.0.1'
```

### Plotting run progress

To turn `plot_data` into a chart without installing extra packages:

```bash
python evaluation/plot_progress.py ipv4
python evaluation/plot_progress.py results/ipv4/plot_data --output results/ipv4/my_plot.svg
```

This writes an SVG dashboard with one panel per metric. Coverage is rendered as
percentage-over-time for easier comparisons, while the raw `coverage_seen`
count remains available in `plot_data`, `stats.txt`, and
`bug_coverage_summary.json`.

Read the panels like this:

- `coverage_seen`: your raw proxy coverage growth
- `coverage_percent`: percentage of the 65,536-slot bitmap covered so far
- `unique_bugs`: distinct saved bug signatures found so far
- `corpus_size`: how many interesting seeds entered the queue
- `unique_crashes`: distinct crash signatures, deduplicated by `(bug_type, exit_code, exception)`

For demo-friendly bug inspection, open `results/<target>/unique_bugs.json`.
It stores one entry per distinct saved bug signature along with
the first execution where it appeared and an example triggering input.

### Generating evaluation graphs

`plot_progress.py` writes two SVGs: `progress.svg` (coverage, bugs, corpus, crashes over time) and `eval_graphs.svg` (interesting test cases vs wall-clock time and vs total tests):

```bash
python evaluation/plot_progress.py ipv4
python evaluation/plot_progress.py ipv6
```

For older runs without an explicit `interesting_test_cases` column, `eval_graphs.svg` falls back to `corpus_size`.

### RQ2 timing metrics

`stats.txt` and `bug_coverage_summary.json` now include:

- `Avg gen/test`: average candidate generation time, excluding target execution
- `Avg run/test`: average target execution time only
- `Coverage percent`: raw coverage normalized against the 65,536-slot bitmap

These are collected separately inside the main fuzz loop, so they can be used
for the RQ2 efficiency table without relying on combined `execs/sec`.

### Aggregating report metrics

To produce report-ready summaries across completed runs:

```bash
python evaluation/report_metrics.py
python evaluation/report_metrics.py results savedruns --output-dir results/report
```

This writes:

- `results/report/report_metrics.json`: machine-readable RQ1-RQ4 summary grouped by target and evaluation mode
- `results/report/report_metrics.md`: concise Markdown summary for the report
- `results/report/curves/*.csv`: averaged curve data for `#unique crashes vs time`, `#interesting test cases vs time`, `#interesting test cases vs #tests`, and `coverage vs time`

The aggregator expects finished run directories containing `fuzzer_config`,
`bug_coverage_summary.json`, and `plot_data` (or Atheris-compatible logs). For
baseline and stability claims, collect at least five runs per target/mode and
then rerun the aggregator over those saved outputs.

---

## DL Model Checkpoints

When torch is installed and `hybrid_dl` is active, the fuzzer trains a neural surrogate model on inputs that trigger new behaviors. Checkpoints are saved to `models/`:

```text
models/ipv4_surrogate.pt
models/ipv6_surrogate.pt
models/cidrize_surrogate.pt
```

The checkpoint also stores optimizer state and lightweight scheduler metadata,
so the hybrid fallback state survives restarts. That means the scheduler
remembers whether the model is still in warm-up instead of assuming every new
run starts fully trusted.

Delete the `.pt` file to start fresh.

For a one-command reset, run with `--fresh-start`. That clears
`results/<target>/` and removes `models/<target>_surrogate.pt` before the
campaign begins.

---

## Ablation Configurations

To evaluate which components contribute to bug-finding, run with the explicit evaluation modes and compare `stats.txt` plus `fuzzer_config`:

| Config | How to run |
|---|---|
| Havoc only | `python main.py ipv4 --evaluation-mode havoc_only ...` |
| Semantic + Havoc | `python main.py ipv4 --evaluation-mode semantic_plus_havoc ...` |
| Static payoff | `python main.py ipv4 --evaluation-mode static_payoff ...` |
| Full hybrid DL | `python main.py ipv4 --evaluation-mode hybrid_dl ...` |

Recommended per-config run: `--time-budget 3600` (1 hour), repeated with different `--seed` values for variance.

---

## Evaluation Parameters to Test

| Parameter | Values to compare |
|---|---|
| `--havoc-iters` | `4`, `8`, `16`, `32` |
| `--seeds-n` | `50`, `100`, `200` |
| `target` | `ipv4` vs `ipv6` |
| Evaluation mode | `havoc_only`, `semantic_plus_havoc`, `static_payoff`, `hybrid_dl` |

Metrics to report per configuration: `validity_bugs`, `bonus_bugs`, `oracle_mismatches`, `behaviors_covered`, `time_to_first_real_bug`, `time_to_first_interesting_result`, and `total_executions`.
