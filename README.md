# Hybrid Coverage-Guided Fuzzer

A format-aware fuzzer targeting IPv4, IPv6, cidrize, and a bundled JSON decoder.
For binary targets, the executor now supports three runtime modes: Windows
behavior hashing, Linux behavior hashing, and AFL++ QEMU edge coverage when
`afl-showmap` is available.

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

> Without torch installed, or when `--no-dl` is used, the binary targets run with the static/payoff-tracking scheduler only.

### Linux edge coverage with AFL++ QEMU - optional

On Linux, if the target has a registered `binary_linux` path and `afl-showmap`
is installed, the executor switches to `QEMU` mode automatically and records a
real 65,536-byte AFL++ edge bitmap instead of the fallback behavior hash.

If `afl-showmap` is not installed, Linux still runs natively, but coverage
falls back to the same behavior-hash model used on Windows.

### JSON target requirements

The `json` target uses [Atheris](https://github.com/google/atheris) for instrumentation.

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
| `target` | `ipv4`, `ipv6`, `cidrize`, `json`, `all` | Which parser to fuzz (`all` runs the binary parser targets sequentially) |
| `--havoc-iters N` | int (default: `8`) | Byte-level mutations applied per execution |
| `--time-budget S` | int (default: `86400`) | Total fuzzing time in seconds |
| `--seed RNG` | int (default: `42`) | RNG seed for reproducibility |
| `--seeds-n N` | int (default: `100`) | Initial corpus size loaded at startup |
| `--no-dl` | flag | Force the static scheduler even if torch is installed |
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

# Fuzz the bundled JSON decoder with Atheris for 10 minutes
python main.py json --time-budget 600

# Fuzz the binary parser targets (`ipv4`, `ipv6`, `cidrize`) sequentially
python main.py all --time-budget 86400

# Reproducible run
python main.py ipv4 --time-budget 3600 --seed 123

# Force static mode even if torch is installed
python main.py ipv4 --time-budget 3600 --no-dl

# Start from a clean slate
python3 main.py ipv4 --time-budget 100 --fresh-start


```

> On Linux, `afl-showmap` enables `QEMU` mode with real edge coverage. Without
> it, Linux uses the faster fallback `Linux` mode with behavior hashing and a
> 30-second timeout.

> On Windows, the parser bundles are PyInstaller one-file executables. Each
> execution can take about 20-30 seconds to unpack, so expect much lower exec/s
> than on Linux.

> The `json` target is different: it launches an Atheris/libFuzzer campaign in `results/json/` and lets Atheris manage corpus growth and coverage guidance directly.

---

## Hybrid Static + DL Scheduling

The scheduler now treats static behavior as a first-class policy, not a one-time bootstrap. This is deliberate and follows the same conservative lesson emphasized by Neuzz++: when the learned model is noisy, sparse, or temporarily misleading, the fuzzer should reduce learned influence instead of committing to it.

That matters especially in this repository because:

- coverage is hashed parser behavior, not true edge coverage
- the parser binaries are opaque
- executions are slow, so training data arrives slowly
- the model can overfit a small set of observed behaviors

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
- `bonus`: unexpected exception on an oracle-invalid or oracle-unsupported input
- `CRASH` / `TIMEOUT`: process failure or timeout

Current built-in oracles cover IPv4, IPv6, and cidrize. The JSON target uses a
separate stdlib-JSON oracle inside the Atheris harness.

---

## Output

All results are written to `results/<target>/`:

| File | Contents |
|---|---|
| `bugs.jsonl` | One JSON record per interesting result, including the saved bug signature and captured output |
| `unique_bugs.json` | Deduplicated bug signatures with first-seen execution, oracle context, and one example input |
| `crashes/crash_NNNNNN.txt` | One file per crashing input |
| `queue/id_NNNNNN.txt` | Interesting inputs re-added to the corpus, with exec number and priority |
| `plot_data` | CSV progress samples over time (`relative_time_sec`, `total_execs`, `behaviors_seen`, `corpus_size`, `unique_bugs`, `unique_crashes`) |
| `progress.svg` | Optional chart generated from `plot_data` with `evaluation/plot_progress.py` |
| `fuzzer_config` | JSON snapshot of the effective run configuration |
| `fuzzer_stats` | Duplicate of the end-of-run text summary for AFL/Neuzz-style tooling |
| `mutation_stats.json` | Learned payoff statistics for operators, fields, stages, and seed families |
| `dl_training.jsonl` | One JSON record per periodic/final DL training event |
| `dl_summary.json` | Final DL/checkpoint summary for the run |
| `stats.txt` | Final summary printed and saved at the end of each run |

For the `json` target specifically:

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

This writes an SVG dashboard with one panel per metric, using raw values over
time so plateaus are easier to spot than in a normalized single-line overlay.

Read the panels like this:

- `behaviors_seen`: your proxy coverage growth
- `unique_bugs`: distinct saved bug signatures found so far
- `corpus_size`: how many interesting seeds entered the queue
- `unique_crashes`: distinct crash signatures, deduplicated by `(bug_type, exit_code, exception)`

For demo-friendly bug inspection, open `results/<target>/unique_bugs.json`.
It stores one entry per distinct saved bug signature along with
the first execution where it appeared and an example triggering input.

---

## DL Model Checkpoints

When torch is installed and DL is not disabled, the fuzzer trains a neural surrogate model on inputs that trigger new behaviors. Checkpoints are saved to `models/`:

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

To evaluate which components contribute to bug-finding, run with the following setups and compare `stats.txt`:

| Config | How to run |
|---|---|
| Baseline (havoc only, no torch) | Uninstall torch, run normally |
| + Semantic mutations | Install torch, run normally while relying on static priors |
| Full Hybrid (+ DL scheduler) | Install torch, run normally and let the hybrid policy decide how much guidance to trust |

Recommended per-config run: `--time-budget 3600` (1 hour), repeated with different `--seed` values for variance.

---

## Evaluation Parameters to Test

| Parameter | Values to compare |
|---|---|
| `--havoc-iters` | `4`, `8`, `16`, `32` |
| `--seeds-n` | `50`, `100`, `200` |
| `target` | `ipv4` vs `ipv6` |
| Scheduler | Static-only vs hybrid static+DL |

Metrics to report per configuration: `validity_bugs`, `bonus_bugs`, `behaviors_covered`, `time_to_first_bug`, `total_executions`.
