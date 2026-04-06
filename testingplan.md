# Format-Based Fuzzer: Implementation & Evaluation Plan

> **Project:** Coverage-guided format-based fuzzer with neural surrogate scheduler  
> **Targets:** IPv4, IPv6, cidrize, JSON decoder  
> **Document scope:** Optimisation, training, benchmarking, and ablation study requirements

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Optimisation Requirements](#2-optimisation-requirements)
3. [Training Requirements](#3-training-requirements)
4. [Benchmarking Plan](#4-benchmarking-plan)
5. [Ablation Study](#5-ablation-study)
6. [Experimental Setup](#6-experimental-setup)
7. [Reporting Requirements](#7-reporting-requirements)

---

## 1. System Overview

The fuzzer under evaluation is a **three-tier coverage-guided fuzzer** combining:

- A **format-aware mutation engine** that understands IPv4/IPv6/CIDR/JSON structure
- A **neural surrogate scheduler** (FFNN/MLP) that predicts coverage from inputs and uses gradient information to allocate mutation energy
- An **oracle** (crash + coverage) that labels each execution and feeds back into both the surrogate retraining loop and the DL scheduler's energy weights
- **Coverage tracking** via AFL-style edge bitmaps

The goal of the evaluation plan is to answer four research questions:

| RQ | Question |
|----|----------|
| RQ1 | Which optimisation choices most improve fuzzer throughput and edge coverage? |
| RQ2 | How should the surrogate be trained for best generalisation across inputs? |
| RQ3 | Does the fuzzer outperform comparable state-of-the-art tools on the chosen targets? |
| RQ4 | Which individual components are responsible for the performance gains? |

---

## 2. Optimisation Requirements

### 2.1 Mutation Engine Optimisations

**Goal:** Maximise the number of useful candidate inputs generated per unit time.

#### 2.1.1 Gradient-guided byte selection

- Implement sign-based gradient stepping (`+δ` or `−δ` per byte, not full gradient magnitude) to avoid byte overflow and keep steps bounded within `[0, 255]`
- Use a **sliding window** over high-gradient byte positions to handle multi-byte constraints (e.g., magic numbers, length fields)
- Tune window width `w ∈ {4, 8, 16, 32}` bytes and record which performs best per target format

#### 2.1.2 Format-aware mutation layers

Define three mutation tiers applied in sequence:

| Tier | Description | Example |
|------|-------------|---------|
| Structural | Mutate format fields respecting schema | IPv4 octet swap, JSON key rename |
| Boundary | Push field values to valid/invalid boundaries | 255.255.255.255, empty string `""` |
| Raw | Byte-level gradient-guided perturbation | High-∂ byte flip/increment |

Each tier should be togglable independently for ablation (Section 5).

#### 2.1.3 Energy scheduling

The DL scheduler assigns a mutation energy `e(s)` to each seed `s`, controlling how many candidate inputs are generated from it per cycle. Optimisation requirements:

- Energy initialised uniformly; updated after each oracle observation
- Increase energy for seeds that produced new coverage in the last `k` cycles
- Decrease energy for seeds that have been exhausted (no new coverage for `n` consecutive cycles)
- Tune `k ∈ {3, 5, 10}` and `n ∈ {10, 20, 50}` as hyperparameters
- Log energy distribution per cycle to diagnose stagnation

#### 2.1.4 Corpus management

- Keep corpus size bounded: evict seeds with lowest energy when corpus exceeds `C_max`
- Prefer seeds that cover rare edges (AFL-style frequency weighting)
- Deduplicate by edge coverage bitmap hash before adding to corpus

### 2.2 Surrogate NN Optimisations

**Goal:** Maximise surrogate accuracy while minimising time spent in training (leaving more budget for execution).

- Use **Adam optimiser** with learning rate `1e-4` and **cosine decay with warm restarts** (cycle length `T_0 = 50` steps, multiplier `T_mult = 2`)
- Retrain only when misprediction rate on recent inputs exceeds a threshold `τ ∈ {0.1, 0.2, 0.3}` — avoid unnecessary retrains
- Profile wall-clock time split between (a) fuzzing execution and (b) NN training per run; target >80% time in (a)

### 2.3 Oracle Integration Optimisations

- Run oracle check (coverage bitmap diff + crash/signal detection) in the same process call as target execution — do not add a separate IPC round trip
- Cache edge bitmap for seeds already in corpus; only diff against new candidates
- Log oracle verdict latency per execution; flag if >5ms per call

---

## 3. Training Requirements

### 3.1 Surrogate Model Specification

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Architecture | MLP, 1 hidden layer | Validated by NEUZZ and PreFuzz; deeper nets do not improve coverage |
| Hidden units | 4096 | Matches NEUZZ baseline for fair comparison |
| Input | Byte array (padded/truncated to fixed length `L`) | One neuron per input byte |
| Output | Edge activation vector (binary per edge) | One output per CFG edge in target |
| Loss | Binary cross-entropy per edge | Multi-label classification |
| Optimiser | Adam, lr = 1e-4 | Adaptive per-parameter LR; faster convergence than SGD |
| LR schedule | Cosine decay with restarts | Escapes local minima during incremental retraining |

### 3.2 Input Representation

- Pad all inputs to a fixed maximum length `L` (set per target format):
  - IPv4: `L = 16` bytes
  - IPv6: `L = 40` bytes
  - CIDR: `L = 44` bytes
  - JSON decoder: `L = 512` bytes
- Use zero-padding; record actual length as an additional feature if helpful
- Normalise byte values to `[0, 1]` by dividing by 255

### 3.3 Training Data Collection

**Phase 1 — Cold start corpus:**
- Seed with 100–500 hand-crafted valid inputs per target format
- Run target with each seed and record edge bitmap → initial training set

**Phase 2 — Incremental retraining:**
- After every `B = 50` new executions, compute misprediction rate on recent inputs
- If misprediction rate > `τ`, trigger retraining on the full accumulated corpus
- Cap corpus size at `C_max = 10,000` inputs to bound memory and training time

> **Deviation from NEUZZ:** NEUZZ uses a static 5:1 train/test split on an AFL-generated corpus (~2K inputs) to detect overfitting before deployment. This is not applicable here for two reasons: (1) the opaque PyInstaller binaries cannot be instrumented with AFL, so the corpus grows incrementally at ~2 new behaviors per hour rather than starting from 2K; a 5:1 split on 10–20 samples would reduce the training set below useful size. (2) The rolling `misprediction_rate` metric — computed on the `B` most recent inputs immediately before each retrain event — serves as an equivalent overfitting signal for the incremental setting.

**Phase 3 — Convergence criteria:**
- Training is considered converged when validation loss improvement < `1e-4` for 5 consecutive epochs
- Record number of retraining events, average retraining time, and misprediction rate trajectory

### 3.4 Gradient Computation Verification

Before using gradients for mutation, verify correctness:

- For a held-out input `x`, perturb byte `i` by `+δ` and measure actual coverage change
- Verify that the sign of `∂output/∂x[i]` matches the direction of coverage increase
- Report **gradient sign accuracy** (fraction of bytes where sign matches oracle direction) as a training quality metric
- Target gradient sign accuracy > 70% on the validation set

---

## 4. Benchmarking Plan

### 4.1 Benchmark Targets

All experiments run on the four primary targets. Each target is chosen because it represents a distinct format class with different structural complexity:

| Target | Format class | Structural complexity | Why included |
|--------|-------------|----------------------|--------------|
| IPv4 parser | Fixed-length dotted-decimal | Low | Simple baseline; validates basic mutation |
| IPv6 parser | Variable-length hex-colon | Medium | Multi-representation (compressed, full) |
| cidrize | Compound (IP + prefix) | Medium | Tests multi-field dependency |
| JSON decoder | Recursive, nested | High | Deep structural constraints; hardest target |

Additionally, use the **LAVA-M bug dataset** as a standardised bug-finding benchmark (same as NEUZZ evaluation), specifically the `who`, `base64`, `md5sum`, and `uniq` binaries.

### 4.2 Baseline Fuzzers

The following tools are chosen as baselines, each representing a distinct point in the design space:

#### AFL (v2.57b)
**Why:** The de facto evolutionary fuzzing baseline. Represents the pure random-mutation upper bound. All results should be reported relative to AFL coverage as a normalisation baseline (AFL = 100%).

**Setup:** Standard AFL with LLVM instrumentation (`afl-clang-fast`), default power schedule, no dictionary.

#### AFLFast
**Why:** Represents the best evolutionary-only approach with smarter seed scheduling (Markov chain power schedule). Tests whether our DL scheduler adds value beyond classical scheduling improvements.

**Setup:** Same instrumentation as AFL; use `--schedule=fast`.

#### NEUZZ
**Why:** The closest methodological predecessor — gradient-guided mutation with a neural surrogate. The primary comparison point for our neural scheduler contribution. Any gain over NEUZZ isolates the value of format-awareness and the DL energy scheduler specifically.

**Setup:** Original NEUZZ codebase; train surrogate on same initial corpus as our fuzzer; same 4096-neuron MLP. Run with default settings as per the paper.

**Expected limitation:** NEUZZ uses no format knowledge; byte-level gradient guidance alone may miss multi-byte structural constraints in JSON and CIDR.

#### MLFuzz / PreFuzz (if available)
**Why:** Represents the most recent NPS-guided fuzzing work. Tests whether our format-aware approach improves over the current state of the art in the NPS family.

**Setup:** Use published configuration; same target binaries.

**Note:** If MLFuzz/PreFuzz source is unavailable or requires proprietary infrastructure, document this explicitly and replace with **ANGORA** (gradient-guided without smoothing) as an alternative data point.

#### libFuzzer (coverage-guided, no NN)
**Why:** Represents the state of the art in production coverage-guided fuzzing without ML. Tests whether the NN adds value over a highly optimised evolutionary baseline.

**Setup:** Compile targets with `-fsanitize=fuzzer`; use default corpus; enable ASan.

### 4.3 Metrics

Collect the following metrics for all fuzzers across all targets:

| Metric | Description | Collection method |
|--------|-------------|-------------------|
| Edge coverage | Number of unique CFG edges covered | AFL bitmap at end of run |
| Coverage over time | Edge coverage at 1h, 6h, 12h, 24h checkpoints | Logged every 60s |
| Bugs found | Number of unique crash signatures (deduplicated by stack hash) | AFL crash triage + AddressSanitizer |
| Unique bugs | Bugs not found by any other fuzzer in the comparison | Manual deduplication post-run |
| Executions/sec (execs/s) | Throughput of the fuzzing loop | AFL `fuzzer_stats` |
| Time to first crash | Wall-clock time to first unique crash | Logged per run |
| Corpus size over time | Number of seeds in corpus at each checkpoint | Logged every 60s |
| NN training time | Total wall-clock time spent in surrogate retraining | Internal profiler |
| Misprediction rate | Fraction of inputs where surrogate mispredicts coverage | Logged per retrain event |

### 4.4 Statistical Validity

Fuzzing results have high variance. To ensure statistical validity:

- Run each fuzzer × target combination **10 independent times** with different random seeds
- Report **mean ± standard deviation** for all metrics
- Use the **Mann-Whitney U test** (non-parametric, no normality assumption) to test significance of pairwise differences; report p-values
- Report **Vargha-Delaney A₁₂ effect size** for coverage comparisons
- Draw **coverage over time** plots with shaded 95% confidence intervals across 10 runs

### 4.5 Time Budget

Each fuzzer run is **24 hours** of wall-clock fuzzing time, matching the NEUZZ paper evaluation. For LAVA-M, use **6 hours** (standard in the literature).

---

## 5. Ablation Study

The ablation study answers RQ4: which components individually contribute to performance? Each ablation removes or disables one component and measures the resulting coverage drop.

### 5.1 Ablation Variants

All variants are implemented. Run each with `--fresh-start --time-budget 86400 --seed <N>`.

| Variant ID | What is disabled | Purpose | CLI flags |
|------------|-----------------|---------|-----------|
| **Full** | — | Full system, all components enabled | `--evaluation-mode hybrid_dl` |
| **A1** | Format-aware mutation (tiers 1+2 disabled; raw bytes only) | Isolates value of format knowledge | `--evaluation-mode havoc_only` |
| **A2** | Neural surrogate scheduler disabled; uniform energy | Isolates value of DL energy scheduling | `--evaluation-mode static_payoff` |
| **A3** | Gradient-guided byte selection disabled; random byte selection | Isolates value of gradient signal for mutation | `--evaluation-mode hybrid_dl --no-gradient-guidance` |
| **A4** | Incremental retraining disabled; surrogate trained once on initial corpus only | Isolates value of online learning | `--evaluation-mode hybrid_dl --no-retrain` |
| **A5** | Cosine decay with restarts replaced by fixed LR `1e-3` | Isolates value of LR schedule | `--evaluation-mode hybrid_dl --fixed-lr` |

### 5.2 What Each Ablation Tells You

**A1 (no format awareness):** If coverage drops significantly on JSON and CIDR but not IPv4, format-awareness matters proportionally to structural complexity. This validates the three-tier mutation design.

**A2 (uniform energy):** If coverage drops, the DL scheduler is genuinely learning useful energy allocation beyond what uniform distribution would achieve. If coverage stays the same, the scheduler adds overhead without benefit.

**A3 (no gradient selection):** Compares gradient-guided byte selection against random byte selection with the same surrogate. A significant drop confirms that the gradient signal, not just the surrogate's existence, is responsible for gains.

**A4 (no incremental retraining):** Tests whether the surrogate needs to stay up-to-date. A significant drop means the online learning loop is essential; a small drop means the cold-start surrogate generalises well enough.

**A5 (fixed LR):** Validates whether the cosine decay schedule meaningfully helps surrogate accuracy under incremental retraining conditions. Fixed LR used is `1e-3` (the Adam base rate in trainer.py).

### 5.3 Ablation Experimental Protocol

**Step 0 — Pilot check.** Confirm the full system runs end-to-end before committing to long runs:
```bash
python main.py ipv4 --evaluation-mode hybrid_dl --fresh-start --time-budget 600 --seed 1
```
Check that `results/ipv4/energy_log.csv`, `oracle_log.csv`, and `dl_training.jsonl` are produced and non-empty.

**Step 1 — Run each variant.** For each combination of variant × target × seed (1..5), run:
```bash
python main.py <target> <flags> --fresh-start --time-budget 86400 --seed <N>
```
then immediately archive the results before the next run overwrites them:
```bash
# Windows
xcopy /E /I results\<target> ablation_results\<variant_id>\<target>\run<N>

# Unix
cp -r results/<target> ablation_results/<variant_id>/<target>/run<N>
```

Targets for binary variants (Full, A1–A5): `ipv4`, `ipv6`, `cidrize`.
The `json` target uses the Atheris harness and has no DL scheduler — only A1 (`havoc_only`) is meaningful for it.

**Step 2 — Collect metrics.** After all runs, for each variant × target combination:
- Load `ablation_results/<variant>/<target>/run*/plot_data` (CSV)
- Compute mean ± SD of `behaviors_seen` at the 24h mark across the 5 runs
- Compute mean ± SD of `misprediction_rate` from `dl_training.jsonl` (Full, A3, A4, A5 only)

**Step 3 — Fill the results table** (Section 5.4) and rank components by `ΔCov(Full) − ΔCov(Aᵢ)`.

**Step 4 — Plot.** Use `python evaluation/plot_progress.py <target>` for per-run curves.

**Results directory convention:**
```
ablation_results/
  Full/ipv4/run1/    ← copy of results/ipv4/ after each run
  Full/ipv4/run2/
  ...
  A1/ipv4/run1/
  ...
```

**Compute budget note.** Each run = 24 h. Sequential execution: 5 runs × 6 variants × 3 targets = **90 runs = 2160 h**. The binaries take ~20–30 s per execution (PyInstaller bundles), so each 24 h run yields only ~2880–4320 total executions. To make the study feasible:
- Run variants in parallel across machines/processes if available, or
- Reduce to **3 runs per variant** (sufficient to detect large effects at this execution count), or
- Use a **6 h time budget** for ablation runs and note the deviation from the full benchmark protocol.

### 5.4 Metrics to Compare Across Variants

Not all metrics are meaningful for all variants. Use the table below to decide what to collect and compare per variant.

| Metric | Source file | Full | A1 | A2 | A3 | A4 | A5 |
|--------|------------|:----:|:--:|:--:|:--:|:--:|:--:|
| `behaviors_seen` at end of run | `plot_data` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `behaviors_seen` over time (curve) | `plot_data` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `unique_bugs` (real bugs found) | `bug_coverage_summary.json` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pass_rate` (clean parses / total execs) | `stats.txt` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `execs/sec` (throughput) | `stats.txt` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `corpus_size` over time | `plot_data` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `misprediction_rate` per training round | `dl_training.jsonl` | ✓ | — | — | ✓ | ✓ | ✓ |
| `loss` per training round | `dl_training.jsonl` | ✓ | — | — | ✓ | ✓ | ✓ |
| Training time per round (`duration_sec`) | `dl_training.jsonl` | ✓ | — | — | ✓ | ✓ | ✓ |
| Seed energy distribution | `energy_log.csv` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**What each comparison isolates:**

| Comparison | Primary metric | Secondary metric | What a drop means |
|------------|---------------|-----------------|-------------------|
| Full vs A1 | `behaviors_seen` | `unique_bugs` | Format-aware mutation adds coverage |
| Full vs A2 | `behaviors_seen` | `energy` distribution | DL energy scheduling adds value |
| Full vs A3 | `behaviors_seen` | `misprediction_rate` | Gradient guidance adds value beyond the surrogate alone |
| Full vs A4 | `behaviors_seen` over time | `misprediction_rate` trajectory | Surrogate needs to stay up-to-date |
| Full vs A5 | `loss` trajectory | `behaviors_seen` | Cosine decay helps surrogate learn better |

### 5.5 Primary Results Table (fill after runs)

Report mean `behaviors_seen` at end of run ± SD across 3 runs. ΔCov = Full − Aᵢ.

| Variant | IPv4 | IPv6 | cidrize | Mean Δ vs Full |
|---------|------|------|---------|----------------|
| Full    | — ± — | — ± — | — ± — | 0 |
| A1      | | | | |
| A2      | | | | |
| A3      | | | | |
| A4      | | | | |
| A5      | | | | |

### 5.6 Secondary Results Table (fill after runs)

| Variant | Unique real bugs | Pass rate | Execs/sec | Training rounds |
|---------|-----------------|-----------|-----------|-----------------|
| Full    | | | | |
| A1      | | | n/a | n/a |
| A2      | | | n/a | n/a |
| A3      | | | | |
| A4      | | | | 0 (disabled) |
| A5      | | | | |

### 5.7 Plots to Produce for Ablation

| # | Plot | Data source | Variants |
|---|------|------------|---------|
| 1 | Coverage over time — line plot per target, mean ± SD shaded, all 6 variants | `plot_data` (`relative_time_sec`, `behaviors_seen`) | All |
| 2 | Final coverage bar chart — grouped by target, one bar per variant | `plot_data` last row | All |
| 3 | Ablation heatmap — rows = variants, cols = targets, colour = ΔCov vs Full | Derived from Table 5.5 | All |
| 4 | Misprediction rate over training rounds | `dl_training.jsonl` (`round`, `misprediction_rate`) | Full, A3, A4, A5 |
| 5 | Training loss over rounds | `dl_training.jsonl` (`round`, `loss`) | Full, A4, A5 |
| 6 | Energy distribution at run end — histogram of `energy` values | `energy_log.csv` | Full vs A2 |
| 7 | Training time overhead — stacked bar: fuzzing time vs total `duration_sec` | `dl_training.jsonl` | Full, A3, A4, A5 |
| 8 | Pass rate bar chart — fraction of executions that parsed cleanly | `stats.txt` | All |

---

## 6. Experimental Setup

### 6.1 Hardware

All experiments must be run on the **same machine** to ensure fair comparison. Record and report:

| Item | Specification |
|------|--------------|
| CPU | Model, core count, clock speed |
| RAM | Total GB |
| OS | Linux distribution, kernel version |
| Python | Version (e.g., 3.10.x) |
| PyTorch | Version (surrogate training) |
| AFL version | e.g., 2.57b |
| Compiler | clang version (for instrumentation) |
| LLVM | Version |

Recommended minimum: 8-core CPU, 32 GB RAM, Ubuntu 22.04, dedicated run (no other workloads during experiments).

### 6.2 Target Compilation

Compile all targets twice:

- **With AFL instrumentation** (`afl-clang-fast -fsanitize=address`) for fuzzing
- **Without instrumentation** (standard `clang`) for surrogate training throughput measurement

Disable ASLR during runs for reproducibility:
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Set CPU frequency to performance mode:
```bash
sudo cpupower frequency-set -g performance
```

### 6.3 Reproduciblity

- Fix random seeds for all Python/NumPy/PyTorch operations per run; log the seed used
- Use Docker or a virtual environment to pin all dependency versions
- Archive the exact binary of each target used in experiments
- All scripts, configs, and hyperparameters must be committed to version control before experiments begin

### 6.4 Fuzzing Harness Requirements

Each target must be wrapped in a harness that:

- Accepts input via stdin or a file path (AFL standard)
- Exits with code 0 on clean parse, non-zero on error
- Does not buffer stdout/stderr (use `fflush`)
- Has a defined maximum input length `L` per format (see Section 3.2)
- Is compiled with AddressSanitizer (`-fsanitize=address`) to catch silent memory errors that would otherwise be missed by the crash oracle alone

---

## 7. Reporting Requirements

### 7.1 Per-experiment Log Files

Every run must produce:

```
run_{fuzzer}_{target}_{seed}/
  fuzzer_stats          # AFL stats file (execs/s, corpus size, etc.)
  coverage_log.csv      # timestamp, edge_count, corpus_size (logged every 60s)
  crashes/              # deduplicated crash inputs
  training_log.csv      # retrain_event, misprediction_rate, val_loss, train_time_s
  energy_log.csv        # timestamp, seed_id, energy (logged every cycle)
  oracle_log.csv        # timestamp, input_hash, coverage_label, bug_label, latency_ms
```

### 7.2 Figures to Produce

**Benchmarking figures (Section 4 — comparing against baselines):**

1. **Coverage over time** — line plot per target, all fuzzers, mean ± SD, 6h x-axis. Data: `plot_data` columns `relative_time_sec`, `behaviors_seen`.
2. **Final coverage bar chart** — grouped bar chart, all fuzzers × targets. Data: final `behaviors_seen` from each run's `plot_data`.
3. **Bugs found table** — count of unique real bugs (`validity` + `CRASH` + `oracle_mismatch` + `bonus`) per fuzzer × target. Data: `bug_coverage_summary.json` → `unique_real_bugs`.

**Ablation figures (Section 5 — comparing variants):**

4. **Ablation coverage over time** — one plot per target, one line per variant (Full, A1–A5), mean ± SD shaded. Same data source as Figure 1.
5. **Ablation heatmap** — rows = A1–A5, columns = targets, cell colour = ΔCov(Full) − ΔCov(Aᵢ). Summarises Table 5.5 visually.
6. **Misprediction rate over training rounds** — line plot, one line per variant (Full, A3, A4, A5). Data: `dl_training.jsonl` fields `round`, `misprediction_rate`.
7. **Training loss over rounds** — line plot (Full, A4, A5). Data: `dl_training.jsonl` fields `round`, `loss`.
8. **Energy distribution** — histogram of `energy` values from `energy_log.csv` for Full vs A2, plotted at the run's end.
9. **Training time overhead** — stacked bar per variant (Full, A3, A4, A5): total fuzzing time vs sum of `duration_sec` from `dl_training.jsonl`.
10. **Pass rate bar chart** — one bar per variant, showing `pass_count / total_executions` from `stats.txt`. Diagnoses whether mutations are preserving valid structure.

### 7.3 Claims to Validate

Each of the following claims must be directly supported by experimental results:

| Claim | Supported by |
|-------|-------------|
| Format-aware mutation improves coverage on structured targets | A1 ablation + benchmark vs AFL |
| DL scheduler adds value over uniform energy | A2 ablation |
| Gradient-guided selection outperforms random selection | A3 ablation |
| Our fuzzer outperforms NEUZZ on JSON target | Benchmark metric table |
| Incremental retraining is necessary for sustained coverage | A4 ablation, coverage-over-time plot |

---

*Document version 1.0 — to be updated after pilot run results.*