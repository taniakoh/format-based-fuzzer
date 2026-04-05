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

- Use **early stopping** with a 10% validation split: halt retraining when validation loss has not improved for `p = 5` epochs
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
| Validation split | 10% held out | Early stopping signal; prevents overfitting on small corpora |

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

Define the following variants of the fuzzer, each differing from the full system in exactly one way:

| Variant ID | What is disabled | Purpose |
|------------|-----------------|---------|
| **Full** | — | Full system, all components enabled |
| **A1** | Format-aware mutation (tiers 1+2 disabled; raw bytes only) | Isolates value of format knowledge |
| **A2** | Neural surrogate scheduler disabled; uniform energy | Isolates value of DL energy scheduling |
| **A3** | Gradient-guided byte selection disabled; random byte selection | Isolates value of gradient signal for mutation |
| **A4** | Incremental retraining disabled; surrogate trained once on initial corpus only | Isolates value of online learning |
| **A5** | Cosine decay with restarts replaced by fixed LR `1e-4` | Isolates value of LR schedule |
| **A6** | Validation set removed; train until fixed epoch count | Isolates value of early stopping |
| **A7** | Oracle feedback to DL scheduler disabled; energy updated by coverage signal only | Isolates oracle's role in scheduling |

### 5.2 What Each Ablation Tells You

**A1 (no format awareness):** If coverage drops significantly on JSON and CIDR but not IPv4, format-awareness matters proportionally to structural complexity. This validates the three-tier mutation design.

**A2 (uniform energy):** If coverage drops, the DL scheduler is genuinely learning useful energy allocation beyond what uniform distribution would achieve. If coverage stays the same, the scheduler adds overhead without benefit.

**A3 (no gradient selection):** Compares gradient-guided byte selection against random byte selection with the same surrogate. A significant drop confirms that the gradient signal, not just the surrogate's existence, is responsible for gains.

**A4 (no incremental retraining):** Tests whether the surrogate needs to stay up-to-date. A significant drop means the online learning loop is essential; a small drop means the cold-start surrogate generalises well enough.

**A5 (fixed LR):** Validates whether the cosine decay schedule meaningfully helps surrogate accuracy under incremental retraining conditions.

**A6 (no early stopping):** Measures how much time is wasted on unnecessary training epochs without a validation signal, and whether this hurts overall coverage by reducing fuzzing time.

**A7 (oracle not feeding scheduler):** Isolates the specific feedback path from oracle → DL scheduler. If removing this path hurts coverage, it confirms the oracle's direct role in improving energy allocation beyond what coverage signal alone provides.

### 5.3 Ablation Experimental Protocol

- Run each variant on all four primary targets
- **5 independent runs** per variant (fewer than full benchmark; ablation needs trend, not exact significance)
- Same 24-hour time budget per run
- Report mean edge coverage at 24h and coverage-over-time curves
- Rank components by coverage contribution: `ΔCov(Full) − ΔCov(Aᵢ)`

### 5.4 Expected Results Table Format

| Variant | IPv4 cov. | IPv6 cov. | cidrize cov. | JSON cov. | Mean Δ vs Full |
|---------|-----------|-----------|--------------|-----------|----------------|
| Full    | —         | —         | —            | —         | 0%             |
| A1      |           |           |              |           |                |
| A2      |           |           |              |           |                |
| A3      |           |           |              |           |                |
| A4      |           |           |              |           |                |
| A5      |           |           |              |           |                |
| A6      |           |           |              |           |                |
| A7      |           |           |              |           |                |

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

1. **Coverage over time** — line plot per target, all fuzzers, mean ± 95% CI, 24h x-axis
2. **Final coverage bar chart** — grouped bar chart, all fuzzers × targets, with significance markers
3. **Ablation heatmap** — variants × targets, colour = ΔCov vs Full
4. **Surrogate accuracy over time** — misprediction rate vs. number of retraining events
5. **Energy distribution** — histogram of seed energies at hours 1, 6, 12, 24 for full system vs A2
6. **Training time budget** — stacked bar: time in fuzzing vs. time in NN training per run

### 7.3 Claims to Validate

Each of the following claims must be directly supported by experimental results:

| Claim | Supported by |
|-------|-------------|
| Format-aware mutation improves coverage on structured targets | A1 ablation + benchmark vs AFL |
| DL scheduler adds value over uniform energy | A2 ablation |
| Gradient-guided selection outperforms random selection | A3 ablation |
| Our fuzzer outperforms NEUZZ on JSON target | Benchmark metric table |
| Incremental retraining is necessary for sustained coverage | A4 ablation, coverage-over-time plot |
| Oracle feedback to scheduler meaningfully improves coverage | A7 ablation |

---

*Document version 1.0 — to be updated after pilot run results.*