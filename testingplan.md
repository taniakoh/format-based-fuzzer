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

**Phase 0 — Bootstrap decision:**
- Do **not** require a separate offline pretraining run for the normal `hybrid_dl` benchmark. The current implementation already performs an online warm-up: retraining is triggered every `TRAIN_EVERY = 10` newly interesting behaviors, and the scheduler stays mostly static until it has seen at least 20 samples and 2 training rounds.
- Do require a **bootstrap checkpoint** for the frozen-model ablation (**A4**) only. In the current code, `--no-retrain` disables the periodic and final retraining path; if `--fresh-start` also removes the checkpoint, A4 would measure a cold, effectively untrained model rather than a "train once, then freeze" model.

**Phase 1 — Cold start corpus:**
- Seed each target with the existing hand-crafted corpus (`--seeds-n 100` by default) rather than waiting to accumulate a large AFL-style offline dataset.
- Start fuzzing immediately from that corpus and let the online training loop collect the initial `(input, behavior)` pairs from genuinely interesting executions.

**Phase 2 — Online warm-up and incremental retraining:**
- For normal `hybrid_dl` and `A5` runs, treat the first two retraining rounds as a warm-up period; guided mutation should not be considered "active" until the scheduler exits its `undertrained_*` fallback states.
- Record the first timestamp at which the scheduler becomes eligible for guided mutation (`training_samples_seen >= 20` and `training_rounds >= 2`) and report it as the model's activation point.
- Keep retraining on the accumulated interesting-behavior buffer, but gate interpretation using the logged `misprediction_rate` and `duration_sec` so training overhead and learning quality are both visible.

**Phase 3 — Validation strategy:**
- For opaque binary targets (IPv4, IPv6, cidrize), prefer a rolling hold-out based on the most recent interesting inputs instead of NEUZZ's static 5:1 split. The dataset arrives too slowly for a large up-front split to be statistically useful.
- For shared-source baselines where AFL-style corpus generation is feasible (`cJSON`, `LAVA-M`), retain NEUZZ-compatible reporting: one hour of AFL warm-up to build the initial corpus, then use the same initial corpus for all fuzzers in the comparison.
- Add a small fixed validation slice for each retrain event when enough data exists (target: latest 10-20% of the interesting-behavior buffer, minimum 10 samples) and log both training loss and hold-out loss. This follows the NEUZZ++ recommendation that ML-specific metrics be evaluated on data distinct from the training set.

> **Approach taken from NEUZZ / NEUZZ++:** NEUZZ bootstraps from an AFL-generated corpus of about 2K inputs and splits it 5:1 into train/test before 24-hour campaigns. We should keep that setup only for the shared-source comparison targets (`cJSON`, `LAVA-M`), where it is reproducible. For the assignment's slow opaque binaries, follow the implementation's online design instead: start fuzzing immediately, warm up conservatively, and validate each retrain event on a rolling hold-out. This preserves the spirit of NEUZZ's incremental learning while adopting NEUZZ++'s stronger ML-evaluation discipline.

**Phase 4 — Convergence criteria:**
- Training is considered operationally mature when the scheduler has exited warm-up and the rolling hold-out loss or `misprediction_rate` no longer improves materially across consecutive retrain events.
- Record number of retraining events, average retraining time, activation time, hold-out loss trajectory, and misprediction rate trajectory.

### 3.4 Gradient Computation Verification

Before using gradients for mutation, verify correctness:

- For a held-out input `x`, perturb byte `i` by `+δ` and measure actual coverage change
- Verify that the sign of `∂output/∂x[i]` matches the direction of coverage increase
- Report **gradient sign accuracy** (fraction of bytes where sign matches oracle direction) as a training quality metric
- Target gradient sign accuracy > 70% on the validation set

---

## 4. Benchmarking Plan

### 4.1 Benchmark Targets

All experiments run on the four primary targets plus one external C target. Each target is chosen because it represents a distinct format class with different structural complexity:

| Target | Format class | Structural complexity | Why included |
|--------|-------------|----------------------|--------------|
| IPv4 parser | Fixed-length dotted-decimal | Low | Simple baseline; validates basic mutation |
| IPv6 parser | Variable-length hex-colon | Medium | Multi-representation (compressed, full) |
| cidrize | Compound (IP + prefix) | Medium | Tests multi-field dependency |
| JSON decoder (Python) | Recursive, nested | High | Deep structural constraints; hardest target |
| **cJSON** (C library) | Recursive, nested | High | External C target; shared greybox benchmark with AFL++ and NEUZZ |

**cJSON** (`github.com/DaveGamble/cJSON`) is a widely-used single-file C JSON parser. It is compiled as a plain binary (no source instrumentation) and fuzzed by all tools under identical QEMU-based edge coverage, ensuring a fair apples-to-apples greybox comparison. This target also demonstrates that the fuzzer generalises beyond the assignment's original Python targets.

Additionally, use the **LAVA-M bug dataset** as a standardised bug-finding benchmark (same as NEUZZ evaluation), specifically the `who`, `base64`, `md5sum`, and `uniq` binaries.

### 4.2 Baseline Fuzzers

The following tools are chosen as baselines, each representing a distinct point in the design space:

> **Coverage mechanism decision:** All greybox fuzzers (AFL++, AFLFast, NEUZZ, ours) run against **plain uninstrumented binaries** under **QEMU-based edge coverage** (`afl-fuzz -Q`). This ensures all tools use an identical coverage signal, isolating mutation strategy as the only variable. Source instrumentation (LLVM/`afl-clang-fast`) is deliberately avoided for the primary greybox comparison because it would give AFL++ a coverage quality advantage unrelated to mutation strategy. The cjson target is compiled once as a plain binary (`gcc`, no AFL flags); the same binary is used by every fuzzer.

#### AFL++ (QEMU mode)
**Why:** The de facto evolutionary fuzzing baseline. Represents coverage-guided mutation without format knowledge or neural guidance. All results reported relative to AFL++ coverage as a normalisation baseline (AFL++ = 100%).

**Setup:** `afl-fuzz -Q -i corpus/cjson_seeds/ -o results/cjson_afl/ -- cjson/cjson_driver --ipstr=@@`

No dictionary, default power schedule, QEMU mode on plain binary.

#### AFLFast (QEMU mode)
**Why:** Represents the best evolutionary-only approach with smarter seed scheduling (Markov chain power schedule). Tests whether our DL scheduler adds value beyond classical scheduling improvements.

**Setup:** Same as AFL++ but with `--schedule=fast` and QEMU mode on the same plain binary.

#### NEUZZ (QEMU mode)
**Why:** The closest methodological predecessor — gradient-guided mutation with a neural surrogate. The primary comparison point for our neural scheduler contribution. Any gain over NEUZZ isolates the value of format-awareness and the DL energy scheduler specifically.

**Setup:** Original NEUZZ codebase with QEMU coverage on the same plain binary. For `cJSON` and `LAVA-M`, follow the paper's setup as closely as practical: run AFL for one hour to build the initial corpus, train on that corpus, and then launch the fixed-time campaign from the same seed set for every fuzzer.

**Expected limitation:** NEUZZ uses no format knowledge; byte-level gradient guidance alone may miss multi-byte structural constraints in JSON and CIDR.

#### NEUZZ++ (preferred modern NPS baseline)
**Why:** NEUZZ++ is the strongest directly relevant follow-up study because it revisits neural program smoothing with a more practical implementation and a much stricter benchmarking methodology. It is the right reference point for how to test an ML-guided fuzzer credibly, even when NEUZZ remains the historical baseline for architecture choices.

**Setup:** Use the published NEUZZ++ / MLFuzz configuration on the same shared plain binary targets where possible. Reuse the same initial corpus, coverage metric, harness mode, and wall-clock budget as the other greybox fuzzers. Replay each run's final corpus under one common coverage collector so the comparison metric is identical across tools.

**Expected limitation:** NEUZZ++ shows that many prior NPS gains disappear under stronger baselines and more repetitions. We should therefore treat NEUZZ++ as both a competitor and a methodological guardrail.

#### PreFuzz / MLFuzz (supplementary, if available)
**Why:** Provides one more data point from the broader neural-program-smoothing family, but is less central than NEUZZ and NEUZZ++ for this project's story.

**Setup:** Use published configuration only if it can be reproduced on the same targets and coverage metric without changing the harness assumptions.

**Note:** If PreFuzz / MLFuzz setup is unavailable or too infrastructure-heavy, document this explicitly and omit it rather than weakening the primary NEUZZ / NEUZZ++ comparison.

#### libFuzzer (supplementary only)
**Why:** Represents the state of the art in production coverage-guided fuzzing without ML.

**Note:** libFuzzer requires source instrumentation (`-fsanitize=fuzzer`) and cannot run in QEMU mode. It is run as a **supplementary comparison** on cJSON only (compiled separately with `-fsanitize=fuzzer,address`), reported alongside but not included in the primary QEMU greybox comparison table. This deviation from the shared coverage mechanism is documented explicitly.

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

- For the shared-source benchmark targets (`cJSON`, `LAVA-M`), target **20-30 independent runs** per fuzzer × target combination; NEUZZ++ explicitly recommends 30 trials for ML-based fuzzing because variance can be higher than in standard greybox fuzzers.
- For the slow opaque binaries (`ipv4`, `ipv6`, `cidrize`), treat **10 runs** as the minimum reportable benchmark and **3-5 runs** as pilot-only, not final-evidence, numbers.
- Report **mean ± standard deviation** for all metrics
- Use the **Mann-Whitney U test** (non-parametric, no normality assumption) to test significance of pairwise differences; report p-values
- Report **Vargha-Delaney A₁₂ effect size** for coverage comparisons
- Draw **coverage over time** plots with shaded 95% confidence intervals and clearly state the exact run count per target
- Replay each finished corpus through a common coverage measurement pass when comparing different fuzzers, following the NEUZZ++ / FuzzBench-style recommendation to avoid mismatched internal coverage metrics

### 4.5 Time Budget

- Keep **24 hours** as the primary wall-clock budget for the shared-source greybox benchmark (`cJSON`; optionally additional open-source targets), matching NEUZZ's headline comparison window.
- Keep **6 hours** for `LAVA-M`, which is standard in the literature and was also used by NEUZZ for that dataset.
- For the opaque Windows parser targets, use a staged protocol:
  - `10 minutes` for pilot / harness validation
  - `1-2 hours` for development checks and checkpoint bootstrap generation
  - `6-24 hours` for final effectiveness runs, with the exact budget reported alongside the low execution rate of the PyInstaller targets
- Do not compare a 6-hour opaque-binary run directly against a 24-hour NEUZZ result; only compare tools under matched time budgets on the same target and harness.

### 4.6 New-Format Onboarding Benchmark

In addition to bug-finding and coverage benchmarking on the existing targets, the project should explicitly measure **format transfer**: how well the fuzzer absorbs a previously unseen input format under a constrained onboarding budget.

This benchmark is not asking "can the fuzzer find bugs in one more parser if we hand-write a strong mutator?" Instead, it asks:

> **Given a new format the fuzzer has never seen before, how much effectiveness does it retain with minimal format-specific engineering?**

This is especially important for the current architecture because the repository already exposes a meaningful low-effort onboarding path through:

- `config/<format>_format.json`
- `GenericSeedGenerator`
- `GenericSemanticMutator`

The benchmark should therefore evaluate the quality of that path directly, rather than only the quality of hand-written format-specific extensions.

#### 4.6.1 Research question

Add a transfer-focused sub-question under RQ3:

| ID | Question |
|----|----------|
| RQ3a | How effectively does the fuzzer generalise to a previously unseen format under limited onboarding effort? |

#### 4.6.2 Onboarding budgets

For each held-out format, evaluate three onboarding levels:

| Level | Allowed work | Purpose |
|------|--------------|---------|
| **B0: config-only** | Add only `config/<format>_format.json` with `valid_examples` and minimal metadata | Tests true low-effort transfer |
| **B1: config+hints** | Add config plus token hints / mutation hints / bootstrap hints; no custom Python mutator | Tests whether generic infrastructure is sufficient with moderate guidance |
| **B2: custom mutator** | Add a dedicated seed generator and/or semantic mutator | Upper bound for that format in the current architecture |

The primary transfer metric should be:

> **How close does B0 or B1 get to B2 under the same time budget?**

If a new format only works well after B2, then the fuzzer is extensible, but not strongly format-transferable.

#### 4.6.3 Candidate held-out formats

Choose **4-6 previously unsupported formats** with increasing structural difficulty. Recommended progression:

| Format | Why it is useful |
|--------|------------------|
| MAC address | Fixed-field delimiter-separated text; simplest transfer case |
| Semantic version (`semver`) | Optional fields and precedence/build suffixes |
| URL / URI | Multiple optional components and separator semantics |
| Email address | Local/domain structure with quoting and edge-case validity rules |
| ISO-8601 date/time | Normalisation and cross-field validity constraints |
| CSV row with quoting/escaping | Tests delimiter, escaping, and quoted-field handling |

Stretch target:

| Format | Why it is useful |
|--------|------------------|
| Small binary/container format | Tests whether the generic fallback remains effective outside structured text |

The held-out formats should not receive a format-specific mutator during B0 or B1. They must remain genuinely "new" to the fuzzer until B2.

#### 4.6.4 Metrics

For each format × onboarding level combination, collect:

| Metric | Meaning |
|--------|---------|
| Time to first valid input | How quickly the fuzzer reaches the parser success path |
| Valid-input rate over time | Whether mutations preserve enough structure to keep exploring deeper logic |
| Coverage growth over time | Standard effectiveness signal |
| Unique interesting inputs | Diversity of retained structured exploration |
| Real bugs / oracle mismatches | Whether transfer quality leads to bug-finding, not just syntax churn |
| Onboarding effort | Files changed, lines changed, and approximate engineering time |

In addition to raw coverage, define a **transfer efficiency score**:

```text
transfer_efficiency = coverage(B0 or B1) / coverage(B2)
```

reported at matched checkpoints (for example 10 min, 1 h, 6 h, final).

#### 4.6.5 Evaluation protocol

For each held-out format:

1. Implement B0 and run `N` repeated trials under a fixed budget.
2. Extend to B1 without adding custom format-specific mutation code; rerun the same protocol.
3. Implement B2 as the best practical hand-written mutator/generator for that format.
4. Compare B0, B1, and B2 on matched seeds, harness, oracle, and wall-clock budget.

Keep the same statistical guidance as Section 4.4:

- Prefer **20-30 runs** when the target is fast enough.
- Treat **10 runs** as the minimum reportable count for slower targets.
- Report mean ± SD, Mann-Whitney U, and effect size.

#### 4.6.6 What success looks like

Interpretation should be conservative:

- **Strong transfer:** B0 already reaches a substantial fraction of B2.
- **Moderate transfer:** B1 performs well, but B0 is weak.
- **Low transfer / high extension cost:** Only B2 performs well.

For this project, the most meaningful success criterion is:

> **A new format should be considered successfully onboarded only if the config-driven path (B0 or B1) is competitive with the custom-mutation upper bound.**

That criterion aligns the benchmark with the actual architectural promise of the repository: not just that it can be extended to new formats, but that it can absorb them with limited manual work.

#### 4.6.7 Literature rationale

This benchmark design is motivated by prior structured-input fuzzing work:

- **NAUTILUS** and **Superion** show that structure-preserving mutation is essential once inputs are more constrained than byte-level fuzzers can handle reliably.
- **Gramatron** shows that grammar-aware mutation should include larger, higher-level structural edits rather than only local repairs.
- **Fuzz4All** suggests LLMs are most useful as an offline bootstrap aid for unseen input languages, not as the hot-loop mutator itself.
- **FieldsFuzz** highlights that field dependencies become the main bottleneck as formats become more realistic.

Together, these papers imply that the right transfer benchmark is not simply "one more target", but a staged measurement of how much manual format knowledge the fuzzer still requires before it becomes effective.

#### 4.6.8 Concrete held-out benchmark: ISO-8601 datetime

If only **one** new-format transfer benchmark is implemented, use **ISO-8601 datetime strings** as the held-out format.

**Why this format**

- It is clearly more structured than IPv4 but simpler than full JSON.
- It has multiple optional components: date-only, datetime, seconds, fractional seconds, `Z`, and signed timezone offsets.
- It includes real cross-field validity constraints such as month/day ranges, leap years, hour/minute/second bounds, and timezone syntax.
- It is still a string format, so it exercises the repository's generic text-format fallback path without requiring a binary/container extension.
- It has a practical oracle path in Python, which keeps the benchmark realistic for this repository.

##### 4.6.8.1 Scope of accepted inputs

To keep the benchmark precise, define the accepted language as this **restricted ISO-8601 subset**:

- Date only: `YYYY-MM-DD`
- Datetime without timezone: `YYYY-MM-DDTHH:MM:SS`
- Datetime with fractional seconds: `YYYY-MM-DDTHH:MM:SS.ssssss`
- Datetime with UTC suffix: `YYYY-MM-DDTHH:MM:SSZ`
- Datetime with signed offset: `YYYY-MM-DDTHH:MM:SS+08:00`

Out of scope for this benchmark:

- Week dates
- Ordinal dates
- Reduced precision dates such as `YYYY-MM`
- Named time zones
- Free-form whitespace-tolerant variants

This restricted scope avoids oracle ambiguity and makes the transfer experiment easier to reproduce.

##### 4.6.8.2 Oracle choice

Use a **shape-first oracle** similar in spirit to the existing parser oracles.

Primary oracle:

- Python standard library `datetime.date.fromisoformat(...)`
- Python standard library `datetime.datetime.fromisoformat(...)`

Oracle policy:

- If the input matches the benchmark's supported shapes and the corresponding stdlib parser accepts it, classify as **oracle-valid**.
- If the input matches the supported shapes but stdlib parsing fails, classify as **oracle-invalid**.
- If the input falls outside the benchmark's supported shapes, classify as **oracle-unsupported**.

Normalization policy:

- Normalize `Z` to `+00:00` before passing to `datetime.fromisoformat(...)` if needed.
- Preserve the original input for bug reporting, but store a normalized value in oracle metadata for easier deduplication.

Suggested oracle metadata fields:

| Field | Meaning |
|------|---------|
| `shape` | `date`, `datetime`, `datetime_frac`, `datetime_z`, or `datetime_offset` |
| `normalized` | Canonicalized datetime string if supported |
| `expected_valid` | `true`, `false`, or `null` for unsupported |
| `reason` | Short classifier label such as `iso_datetime_valid`, `iso_datetime_invalid_day`, `iso_datetime_unsupported_shape` |

##### 4.6.8.3 Onboarding budgets for this format

Use this exact progression:

| Level | Allowed work for ISO-8601 benchmark |
|------|--------------------------------------|
| **B0: config-only** | Add `config/iso8601_format.json` with `valid_examples`, field names, and no custom Python mutator |
| **B1: config+hints** | Add token hints and mutation hints for separators (`-`, `T`, `:`, `.`, `+`, `Z`) and numeric fields; still no custom mutator |
| **B2: custom mutator** | Add `ISO8601SeedGenerator` and/or `ISO8601SemanticMutator` with date/time-aware boundary mutations |

##### 4.6.8.4 Seed examples

Start B0 with a compact but diverse valid seed set:

```text
2026-01-01
2024-02-29
2026-04-15T00:00:00
2026-04-15T12:34:56
2026-04-15T12:34:56.123456
2026-04-15T12:34:56Z
2026-04-15T12:34:56+00:00
2026-04-15T20:34:56+08:00
1999-12-31T23:59:59-05:00
```

Recommended structured-invalid seeds for later B2 comparison:

```text
2026-13-01
2026-02-29
2026-04-31
2026-04-15T24:00:00
2026-04-15T12:60:00
2026-04-15T12:34:60
2026-04-15T12:34
2026-04-15 12:34:56
2026-04-15T12:34:56+2400
```

##### 4.6.8.5 Expected useful mutations in B2

If B2 is implemented, the custom mutator should focus on:

- Year boundary changes: `0001`, `1970`, `1999`, `2000`, `2038`, `9999`
- Month/day consistency: `02-29`, `04-31`, `12-31`
- Leap-year flips: valid leap day to invalid non-leap day and back
- Time boundaries: `00:00:00`, `23:59:59`, `24:00:00`
- Fractional-second expansion/truncation
- Offset mutations: `Z`, `+00:00`, `-00:00`, `+14:00`, `-12:00`, malformed offsets
- Separator confusion: replacing `T`, `:`, `-`, `.`, `+`, or dropping them entirely

These mutations directly test whether the fuzzer can preserve high-level shape while still crossing semantic validity boundaries.

##### 4.6.8.6 Scorecard template

Use the following per-format scorecard for reporting:

| Metric | B0: config-only | B1: config+hints | B2: custom mutator |
|--------|------------------|------------------|--------------------|
| Files added / changed | | | |
| Approx. engineering time | | | |
| Valid seed count | | | |
| Time to first valid parse | | | |
| Valid-input rate @ 10 min | | | |
| Valid-input rate @ end of run | | | |
| Coverage @ 10 min | | | |
| Coverage @ 1 h | | | |
| Coverage @ end of run | | | |
| Unique interesting inputs | | | |
| Unique real bugs / oracle mismatches | | | |
| Transfer efficiency vs B2 | | | `1.00` |

Also include a short qualitative verdict:

| Verdict field | Notes |
|--------------|-------|
| Mutation quality | Are inputs staying close to supported shapes? |
| Oracle usefulness | Did the oracle classify enough cases to be informative? |
| Main failure mode | Syntax destruction, low valid rate, shallow coverage, or oracle ambiguity |
| Overall transfer result | Strong / Moderate / Low |

##### 4.6.8.7 Success criterion for this concrete benchmark

For the ISO-8601 benchmark, declare the generic path successful only if:

- **B0 or B1 reaches at least 70% of B2 final coverage**, and
- **B0 or B1 reaches the first valid parse within the same order of magnitude of time as B2**, and
- **B0 or B1 maintains a non-trivial valid-input rate** rather than collapsing into near-total syntax destruction.

That threshold is intentionally strict enough to distinguish real transfer from mere extensibility.

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
| **A4** | Incremental retraining disabled; surrogate loaded from a prebuilt bootstrap checkpoint and then frozen | Isolates value of online learning after cold start | `--evaluation-mode hybrid_dl --no-retrain` |
| **A5** | Cosine decay with restarts replaced by fixed LR `1e-3` | Isolates value of LR schedule | `--evaluation-mode hybrid_dl --fixed-lr` |

### 5.2 What Each Ablation Tells You

**A1 (no format awareness):** If coverage drops significantly on JSON and CIDR but not IPv4, format-awareness matters proportionally to structural complexity. This validates the three-tier mutation design.

**A2 (uniform energy):** If coverage drops, the DL scheduler is genuinely learning useful energy allocation beyond what uniform distribution would achieve. If coverage stays the same, the scheduler adds overhead without benefit.

**A3 (no gradient selection):** Compares gradient-guided byte selection against random byte selection with the same surrogate. A significant drop confirms that the gradient signal, not just the surrogate's existence, is responsible for gains.

**A4 (frozen checkpoint):** Tests whether the surrogate needs to stay up-to-date after an initial bootstrap phase. A significant drop means the online learning loop is essential; a small drop means the warm-start checkpoint generalises well enough.

**A5 (fixed LR):** Validates whether the cosine decay schedule meaningfully helps surrogate accuracy under incremental retraining conditions. Fixed LR used is `1e-3` (the Adam base rate in trainer.py).

### 5.3 Ablation Experimental Protocol

**Step 0 — Pilot check.** Confirm the full system runs end-to-end before committing to long runs:
```bash
python main.py ipv4 --evaluation-mode hybrid_dl --fresh-start --time-budget 600 --seed 1
```
Check that `results/ipv4/energy_log.csv`, `oracle_log.csv`, and `dl_training.jsonl` are produced and non-empty.

**Step 1 — Build the frozen checkpoint for A4.** For each binary target used in A4, run one short bootstrap campaign with retraining enabled and archive the resulting checkpoint:
```bash
python main.py <target> --evaluation-mode hybrid_dl --fresh-start --time-budget 3600 --seed 1
```
Copy `models/<target>_surrogate.pt` into `savedruns/bootstrap_checkpoints/` and reuse that checkpoint for every A4 repetition on the same target. Do not let `--fresh-start` delete the checkpoint immediately before an A4 run without restoring it first.

**Step 2 — Run each variant.** For each combination of variant × target × seed (1..5), run:
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

**Step 3 — Collect metrics.** After all runs, for each variant × target combination:
- Load `ablation_results/<variant>/<target>/run*/plot_data` (CSV)
- Compute mean ± SD of `behaviors_seen` at the 24h mark across the 5 runs
- Compute mean ± SD of `misprediction_rate` from `dl_training.jsonl` (Full, A3, A4, A5 only)
- For A4, also record whether the checkpoint was successfully loaded at run start (`dl_summary.json` / `fuzzer_config.json`) so the ablation is not accidentally measuring an untrained model

**Step 4 — Fill the results table** (Section 5.4) and rank components by `ΔCov(Full) − ΔCov(Aᵢ)`.

**Step 5 — Plot.** Use `python evaluation/plot_progress.py <target>` for per-run curves.

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
| AFL++ version | e.g., 4.x |
| QEMU version | bundled with AFL++ (`afl-qemu-trace --version`) |
| Compiler | gcc version (plain binary build) |

Recommended minimum: 8-core CPU, 32 GB RAM, Ubuntu 22.04, dedicated run (no other workloads during experiments).

### 6.2 Target Compilation

Compile targets as follows:

- **Plain binary** (`gcc`, no AFL flags) — used by all greybox fuzzers under QEMU mode. One binary, shared across AFL++, AFLFast, NEUZZ, and our fuzzer. See `cjson/build.sh`.
- **ASAN binary** (`gcc -fsanitize=address,undefined`) — used for crash triage and silent memory error detection after a bug is found. Not used during the main fuzzing runs (ASAN overhead ~2x would skew throughput metrics).
- **libFuzzer binary** (`clang -fsanitize=fuzzer,address`) — supplementary only, cJSON target only.

> **Rationale:** Compiling with AFL instrumentation (`afl-clang-fast`) is skipped for the primary comparison. LLVM instrumentation gives AFL++ higher-quality coverage than QEMU, which would favour AFL++ independently of its mutation strategy. Using a single plain binary under QEMU ensures the coverage signal is identical for all fuzzers.

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
| Our fuzzer matches or exceeds NEUZZ / NEUZZ++ on shared binary targets under matched budgets | Benchmark metric table + common replayed coverage metric |
| Incremental retraining is necessary for sustained coverage after warm start | A4 ablation, coverage-over-time plot, checkpoint-loaded metadata |

---

*Document version 1.1 — updated on 2026-04-15 using NEUZZ / NEUZZ++ evaluation guidance and the repository's current online-training implementation.*
