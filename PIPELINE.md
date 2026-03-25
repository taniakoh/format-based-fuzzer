# Fuzzer Pipeline: Input -> Output -> Model

This document traces one binary-target fuzzing iteration in the current codebase and notes where the `json` target takes a different Atheris-managed path.

---

## Overview

```text
Seed generator / corpus file
        |
        v
     Corpus.select()
        |
        v
Tier 1 structure mutator (pass-through today)
        |
        v
Scheduler.plan_mutation(seed)
        |
        +--> semantic_probability
        +--> preferred_fields
        +--> guided_ratio
        +--> havoc operator weights
        +--> optional hot bytes (DL only, confidence-gated)
        |
        v
Tier 2 semantic mutator (sometimes applied)
        |
        v
Tier 3 havoc mutator
        |
        v
Executor.run(mutated)
        |
        v
RunResult + behavior bitmap
        |
        v
CoverageAnalyzer.is_interesting()
        |
        +--> not new: log bug/crash stats only
        |
        +--> new behavior:
             add to corpus
             write queue entry
             append DL training sample
             maybe train surrogate and save checkpoint
```

For `json`, `main.py` switches to `_run_atheris_target(...)` instead of the loop below. Atheris then owns execution scheduling, coverage, and corpus growth inside `results/json/`.

---

## Stage 1: Seed Generation

**Files:** `fuzzer/seed_generator.py`, `corpus/<target>_seeds.txt`, `config/<target>_format.json`

The initial corpus is built before mutation starts:

1. If `corpus/<target>_seeds.txt` exists, those seeds are loaded first.
2. The remaining slots up to `--seeds-n` are filled by the registered generator for that target.
3. If no custom generator exists, `GenericSeedGenerator` falls back to `valid_examples` from the format config.

Current built-in generators:

- `ipv4`: boundary-heavy dotted quads with occasional leading zeros
- `ipv6`: multiple structural templates, including compressed forms and mixed IPv4 suffixes
- `cidrize`: IPv4, IPv6, CIDR, range, partial-range, and wildcard forms
- `json`: generic fallback seeded from `config/json_format.json` and `corpus/json_seeds.txt`

All seeds are stored as `bytes`. Each one is inserted into the corpus with initial priority `1.0`.

---

## Stage 2: Seed Selection

**File:** `fuzzer/corpus.py`

Each iteration calls:

```python
seed = corpus.select(priority_fn=scheduler.get_seed_priority)
```

Selection is weighted by priority, not strict round-robin.

- `StaticScheduler` still adapts priorities based on observed mutation payoff by seed family.
- `DLScheduler` adds a confidence-and-blend-based boost on top of that static baseline.

So even the "static" mode is no longer purely fixed weights everywhere; it has online payoff tracking, just without neural guidance.

---

## Stage 3: Mutation Planning

**Files:** `fuzzer/scheduler.py`, `dl/surrogate.py`, `dl/trustworthiness.py`

Before Tier 2 and Tier 3 run, the scheduler builds a mutation plan:

```python
plan = scheduler.plan_mutation(seed)
```

The plan currently includes:

- `weights`: normalized havoc operator weights
- `semantic_probability`: chance to apply Tier 2 on this iteration
- `guided_ratio`: how often Tier 3 should spend effort on guided positions versus random ones
- `preferred_fields`: up to three semantic fields worth biasing toward
- `mode`: `static` or `guided`
- `confidence`, `blend`, `reason`: scheduler diagnostics

### Static mode

`StaticScheduler` uses `MutationPayoffTracker` only. It adapts operator weights, semantic probability, preferred fields, and seed priority from empirical success rates.

### Hybrid DL mode

`DLScheduler` starts from the same payoff tracker, then only enables guided mode when all of these are true:

- model confidence passes the trust gate (`>= 0.75`)
- at least 20 training samples have been seen
- at least 2 training rounds have completed
- recent guided outcomes are not underperforming recent static outcomes

When those checks fail, the scheduler returns a static plan with a concrete fallback reason such as `low_confidence` or `undertrained_rounds`.

---

## Stage 4: Tiered Mutation

**Files:** `fuzzer/mutation/tier1_structure.py`, `fuzzer/mutation/tier2_semantic.py`, `fuzzer/mutation/tier3_havoc.py`

The selected seed then flows through three tiers.

### Tier 1: Structure

`StructureMutator` is currently a pass-through layer. It exists to keep the pipeline shape stable if future targets need coarse structural edits before semantic or havoc mutations.

### Tier 2: Semantic

Tier 2 runs with probability `plan["semantic_probability"]`.

The current target mutators are:

- `ipv4`
- `ipv6`
- `cidrize`
- `json`

Each semantic mutator:

- chooses one operation from the target's configured `semantic_rules`
- can use `hot_bytes` from the DL surrogate
- can bias toward `preferred_fields` from the scheduler
- records trace metadata so the scheduler can learn which operations, fields, and guidance modes are paying off

The core abstraction is `SemanticSpan`, which maps byte positions back to meaningful regions such as IPv4 octets, IPv6 groups, cidrize tokens, or JSON literals/punctuation.

### Tier 3: Havoc

Tier 3 always runs. `HavocMutator` applies `--havoc-iters` stochastic byte-level edits using the weights chosen by the scheduler.

The default operator set is:

- `bit_flip`
- `byte_substitute`
- `arithmetic`
- `splice`
- `delete_range`
- `insert_random`
- `interesting_byte`

If guided hot bytes or preferred semantic fields are available, Tier 3 biases mutation positions toward them according to `guided_ratio`.

---

## Stage 5: Execution

**File:** `fuzzer/executor.py`

`Executor(target)` picks the best runtime mode for the current platform:

- Linux + registered native binary: Linux native execution with a short timeout
- otherwise: behavior-hash execution against the configured parser binary
- JSON does not use `Executor`; it goes through the Atheris harness path in `main.py`

Important implementation details for the binary targets:

- `stdin=subprocess.DEVNULL` is always used
- Windows parser bundles get a 60-second timeout because of PyInstaller unpack overhead
- Linux native binaries use a 5-second timeout
- stdout/stderr are parsed into a `RunResult` containing `bug_type`, `exception_msg`, traceback text, and exit code

Bug classification is derived from parser output plus process state:

- `PASS`
- `validity`
- `invalidity`
- `bonus`
- `CRASH`
- `TIMEOUT`

---

## Stage 6: Behavior Bitmap and Interestingness

**Files:** `fuzzer/executor.py`, `fuzzer/coverage.py`

For non-instrumented runs, coverage is approximated with a 65,536-byte bitmap:

1. `PASS` returns an all-zero bitmap.
2. Otherwise, `"<bug_type>|<exception_msg[:128]>"` is SHA-256 hashed into a stable slot.
3. `CRASH`, `TIMEOUT`, and `validity` set a second slot as well so they remain interesting even when repeated.

`CoverageAnalyzer.is_interesting(bitmap)` merges that bitmap into the global run bitmap and returns `True` if any slot flipped from `0` to `1`.

That count is reported as `Behaviors seen`.

---

## Stage 7: Feedback, Logging, and Corpus Growth

**Files:** `fuzzer/corpus.py`, `evaluation/collect_metrics.py`, `main.py`

Every execution is recorded:

- `bugs.jsonl` gets one entry for every non-`PASS` result
- `unique_bugs.json` tracks distinct `(bug_type, exception_msg)` signatures
- `crashes/` stores unique crash inputs
- `plot_data` appends a CSV progress point

When a new behavior is found:

- the mutated input is added back into the corpus
- a queue artifact is written to `results/<target>/queue/id_XXXXXX.txt`
- `behaviors_covered` is updated
- the input and active bitmap positions are appended to the DL training buffer

Additional run artifacts written by the current implementation:

- `fuzzer_config`
- `fuzzer_stats`
- `mutation_stats.json`
- `dl_training.jsonl`
- `dl_summary.json`

---

## Stage 8: DL Training and Checkpoints

**Files:** `dl/surrogate.py`, `dl/trainer.py`

This stage only runs when torch is available and DL has not been disabled with `--no-dl`.

Training happens:

- periodically, every `TRAIN_EVERY = 10` newly discovered behaviors
- once more at shutdown if the training buffer is non-empty

### Model

`CoverageSurrogate` uses:

- byte embedding (`256 -> 8`)
- MLP encoder (`2048 -> 512 -> 256`)
- `coverage_head`: 128-dimensional sigmoid output
- `confidence_head`: 1-dimensional sigmoid output

### Targets and loss

The surrogate is trained on:

- a 128-dimensional binary coverage target built from observed bitmap positions `< 128`
- a learned confidence target derived from top-k overlap between predicted and true coverage

Training combines:

- coverage BCE loss
- a lightly weighted confidence regression loss

### Persistence

Checkpoints are saved to:

```text
models/<target>_surrogate.pt
```

Checkpoint metadata also stores scheduler runtime state such as:

- `training_samples_seen`
- `training_rounds`
- `last_training_loss`

That metadata is restored on the next run so the hybrid scheduler does not forget its warm-up state.

---

## JSON Target Divergence

**Files:** `main.py`, `fuzzer/json_atheris_harness.py`

The `json` target does not use the binary-target loop above.

Instead, `main.py`:

1. generates a seed corpus on disk in `results/json/atheris_corpus/`
2. writes `results/json/fuzzer_config`
3. launches the Atheris harness in a subprocess
4. lets Atheris/libFuzzer manage coverage, scheduling, and crash artifacts

The main outputs for that path are:

- `atheris.log`
- `atheris_corpus/`
- `crashes/`
- `stats.txt`
- `fuzzer_stats`

Because Atheris owns the execution loop, the DL scheduler, behavior bitmap, and corpus feedback path described above apply only to the binary targets.

---

## Key Numbers

| Constant | Value | Where |
|---|---|---|
| Behavior bitmap size | 65,536 bytes | `fuzzer/executor.py`, `fuzzer/coverage.py` |
| Model max input length | 256 bytes | `dl/surrogate.py` |
| Coverage output dimension | 128 | `dl/surrogate.py` |
| Periodic train trigger | 10 new behaviors | `main.py` |
| Confidence threshold | 0.75 | `dl/trustworthiness.py` |
| DL warm-up samples | 20 | `dl/surrogate.py` |
| DL warm-up rounds | 2 | `dl/surrogate.py` |
| Windows timeout | 60 s | `fuzzer/executor.py` |
| Linux timeout | 5 s | `fuzzer/executor.py` |
| Default havoc iterations | 8 | `main.py` |
