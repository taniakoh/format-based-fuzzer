# Fuzzer Pipeline: Input → Output → Model

This document traces the full lifecycle of a single fuzzing iteration, from the very first seed to the trained DL surrogate.

---

## Overview

```
[corpus/ipv4_seeds.txt]
[IPv4SeedGenerator]
        │
        ▼
   ┌─────────┐
   │  Corpus │◄──────────────────────────────────────────┐
   └────┬────┘                                           │
        │ corpus.select()                                │ add(mutated, priority)
        ▼                                                │
  seed: bytes                                           [if new behavior]
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│                    MUTATION PIPELINE                         │
│                                                              │
│  Tier 1: StructureMutator      → pass-through (no-op)       │
│  Tier 2: IPv4SemanticMutator   → IP-aware string mutations  │
│          (50% probability)                                   │
│  Tier 3: HavocMutator          → weighted byte-level chaos  │
│          (weights from Scheduler)                            │
└──────────────────┬───────────────────────────────────────────┘
                   │ mutated: bytes
                   ▼
         ┌─────────────────┐
         │    Executor     │  win-ipv4-parser.exe --ipstr <string>
         └────────┬────────┘
                  │
          ┌───────┴───────┐
          │               │
          ▼               ▼
     stdout/stderr    exit code
          │
          ▼
    ┌───────────────┐
    │  ParseOutput  │  → bug_type, exception_msg, traceback
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ BehaviorBitmap│  SHA-256(bug_type|exception_msg) → slot in 65536-byte map
    └───────┬───────┘
            │ bitmap: bytes
            ▼
    ┌──────────────────┐
    │ CoverageAnalyzer │  is_interesting? (any new slot set?)
    └───────┬──────────┘
            │
    ┌───────┴──────────────────┐
    │                          │
  [NEW]                    [NOT NEW]
    │                          │
    ▼                          ▼
Add to Corpus          Check result.is_interesting
Feed training buffer   Log to bugs.jsonl if bug
    │
    ▼
[Every 10 new behaviors]
    │
    ▼
  Train CoverageSurrogate
  Save models/ipv4_surrogate.pt
```

---

## Stage 1: Seed Generation

**Files:** `fuzzer/seed_generator.py`, `corpus/ipv4_seeds.txt`

The fuzzer starts by building an initial corpus before any mutations run.

**Two sources, merged in order:**

1. **Hand-curated seeds** — loaded from `corpus/ipv4_seeds.txt` (or `ipv6_seeds.txt`). These are valid addresses written by the developer to cover known edge cases (e.g. `0.0.0.0`, `255.255.255.255`, `::1`).

2. **Programmatic seeds** — `IPv4SeedGenerator.generate()` fills remaining slots up to `--seeds-n` (default 100). It picks octets from boundary values `[0, 1, 9, 10, 99, 100, 127, 128, 199, 200, 254, 255]` and occasionally pads them with leading zeros (e.g. `001.002.010.255`).

All seeds are stored as `bytes` (UTF-8 encoded strings). The corpus is a priority-weighted list; every seed starts with `priority=1.0`.

---

## Stage 2: Seed Selection

**File:** `fuzzer/corpus.py`

Each iteration calls `corpus.select()`, which does a **weighted random draw** from all seeds using their priorities as weights. In Phase 1 all priorities are `1.0` (uniform). In Phase 2 the DL scheduler assigns higher priority to inputs the model predicts will find new coverage — so recently-interesting inputs get selected more often.

---

## Stage 3: Mutation Pipeline

**Files:** `fuzzer/mutation/tier1_structure.py`, `tier2_semantic.py`, `tier3_havoc.py`

The selected seed passes through three mutation tiers in order. Each tier takes `bytes` and returns `bytes`.

### Tier 1 — Structure (`StructureMutator`)

A no-op pass-through for IP strings. The class exists so the main loop never has to branch — if a JSON target were added, this tier would add/remove/nest keys.

### Tier 2 — Semantic (`IPv4SemanticMutator` / `IPv6SemanticMutator`)

Applied with **50% probability** per iteration. Picks one operation at random from a protocol-aware list and applies it to the decoded address string.

IPv4 operations:
- `octet_boundary` — replace an octet with `0`, `1`, `127`, `128`, `254`, or `255`
- `leading_zeros` — pad an octet with `zfill(1–4)`, e.g. `1` → `001`
- `extra_octets` — append 1–3 extra `.N` segments
- `missing_octets` — drop one octet
- `wrong_separator` — replace a `.` with `:`, `,`, `/`, space, `-`, or empty string
- `overflow_octet` — replace an octet with `256`, `999`, `65535`, or `2^32`
- `negative_octet` — replace an octet with `-1`, `-128`, `-255`
- `hex_octet` — replace an octet with its `0x` hex form
- `empty_octet` — replace an octet with `""`
- `whitespace_injection` — insert a space/tab/newline/CR at a random position

IPv6 adds: `group_boundary`, `double_colon_position`, `mixed_notation` (IPv4 suffix), `extra/missing_groups`, `overflow_group`, `multiple_double_colons`, `zone_id` (`%eth0`).

If any operation raises an exception, the original bytes are returned unchanged — the fuzzer itself never crashes due to a bad parse.

### Tier 3 — Havoc (`HavocMutator`)

Runs `--havoc-iters` (default 8) stochastic byte-level operations in sequence. Each operation is chosen by weighted random draw:

| Operator | Default Weight | What it does |
|---|---|---|
| `bit_flip` | 0.20 | XOR one random bit in one byte |
| `byte_substitute` | 0.20 | Replace one byte with a random value 0–255 |
| `arithmetic` | 0.15 | Add `±1` or `±35` to one byte (wraps at 255) |
| `interesting_byte` | 0.15 | Set one byte to `0x00`, `0x01`, `0x2E` (`.`), `0x3A` (`:`), `0x7F`, `0x80`, or `0xFF` |
| `splice` | 0.10 | Swap the two halves of the buffer |
| `delete_range` | 0.10 | Delete 1–8 bytes starting at a random position |
| `insert_random` | 0.10 | Insert 1–8 random bytes at a random position |

Weights come from `config/<target>_format.json` in Phase 1, or from `DLScheduler.get_operator_weights()` in Phase 2.

---

## Stage 4: Execution

**File:** `fuzzer/executor.py`

`Executor.run(mutated: bytes)` does three things:

1. **Decode** the bytes to a printable ASCII string (`latin-1` → backslash-escape non-ASCII).
2. **Spawn the binary** as a subprocess:
   ```
   win-ipv4-parser.exe --ipstr <string>
   ```
   stdin is closed (`DEVNULL`). Timeout is 60 seconds (PyInstaller bundles take 20–30s to unpack, so expect ~120 executions/hour).
3. **Parse stdout + stderr** with regex to extract:
   - `bug_type` — from the parser's `Final bug count:` line
   - `exception_msg` — the exception message text
   - `traceback` — the full traceback block (if any)

**Bug classification logic:**
- `"No bugs found"` in output → `PASS`
- `Final bug count:` present → `validity`, `invalidity`, or `bonus` from the dict key
- Traceback present but no bug count → `bonus`
- Non-zero exit code and no other classification → `CRASH`
- Process killed by timeout → `TIMEOUT`

---

## Stage 5: Behavior Bitmap

**File:** `fuzzer/executor.py` (`_result_to_bitmap`)

Because the target binaries are opaque (no AFL instrumentation), real edge coverage is unavailable. Instead:

1. A 65536-byte bitmap is initialized to all zeros.
2. If the result is `PASS`, the bitmap stays all zeros (no new information).
3. Otherwise, the string `"<bug_type>|<exception_msg[:128]>"` is SHA-256 hashed. The first two bytes of the digest are used as a 16-bit index: `bitmap[pos] = 1`.
4. For `CRASH`, `TIMEOUT`, and `validity` bugs, a **second slot** is set using digest bytes 2–3 — so these are always flagged as interesting even if the same exception was seen before.

This gives each unique `(bug_type, error message)` pair a stable, reproducible position in the bitmap.

---

## Stage 6: Coverage Analysis

**File:** `fuzzer/coverage.py`

`CoverageAnalyzer` maintains a single global 65536-byte bitmap that accumulates across all iterations.

`is_interesting(bitmap)` ORs the new bitmap against the global one. If **any slot transitions from 0 → 1**, the input is "interesting" — it triggered a parser behavior never seen before.

The `edge_count` counter increments for every newly-set slot. This is what gets reported as `behaviors_covered` in the stats.

---

## Stage 7: Corpus Feedback and Output

**Files:** `fuzzer/corpus.py`, `evaluation/collect_metrics.py`

### If the input triggered new coverage:
- It is added to the corpus: `corpus.add(mutated, priority=scheduler.get_seed_priority(mutated))`
- The `(mutated, [bitmap_positions_set])` pair is appended to the **training buffer**
- `behaviors_since_last_train` increments

### For every execution (new coverage or not):
- `MetricsCollector.record_execution()` is called
- If `bug_type != PASS`, a JSON record is appended to `results/<target>/bugs.jsonl`
- If it's a crash, the input is written to `results/<target>/crashes/crash_NNNNNN.txt`

### At shutdown:
- `metrics.finalize()` writes `results/<target>/stats.txt`:
  ```
  Target          : ipv4
  Wall time       : 3600.0s
  Total execs     : 120
  Behaviors seen  : 47
  Validity bugs   : 3
  Bonus bugs      : 1
  Invalidity count: 38
  Unique crashes  : 2
  Time-to-1st-bug : 22.4s
  ```

---

## Stage 8: DL Model Training (Phase 2 only)

**Files:** `dl/surrogate.py`, `dl/trainer.py`, `dl/trustworthiness.py`

This stage only activates when `torch` is installed. If not, `StaticScheduler` is used and stages 8–9 are skipped entirely.

### Training trigger

Every time `behaviors_since_last_train >= 10` (i.e., 10 new coverage-triggering inputs have been found), `trainer.train()` is called on the accumulated buffer.

### What the model learns

`CoverageSurrogate` is a small MLP:

```
Input: seed bytes padded/truncated to 256 bytes
  → Embedding layer (256 vocab, dim 8)  →  shape (256, 8)
  → Flatten  →  shape (2048,)
  → Linear(2048 → 512) + ReLU
  → Linear(512 → 256) + ReLU
  → Two heads:
      coverage_head:   Linear(256 → 128)  + sigmoid  → 128-dim coverage prediction
      confidence_head: Linear(256 → 1)    + sigmoid  → single confidence score
```

The **training target** is a 128-dim binary vector. For each `(seed, bitmap_positions)` pair in the buffer, any bitmap position `< 128` is set to `1.0` in the target vector. The model trains to predict which of the 128 coverage slots a given input will activate.

Loss function: Binary Cross Entropy (`BCELoss`). Optimizer: Adam, `lr=1e-3`. Default: 5 epochs per training call.

### Checkpoint persistence

After every training run the model is saved:
```
models/ipv4_surrogate.pt   ← torch.save(model.state_dict(), path)
```

On the next fuzzing run it is loaded automatically:
```
models/ipv4_surrogate.pt   → torch.load(path, map_location=device)
```

Delete the `.pt` file to start training from scratch.

---

## Stage 9: DL Scheduler Feedback (Phase 2 only)

**File:** `dl/surrogate.py` (`DLScheduler`)

Once the model exists, it influences the fuzzer in two ways each iteration:

### 1. Operator weights (`get_operator_weights`)

Before Tier 3 runs, the scheduler encodes the current seed and runs a forward pass. If `confidence >= 0.75` (the trustworthiness threshold in `dl/trustworthiness.py`), it returns **uniform weights** across all operators (each operator gets `1/7 ≈ 0.143`). Otherwise it falls back to the static weights from the JSON config.

> The current "learned weights" implementation uses uniform distribution as a placeholder — the model's learned representation influences **seed priority** and **hot byte identification**, not operator selection directly.

### 2. Seed priority (`get_seed_priority`)

When an interesting input is added to the corpus, `DLScheduler.get_seed_priority(seed)` runs a forward pass and returns the confidence score as the priority. Higher-confidence seeds (those the model believes are near new coverage) are selected more often by `corpus.select()`.

### 3. Hot byte identification (`get_field_importance`)

`identify_hot_bytes()` computes gradients of the predicted coverage with respect to the embedding layer inputs. Byte positions with the highest gradient magnitude are returned — these are the byte positions most likely to change coverage if mutated. (Available but not yet wired into the mutation pipeline directly.)

---

## Full Data Flow Summary

```
corpus/ipv4_seeds.txt  ──┐
IPv4SeedGenerator        ├──► Corpus (priority queue)
                         │         │
                         │    corpus.select()  ◄── DLScheduler.get_seed_priority()
                         │         │
                         │    Tier 1 (pass-through)
                         │         │
                         │    Tier 2 (50%): semantic string mutations
                         │         │
                         │    Tier 3: havoc   ◄── DLScheduler.get_operator_weights()
                         │         │                (or StaticScheduler)
                         │         │
                         │    win-ipv4-parser.exe --ipstr <mutated>
                         │         │
                         │    stdout/stderr → bug_type, exception_msg
                         │         │
                         │    SHA-256 hash → behavior bitmap slot
                         │         │
                         │    CoverageAnalyzer: new slot? ──► NO → log only
                         │         │ YES
                         │         ├──► corpus.add(mutated, priority)  ──┘ (loop back)
                         │         ├──► training_buffer.append((seed, positions))
                         │         │
                         │    every 10 new behaviors:
                         │         ├──► train(CoverageSurrogate, training_buffer)
                         │         └──► save models/ipv4_surrogate.pt
                         │
                    [next run]: load models/ipv4_surrogate.pt → DLScheduler
```

---

## Key Numbers

| Constant | Value | Where |
|---|---|---|
| Bitmap size | 65,536 bytes | `executor.py`, `coverage.py` |
| Max input length (model) | 256 bytes | `surrogate.py:CoverageSurrogate.MAX_LEN` |
| Coverage representation | 128 dimensions | `surrogate.py:CoverageSurrogate.COV_DIM` |
| Train trigger | every 10 new behaviors | `main.py:TRAIN_EVERY` |
| Training epochs per call | 5 | `trainer.py:train()` |
| Confidence threshold | 0.75 | `trustworthiness.py` |
| Execution timeout | 60 seconds | `executor.py:TIMEOUT_SECONDS` |
| Default havoc iterations | 8 per execution | `main.py` / `--havoc-iters` |
