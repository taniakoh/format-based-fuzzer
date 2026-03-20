# Hybrid Coverage-Guided Fuzzer

A three-tier format-aware fuzzer targeting IPv4 and IPv6 string parser binaries.

## Project Structure

```
format-based-fuzzer/
├── config/                    # Format configs (fields, semantic rules, havoc weights)
│   ├── ipv4_format.json
│   └── ipv6_format.json
├── corpus/                    # Seed inputs
│   ├── ipv4_seeds.txt
│   └── ipv6_seeds.txt
├── fuzzer/                    # Core fuzzer modules
│   ├── seed_generator.py      # Grammar-based valid seed generation
│   ├── mutation/
│   │   ├── tier1_structure.py # Structural mutations (pass-through for IP)
│   │   ├── tier2_semantic.py  # Protocol-aware string mutations
│   │   └── tier3_havoc.py     # Stochastic byte-level mutations
│   ├── executor.py            # Wraps win-ipv4/ipv6-parser.exe
│   ├── coverage.py            # Behavior-based coverage tracking
│   ├── corpus.py              # Seed queue with priority selection
│   └── scheduler.py          # Phase 1 static scheduler
├── dl/                        # DL scheduler (Phase 2, requires torch)
│   ├── surrogate.py           # Neural surrogate model + DLScheduler
│   ├── trainer.py             # Training loop + checkpoint save/load
│   └── trustworthiness.py    # Confidence gate
├── evaluation/
│   └── collect_metrics.py     # Metrics collection and stats output
├── models/                    # Saved model checkpoints (created at runtime)
│   ├── ipv4_surrogate.pt
│   └── ipv6_surrogate.pt
├── results/                   # Fuzzing output (created at runtime)
│   ├── ipv4/
│   │   ├── bugs.jsonl
│   │   ├── crashes/
│   │   └── stats.txt
│   └── ipv6/
├── ipv4ipv6/                  # Target binaries
│   ├── win-ipv4-parser.exe
│   └── win-ipv6-parser.exe
└── main.py                    # Entry point
```

---

## Requirements

**Python 3.11+** — no external packages required for Phase 1.

### Phase 2 (DL Scheduler) — optional

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

> Without torch installed the fuzzer runs in Phase 1 mode (static operator weights, no DL). All other functionality is identical.

---

## Running the Fuzzer

### Basic usage

```bash
python main.py <target> [options]
```

| Argument | Values | Description |
|---|---|---|
| `target` | `ipv4`, `ipv6`, `all` | Which parser to fuzz (`all` runs both sequentially) |
| `--havoc-iters N` | int (default: `8`) | Byte-level mutations applied per execution |
| `--time-budget S` | int (default: `86400`) | Total fuzzing time in seconds |
| `--seed RNG` | int (default: `42`) | RNG seed for reproducibility |
| `--seeds-n N` | int (default: `100`) | Initial corpus size loaded at startup |

### Examples

```bash
# Quick smoke test (~5 min, ~10 executions)
python main.py ipv4 --time-budget 300

# Fuzz IPv4 for 1 hour
python main.py ipv4 --time-budget 3600

# Fuzz IPv6 for 1 hour with more havoc mutations per call
python main.py ipv6 --time-budget 3600 --havoc-iters 16

# Fuzz both targets for 24 hours
python main.py all --time-budget 86400

# Reproducible run
python main.py ipv4 --time-budget 3600 --seed 123
```

> **Note:** The target binaries are PyInstaller one-file bundles. Each execution takes ~20–30 seconds to unpack, so expect roughly 120 executions per hour.

---

## Output

All results are written to `results/<target>/`:

| File | Contents |
|---|---|
| `bugs.jsonl` | One JSON record per interesting result (input, bug type, exception) |
| `crashes/crash_NNNNNN.txt` | One file per crashing input |
| `stats.txt` | Final summary printed and saved at the end of each run |

### Bug types

| Type | Meaning |
|---|---|
| `validity` | Valid input falsely rejected by the parser — **real bug** |
| `bonus` | Unexpected exception raised — **real bug** |
| `invalidity` | Expected `ParseException` on an invalid input |
| `CRASH` / `TIMEOUT` | Non-zero exit code or process exceeded 60 s timeout |

### Console output

```
[NEW]         execs=     3  behaviors=   4  corpus=  83  input=b'1:555S.5.'
[VALIDITY    ] execs=     4  input=b'255.255.255.255'
[INVALIDITY  ] execs=     5  input=b'999.0.0.1'
```

---

## DL Model Checkpoints

When torch is installed the fuzzer trains a neural surrogate model on inputs that trigger new behaviors. Checkpoints are saved to `models/`:

```
models/ipv4_surrogate.pt   # saved every 10 new behaviors and at shutdown
models/ipv6_surrogate.pt
```

On the next run the model is loaded automatically and training continues from where it left off. Delete the `.pt` file to start fresh.

---

## Ablation Configurations

To evaluate which components contribute to bug-finding, run with the following setups and compare `stats.txt`:

| Config | How to run |
|---|---|
| Baseline (havoc only, no torch) | Uninstall torch, run normally |
| + Semantic mutations | Install torch, run normally (Phase 1 static weights) |
| Full Hybrid (+ DL scheduler) | Install torch + CUDA, run normally (Phase 2 auto-activates) |

Recommended per-config run: `--time-budget 3600` (1 hour), repeated with different `--seed` values for variance.

---

## Evaluation Parameters to Test

| Parameter | Values to compare |
|---|---|
| `--havoc-iters` | `4`, `8`, `16`, `32` |
| `--seeds-n` | `50`, `100`, `200` |
| `target` | `ipv4` vs `ipv6` |
| Scheduler | Phase 1 (no torch) vs Phase 2 (torch + CUDA) |

Metrics to report per configuration: `validity_bugs`, `bonus_bugs`, `behaviors_covered`, `time_to_first_bug`, `total_executions`.
