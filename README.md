# format-based-fuzzer

An AFL-inspired byte-level fuzzer targeting the IPv4 and IPv6 parser binaries. All mutations are purely structural — the fuzzer treats every input as a raw byte array with no knowledge of IP address format. This mirrors AFL's real-world strategy: bit flipping, byte flipping, arithmetic nudges, interesting boundary values, and random stacked (havoc) mutations.

---

## Table of contents

1. [Project structure](#project-structure)
2. [How each file works](#how-each-file-works)
3. [Target applications](#target-applications)
4. [Setup](#setup)
5. [Running the fuzzer — step by step](#running-the-fuzzer--step-by-step)
6. [CLI reference](#cli-reference)
7. [Understanding the output](#understanding-the-output)
8. [Results on disk](#results-on-disk)
9. [Mutation strategies explained](#mutation-strategies-explained)
10. [Bug classification](#bug-classification)
11. [Sample run results](#sample-run-results)
12. [Extending the fuzzer](#extending-the-fuzzer)

---

## Project structure

```
format-based-fuzzer/
├── fuzzer.py               # Main fuzzer — loads seeds, runs mutations, logs results
├── mutations.py            # All AFL-style mutation strategies
├── test_driver.py          # Runs a binary with one input, returns a classified result
├── smoke_test.py           # Quick 5-input sanity check
├── corpus/
│   ├── ipv4_seeds.txt      # 8 valid IPv4 seed inputs (from the spec)
│   └── ipv6_seeds.txt      # 14 valid IPv6 seed inputs (from the spec)
├── results/                # Created automatically when the fuzzer runs
│   ├── ipv4/
│   │   ├── bugs.jsonl      # Every interesting result, one JSON object per line
│   │   ├── stats.txt       # Final statistics written at the end of each run
│   │   └── crashes/        # One .txt file saved per unique crashing input
│   └── ipv6/
│       ├── bugs.jsonl
│       ├── stats.txt
│       └── crashes/
└── ipv4ipv6/
    ├── win-ipv4-parser.exe
    ├── win-ipv6-parser.exe
    └── README.md           # Spec: valid inputs, expected outputs, RFC references
```

---

## How each file works

### `mutations.py`

The mutation library. Contains two categories of mutation, matching AFL's pipeline:

**Deterministic mutations** — exhaustive, applied to every position in the input:

| Function | What it does |
|---|---|
| `bit_flip_1(data)` | Returns one variant per bit, with that bit flipped |
| `bit_flip_2(data)` | Returns one variant per pair of consecutive bits, both flipped |
| `bit_flip_4(data)` | Returns one variant per group of 4 consecutive bits, all flipped |
| `byte_flip_1(data)` | XORs each byte with `0xFF` (inverts it) |
| `byte_flip_2(data)` | XORs each pair of consecutive bytes with `0xFF` |
| `byte_flip_4(data)` | XORs each group of 4 consecutive bytes with `0xFF` |
| `arith_8(data)` | Adds and subtracts 1–35 to each byte (wrapping at 255/0) |
| `arith_16(data)` | Adds and subtracts 1–35 to each 16-bit word (little-endian) |
| `interesting_8(data)` | Substitutes each byte with values from `{0, 1, 16, 32, 64, 127, 128, 129, 255}` |
| `interesting_16(data)` | Substitutes each 16-bit word with boundary values like `{0, 256, 32767, 65535}` |
| `deterministic_mutations(data)` | Calls all of the above and returns the combined list |

**Havoc mutations** — random, stacked:

| Function | What it does |
|---|---|
| `havoc(data, count, seed)` | Generates `count` variants; each applies 1–8 randomly chosen ops stacked together |

The 9 havoc ops are: random bit flip, random byte replace, arithmetic nudge, interesting 8-bit value, interesting 16-bit value, byte delete, byte insert, chunk clone/duplicate, chunk overwrite with random bytes.

All functions take a `bytearray` and return `list[bytearray]`. The fuzzer decodes each `bytearray` to a UTF-8 string (with `errors='replace'`) before passing it to the test driver.

---

### `test_driver.py`

The test driver is the bridge between the fuzzer and the target binaries. For a given `(target, input_string)` pair it:

1. Builds the command `win-ipv4-parser.exe --ipstr <input_string>` (or `win-ipv6-parser.exe`)
2. Runs it via `subprocess.run` with `stdin=DEVNULL` (required — the binary hangs if stdin is open)
3. Waits up to 60 seconds (the binaries are PyInstaller bundles that unpack Python on startup, taking ~20–30 s each)
4. Parses stdout/stderr using regex to find the `Final bug count:` line and any `TRACEBACK` block
5. Returns a `RunResult` dataclass with fields: `input_str`, `bug_type`, `exit_code`, `stdout`, `stderr`, `exception_msg`, `traceback`

**Key classes and functions:**

| Name | Type | Purpose |
|---|---|---|
| `BugType` | class | String constants for each result class (`PASS`, `validity`, `invalidity`, `bonus`, `CRASH`, `TIMEOUT`) |
| `RunResult` | dataclass | Holds everything about one run; `.is_interesting` is `True` for any non-PASS result |
| `run(target, input_str)` | function | The main entry point — call this to test one input |
| `_parse_output(stdout, stderr)` | function | Internal — extracts bug type and exception message from raw binary output |

Can also be used as a standalone CLI:

```
python test_driver.py ipv4 "1.2.3.4"
python test_driver.py ipv6 "2001:db8::1"
```

This prints the full classified result including stdout and any traceback.

---

### `fuzzer.py`

The main orchestrator. Ties together the corpus, mutations, and test driver into a loop.

**How it works internally:**

1. `load_seeds(target)` — reads `corpus/<target>_seeds.txt`, returns a list of strings
2. `setup_results_dir(target)` — creates `results/<target>/crashes/` if it doesn't exist
3. `Fuzzer.run_deterministic()` — for each seed, calls `deterministic_mutations()` to get all variants, then calls `_test()` on each one
4. `Fuzzer.run_havoc()` — for each seed, calls `havoc(data, count=N)` to get N random variants, then calls `_test()` on each
5. `Fuzzer._test(input_bytes)` — decodes bytes to string, calls `test_driver.run()`, increments counters, prints findings with `[NEW]` tag if the exception message has not been seen before, and calls `save_result()` for any non-PASS result
6. `Fuzzer.print_summary()` — prints totals to console and writes `results/<target>/stats.txt`

**Key class:**

| Method | Purpose |
|---|---|
| `Fuzzer(target, havoc_iters, rng_seed)` | Constructor — loads seeds, sets up output dir |
| `fuzz(det=True, havoc_stage=True)` | Run the full fuzzing campaign |
| `run_deterministic()` | Deterministic stage only |
| `run_havoc()` | Havoc stage only |
| `print_summary()` | Print and save final statistics |

---

### `smoke_test.py`

A minimal script that runs 5 hand-picked inputs through the test driver and prints one line per result. Use this to verify the setup is working before starting a long fuzzer run. Takes about 2 minutes to complete (5 × ~25 s per binary invocation).

```
python smoke_test.py
```

Expected output:
```
  [PASS        ] '1.2.3.4'                                  | (none)
  [validity    ] '255.255.255.255'                          | Expected '.', found '5' ...
  [invalidity  ] '192.123249324.3242334.2343'               | Expected '.', found '249324' ...
  [invalidity  ] '999.999.999.999'                          | Expected '.', found '9' ...
  [invalidity  ] 'abc.def.ghi.jkl'                          | (none)
```

---

### `corpus/ipv4_seeds.txt` and `corpus/ipv6_seeds.txt`

Plain text files, one seed input per line. These are all taken directly from the valid input examples in `ipv4ipv6/README.md`. The fuzzer loads these as starting points — every mutation is derived by byte-level transformation of one of these seeds.

To add more seeds, just append a new line. The fuzzer picks them up automatically on the next run.

---

## Target applications

| Binary | Input | Output (valid) | Output (bug) |
|---|---|---|---|
| `win-ipv4-parser.exe` | `--ipstr <dotted-decimal>` | `Output: [<integer>]` + `No bugs found` | `TRACEBACK` block + `Final bug count: {...}` |
| `win-ipv6-parser.exe` | `--ipstr <colon-hex>` | `Output: [<integer>]` + `No bugs found` | `TRACEBACK` block + `Final bug count: {...}` |

> **Important:** Both `.exe` files are PyInstaller one-file bundles. Every invocation extracts ~24 MB of Python to a temp directory before running. This means each test takes **~20–30 seconds** on Windows. There is no way to speed this up — plan test budgets accordingly.

---

## Setup

Python 3.10 or newer is required. No third-party packages are needed.

```bash
# Clone the repo
git clone <repo-url>
cd format-based-fuzzer

# Verify Python version
python --version   # must be 3.10+

# Confirm the binaries exist
ls ipv4ipv6/
# should show: win-ipv4-parser.exe  win-ipv6-parser.exe  ...
```

---

## Running the fuzzer — step by step

### Step 1 — Verify the test driver works

Run the smoke test first. If any result shows `TIMEOUT` the binary is taking longer than 60 seconds to start — increase `TIMEOUT_SECONDS` in `test_driver.py`.

```bash
python smoke_test.py
```

Takes ~2 minutes. If you see PASS, validity, and invalidity results, everything is working.

### Step 2 — Test a single input manually

Use the test driver directly to inspect one input in detail:

```bash
python test_driver.py ipv4 "192.168.1.1"
python test_driver.py ipv4 "999.0.0.1"
python test_driver.py ipv6 "2001:db8::1"
python test_driver.py ipv6 "gggg::1"
```

### Step 3 — Run a quick havoc-only fuzzer demo

This is the fastest way to see the fuzzer producing results. With `--havoc-iters 5` and 8 seeds it generates 40 test cases:

```bash
# IPv4, 5 random mutations per seed (~17 minutes)
python fuzzer.py ipv4 --havoc-only --havoc-iters 5

# IPv6, 5 random mutations per seed (~17 minutes)
python fuzzer.py ipv6 --havoc-only --havoc-iters 5

# Both targets back-to-back
python fuzzer.py all --havoc-only --havoc-iters 5
```

### Step 4 — Run more havoc iterations

More iterations = more coverage. Each extra iteration per seed adds ~25 seconds per seed to the total runtime.

```bash
# 20 mutations per seed across both targets (~5.5 hours total)
python fuzzer.py all --havoc-only --havoc-iters 20 --seed 42
```

### Step 5 — Run the deterministic stage

The deterministic stage is exhaustive — it generates every possible single-position mutation. For a 7-byte seed like `1.2.3.4` this produces ~800 variants. Across all 8 IPv4 seeds that is roughly 6400 deterministic test cases (~45 hours).

```bash
# Deterministic stage only (very slow — run overnight or over a weekend)
python fuzzer.py ipv4 --det
```

### Step 6 — Full run (deterministic + havoc)

```bash
python fuzzer.py ipv4
python fuzzer.py ipv6
```

### Step 7 — Check the results

```bash
# View all logged findings
cat results/ipv4/bugs.jsonl

# View the final stats summary
cat results/ipv4/stats.txt

# List all saved crash inputs
ls results/ipv4/crashes/

# Print the contents of a crash file
cat results/ipv4/crashes/crash_000001.txt
```

---

## CLI reference

```
python fuzzer.py <target> [options]
```

| Argument | Values | Default | Description |
|---|---|---|---|
| `target` | `ipv4`, `ipv6`, `all` | required | Which parser binary to fuzz. `all` runs both sequentially. |
| `--havoc-iters N` | integer | `20` | Number of havoc mutations generated per seed. |
| `--seed N` | integer | `42` | RNG seed. Use the same seed to reproduce an identical run. |
| `--det` | flag | off | Run the deterministic stage only, skip havoc. |
| `--havoc-only` | flag | off | Run the havoc stage only, skip deterministic. |

**Time estimates** (based on ~25 s per binary invocation):

| Command | Test cases | Approx. time |
|---|---|---|
| `fuzzer.py ipv4 --havoc-only --havoc-iters 5` | 40 | ~17 min |
| `fuzzer.py ipv4 --havoc-only --havoc-iters 20` | 160 | ~67 min |
| `fuzzer.py all --havoc-only --havoc-iters 5` | 110 (8+14 seeds×5) | ~46 min |
| `fuzzer.py ipv4 --det` (one seed, e.g. `1.2.3.4`) | ~800 per seed | ~6 hr per seed |

---

## Understanding the output

During a run, each interesting finding is printed like this:

```
  [NEW] invalidity   | input='0p0.0.0'     | "Expected '.', found 'p0'  (at char 1)" | t=40.0s
        invalidity   | input='0p1.0.0'     | "Expected '.', found 'p1'  (at char 1)" | t=65.2s
  [NEW] CRASH        | input='0\x00\x01.0' | 'embedded null character'               | t=0.0s
```

| Column | Meaning |
|---|---|
| `[NEW]` / blank | `[NEW]` means this exact exception message has not appeared before in this run. Blank means it's a repeat of an already-seen exception. |
| Bug type | See [Bug classification](#bug-classification) below |
| `input=` | The mutated string passed to `--ipstr`. Non-printable bytes shown as `\xNN`. |
| Exception message | Extracted from the `Final bug count:` line in the binary's output |
| `t=` | Seconds elapsed since the fuzzer started |

At the end of every run a summary is printed:

```
============================================================
  Fuzzing summary for ipv4
============================================================
  Total inputs tested : 40
  Elapsed time        : 723.4s
  Inputs / second     : 0.1
  Bug counts:
    CRASH           : 9
    bonus           : 18
    invalidity      : 12
    validity        : 1
  Unique exceptions   : 20
  Results saved to    : results\ipv4
============================================================
```

---

## Results on disk

### `results/<target>/bugs.jsonl`

Every non-PASS result is appended here as a JSON object. Example:

```json
{"idx": 3, "input": "0p0.0.0", "bug_type": "invalidity", "exit_code": 0, "exception": "Expected '.', found 'p0'  (at char 1), (line:1, col:2)"}
{"idx": 1, "input": "0\u0000\u0001.0/0", "bug_type": "CRASH", "exit_code": 0, "exception": "embedded null character"}
```

You can query it with standard tools:

```bash
# Count each bug type
python -c "import json; from collections import Counter; [print(k,v) for k,v in Counter(json.loads(l)['bug_type'] for l in open('results/ipv4/bugs.jsonl')).items()]"

# Print all bonus bugs
python -c "import json; [print(json.loads(l)['input']) for l in open('results/ipv4/bugs.jsonl') if json.loads(l)['bug_type']=='bonus']"
```

### `results/<target>/crashes/`

Each unique crashing input is saved as a separate `.txt` file named `crash_NNNNNN.txt` where `NNNNNN` is the test case index from that run. You can replay any crash directly:

```bash
python test_driver.py ipv4 "$(cat results/ipv4/crashes/crash_000001.txt)"
```

### `results/<target>/stats.txt`

A plain-text summary written at the end of each run. Overwrites the previous run's stats.

---

## Mutation strategies explained

All mutations treat the input as raw bytes — there is no awareness of dots, colons, or any IP address structure.

### Why byte-level mutations find bugs

A string like `1.2.3.4` is stored as bytes `31 2E 32 2E 33 2E 34`. Flipping a bit in `31` (`0` → `1`) turns it into a character the parser never expects. Replacing `.` (`2E`) with `0xFF` destroys the delimiter structure. These transformations systematically probe all the edge cases the parser must handle.

### Deterministic stage

Runs every possible single-position mutation of the input. For a 7-byte string this generates approximately:
- bit_flip_1: 56 variants
- bit_flip_2: 55 variants
- bit_flip_4: 53 variants
- byte_flip_1: 7 variants
- byte_flip_2: 6 variants
- byte_flip_4: 4 variants
- arith_8: 7 × 35 × 2 = 490 variants
- arith_16: 6 × 35 × 2 = 420 variants
- interesting_8: 7 × 10 = 70 variants
- interesting_16: 6 × 10 = 60 variants

**Total: ~1,221 variants per seed.**

### Havoc stage

Each havoc iteration applies 1–8 randomly chosen ops stacked together. The 9 available ops are:

| Op | Description |
|---|---|
| Random bit flip | Flips one bit at a random position |
| Random byte replace | Sets one byte to a completely random value (0–255) |
| Arithmetic nudge | Adds or subtracts a random value (1–35) from one byte |
| Interesting 8-bit | Replaces one byte with a known boundary value |
| Interesting 16-bit | Replaces a 16-bit word with a known boundary value |
| Byte delete | Removes one byte, shrinking the input |
| Byte insert | Inserts one random byte, growing the input |
| Chunk clone | Copies a random slice of the input and inserts it elsewhere |
| Chunk overwrite | Overwrites a random slice with random bytes |

Stacking multiple ops per iteration creates complex, unpredictable mutations that a single-step deterministic pass would never produce.

---

## Bug classification

The binary's output always includes a `Final bug count:` line. The test driver parses it with regex to extract the bug type key.

| Class | Source | Meaning |
|---|---|---|
| `PASS` | `No bugs found` in output | Input was accepted and parsed successfully |
| `validity` | `('validity', ...)` in bug count | **Real bug** — a valid input (per spec) was falsely rejected by the parser |
| `invalidity` | `('invalidity', ...)` in bug count | Expected behaviour — an invalid input was correctly rejected with a `ParseException` |
| `bonus` | `('bonus', ...)` in bug count | An unexpected or unhandled exception was triggered — more interesting than invalidity |
| `CRASH` | Non-zero exit code or launch failure | Hard crash or the binary could not handle the input at OS level |
| `TIMEOUT` | Process did not finish within 60 s | Input caused the binary to hang |

`validity` and `bonus` are the most valuable findings. `invalidity` confirms the parser is rejecting garbage, which is expected. `CRASH` may indicate a memory safety issue.

---

## Sample run results

**Command:** `python fuzzer.py ipv4 --havoc-only --havoc-iters 5 --seed 42`
(40 test cases, ~12 minutes)

```
Bug counts:
  CRASH           : 9    ← null bytes in input cause "embedded null character" errors
  bonus           : 18   ← unexpected exceptions, including codec/encoding errors
  invalidity      : 12   ← parser correctly rejected malformed input
  validity        : 1    ← real bug: valid input falsely rejected

Unique exceptions : 20
```

### Notable finding — `validity` bug

`255.255.255.255` is listed as valid in `ipv4ipv6/README.md` but the parser returns:

```
A validity bug has been triggered: Expected '.', found '5'  (at char 2), (line:1, col:3)
Final bug count: {('validity', ParseException, "Expected '.', found '5' ...", ...): 1}
```

The parser incorrectly rejects the maximum IPv4 address. This is a genuine defect in the target.

---

## Extending the fuzzer

**Add more seeds:**
Append new lines to `corpus/ipv4_seeds.txt` or `corpus/ipv6_seeds.txt`. Both files are loaded fresh on every run.

**Add a new mutation:**
Write a function in `mutations.py` that takes a `bytearray` and returns `list[bytearray]`, then call it from `deterministic_mutations()`:

```python
def my_mutation(data: bytearray) -> list[bytearray]:
    results = []
    # ... generate variants ...
    return results

def deterministic_mutations(data: bytearray) -> list[bytearray]:
    results = []
    ...
    results.extend(my_mutation(data))   # add this line
    return results
```

**Add a new target binary:**
Register it in `test_driver.py`'s `_BINARIES` dict and add a seed file to `corpus/`:

```python
_BINARIES = {
    "ipv4": _HERE / "ipv4ipv6" / "win-ipv4-parser.exe",
    "ipv6": _HERE / "ipv4ipv6" / "win-ipv6-parser.exe",
    "myapp": _HERE / "myapp" / "win-myapp.exe",   # add this
}
```

Then create `corpus/myapp_seeds.txt` and run `python fuzzer.py myapp`.
