# Hybrid Coverage-Guided Fuzzer — Implementation Guide

> Targets: JSON, IPv4, IPv6 | Stack: Python 3.11+, AFL++ LTO, QEMU, PyTorch

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Module 1 — Input Format Config](#2-module-1--input-format-config)
3. [Module 2 — Grammar-Based Seed Generator](#3-module-2--grammar-based-seed-generator)
4. [Module 3 — Three-Tier Mutation Engine](#4-module-3--three-tier-mutation-engine)
5. [Module 4 — Execution Engine](#5-module-4--execution-engine)
6. [Module 5 — Coverage Analyzer](#6-module-5--coverage-analyzer)
7. [Module 6 — DL Scheduler (Phase 2)](#7-module-6--dl-scheduler-phase-2)
8. [Main Fuzzing Loop](#8-main-fuzzing-loop)
9. [Evaluation Harness](#9-evaluation-harness)
10. [Implementation Phases](#10-implementation-phases)

---

## 1. Project Structure

```
hybrid-fuzzer/
├── config/
│   ├── json_format.json          # Grammar + mutation rules for JSON
│   ├── ipv4_format.json          # Field specs + semantic rules for IPv4
│   └── ipv6_format.json          # Field specs + semantic rules for IPv6
│
├── fuzzer/
│   ├── __init__.py
│   ├── seed_generator.py         # Grammar-based valid seed generation
│   ├── mutation/
│   │   ├── __init__.py
│   │   ├── tier1_structure.py    # Structural mutations (JSON)
│   │   ├── tier2_semantic.py     # Protocol-aware mutations (IPv4/IPv6)
│   │   └── tier3_havoc.py        # Stochastic byte-level mutations
│   ├── executor.py               # AFL++ / QEMU subprocess wrapper
│   ├── coverage.py               # Edge bitmap tracking
│   ├── corpus.py                 # Seed queue management + priority scoring
│   └── scheduler.py             # DL scheduler (Phase 2) or static priors (Phase 1)
│
├── dl/
│   ├── surrogate.py              # Neural surrogate model (PyTorch)
│   ├── trainer.py                # Training loop + active learning resampling
│   └── trustworthiness.py        # Confidence gating before gradient use
│
├── evaluation/
│   ├── run_baselines.sh          # Spin up AFL, AFLFast, AFL++, NEUZZ
│   └── collect_metrics.py        # Coverage, crashes, paths, time-to-first-bug
│
├── targets/
│   ├── json_parser/              # White-box target (compiled with AFL++ LTO)
│   └── ipv4_parser/              # Black-box binary target (QEMU mode)
│
├── main.py                       # Entry point
└── requirements.txt
```

---

## 2. Module 1 — Input Format Config

Each format is a JSON config that drives the entire pipeline. Adding a new format (e.g., XML) only requires a new config file — no engine changes.

**`config/json_format.json`**
```json
{
  "format": "JSON",
  "grammar": "grammars/json_grammar.ebnf",
  "structure_rules": ["add_key", "delete_key", "nest_object", "array_expand", "deep_recurse"],
  "semantic_rules": ["type_mutation", "array_contraction"],
  "havoc_operators": {
    "bit_flip":        0.20,
    "byte_substitute": 0.20,
    "splice":          0.20,
    "arithmetic":      0.20,
    "delete_range":    0.10,
    "insert_random":   0.10
  }
}
```

**`config/ipv4_format.json`**
```json
{
  "format": "IPv4",
  "fields": ["version", "ihl", "dscp", "total_length", "id", "flags",
             "fragment_offset", "ttl", "protocol", "checksum", "src_ip", "dst_ip"],
  "semantic_rules": ["ttl_walk", "protocol_invalid", "length_mismatch",
                     "fragment_flags", "checksum_corrupt"],
  "havoc_operators": {
    "ttl_boundary":      0.20,
    "length_mismatch":   0.18,
    "fragment_flags":    0.15,
    "protocol_invalid":  0.12,
    "bit_flip":          0.20,
    "byte_substitute":   0.15
  }
}
```

**Loading configs:**
```python
# fuzzer/format_loader.py
import json
from pathlib import Path

def load_format(name: str) -> dict:
    path = Path("config") / f"{name.lower()}_format.json"
    return json.loads(path.read_text())
```

---

## 3. Module 2 — Grammar-Based Seed Generator

**Goal:** Produce 100% syntactically valid seeds so mutations start from a valid state, not random bytes.

### JSON Seed Generation

Use a recursive EBNF walker rather than a library like Hypothesis — you need control over depth and size.

```python
# fuzzer/seed_generator.py
import json
import random

class JSONSeedGenerator:
    def __init__(self, max_depth: int = 4, max_keys: int = 5):
        self.max_depth = max_depth
        self.max_keys = max_keys

    def generate(self, depth: int = 0) -> dict | list | str | int | float | bool | None:
        if depth >= self.max_depth:
            return self._generate_leaf()
        kind = random.choice(["object", "array", "leaf"])
        if kind == "object":
            return {
                self._random_key(): self.generate(depth + 1)
                for _ in range(random.randint(1, self.max_keys))
            }
        elif kind == "array":
            return [self.generate(depth + 1) for _ in range(random.randint(0, 4))]
        return self._generate_leaf()

    def _generate_leaf(self):
        return random.choice([
            random.randint(-2**31, 2**31),
            round(random.uniform(-1e6, 1e6), 4),
            self._random_string(),
            True, False, None
        ])

    def _random_key(self) -> str:
        keys = ["id", "name", "value", "data", "user", "age", "type", "items"]
        return random.choice(keys)

    def _random_string(self) -> str:
        length = random.randint(0, 32)
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz_0123456789', k=length))

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        return [json.dumps(self.generate()).encode() for _ in range(n)]
```

### IPv4 Seed Generation

Use `scapy` to construct valid packets with correct checksums from the start.

```python
from scapy.all import IP, Raw
import random

class IPv4SeedGenerator:
    def generate(self) -> bytes:
        pkt = IP(
            ttl=random.randint(1, 255),
            proto=random.choice([6, 17, 1]),   # TCP, UDP, ICMP
            dst="192.168.1.1"
        ) / Raw(load=bytes(random.randint(0, 64)))
        return bytes(pkt)   # scapy auto-computes checksum + length

    def generate_corpus(self, n: int = 100) -> list[bytes]:
        return [self.generate() for _ in range(n)]
```

---

## 4. Module 3 — Three-Tier Mutation Engine

All three tiers share a common interface: they accept `bytes` in and return mutated `bytes` out. The main loop stacks tiers in order: Tier 1 → Tier 2 → Tier 3 (Havoc).

### Tier 1 — Structure Mutations (JSON)

**Key operations:** key insertion/deletion, nesting, array expansion, deep recursion.

```python
# fuzzer/mutation/tier1_structure.py
import json, random, copy

class StructureMutator:
    def mutate(self, data: bytes) -> bytes:
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            return data   # pass through invalid inputs unchanged

        op = random.choice([
            self._add_key, self._delete_key, self._nest_value,
            self._expand_array, self._deep_recurse
        ])
        mutated = op(copy.deepcopy(obj))
        return json.dumps(mutated).encode()

    def _add_key(self, obj):
        if isinstance(obj, dict):
            obj[f"fuzz_{random.randint(0, 9999)}"] = random.choice([0, "", None, [], {}])
        return obj

    def _delete_key(self, obj):
        if isinstance(obj, dict) and obj:
            obj.pop(random.choice(list(obj.keys())))
        return obj

    def _nest_value(self, obj):
        if isinstance(obj, dict) and obj:
            k = random.choice(list(obj.keys()))
            obj[k] = {"nested": obj[k], "extra": None}
        return obj

    def _expand_array(self, obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, list):
                    v.extend([None] * random.randint(1, 10))
                    break
        return obj

    def _deep_recurse(self, obj, depth: int = 0):
        # Wrap the entire object in N levels of nesting
        levels = random.randint(1, 5)
        result = obj
        for _ in range(levels):
            result = {"data": result}
        return result
```

### Tier 2 — Semantic Mutations (IPv4/IPv6)

**Key operations:** TTL walk, fragment flags, checksum corruption, protocol edge cases.

```python
# fuzzer/mutation/tier2_semantic.py
import random
from scapy.all import IP, Raw

class IPv4SemanticMutator:
    OPERATIONS = ["ttl_walk", "fragment_flags", "length_mismatch",
                  "protocol_invalid", "checksum_corrupt"]

    def mutate(self, data: bytes) -> bytes:
        op = random.choice(self.OPERATIONS)
        return getattr(self, f"_{op}")(data)

    def _ttl_walk(self, data: bytes) -> bytes:
        pkt = IP(data)
        pkt.ttl = random.choice([0, 1, 64, 128, 254, 255])
        return bytes(pkt)

    def _fragment_flags(self, data: bytes) -> bytes:
        pkt = IP(data)
        pkt.flags = random.choice([0, 1, 2, 3])   # DF, MF, combinations
        pkt.frag = random.randint(0, 8191)
        del pkt.chksum                              # force scapy to recompute
        return bytes(pkt)

    def _length_mismatch(self, data: bytes) -> bytes:
        pkt = IP(data)
        pkt.len = random.choice([0, 1, 65535])     # claim wrong length
        del pkt.chksum
        return bytes(pkt)

    def _protocol_invalid(self, data: bytes) -> bytes:
        pkt = IP(data)
        pkt.proto = random.choice([143, 200, 253, 254, 255])  # reserved/unassigned
        del pkt.chksum
        return bytes(pkt)

    def _checksum_corrupt(self, data: bytes) -> bytes:
        pkt = IP(data)
        pkt.chksum = random.randint(0, 65535)      # intentionally wrong
        return bytes(pkt)
```

### Tier 3 — Havoc (Byte-Level, All Formats)

Havoc stacks multiple operators in a single mutation pass. The operator selection is weighted by either static priors (Phase 1) or DL-learned weights (Phase 2) — the interface is identical.

```python
# fuzzer/mutation/tier3_havoc.py
import random
import struct

class HavocMutator:
    def __init__(self, operator_weights: dict[str, float]):
        self.operators = list(operator_weights.keys())
        self.weights = list(operator_weights.values())

    def mutate(self, data: bytes, iterations: int = 8) -> bytes:
        buf = bytearray(data)
        for _ in range(iterations):
            op = random.choices(self.operators, weights=self.weights, k=1)[0]
            buf = self._apply(buf, op)
        return bytes(buf)

    def _apply(self, buf: bytearray, op: str) -> bytearray:
        if not buf:
            return buf
        idx = random.randint(0, len(buf) - 1)

        match op:
            case "bit_flip":
                buf[idx] ^= (1 << random.randint(0, 7))
            case "byte_substitute":
                buf[idx] = random.randint(0, 255)
            case "arithmetic":
                val = (buf[idx] + random.choice([-35, -1, 1, 35])) & 0xFF
                buf[idx] = val
            case "splice":
                if len(buf) > 4:
                    mid = random.randint(1, len(buf) - 1)
                    buf = buf[:mid] + buf[mid:]   # noop structurally; extend with corpus later
            case "delete_range":
                end = min(idx + random.randint(1, 8), len(buf))
                del buf[idx:end]
            case "insert_random":
                ins = bytes([random.randint(0, 255) for _ in range(random.randint(1, 8))])
                buf[idx:idx] = ins
            case "interesting_byte":
                buf[idx] = random.choice([0, 0x7F, 0x80, 0xFF])
        return buf
```

---

## 5. Module 4 — Execution Engine

Wraps AFL++ (white-box) or QEMU (black-box) as a subprocess. Both modes return a coverage bitmap and a crash flag.

```python
# fuzzer/executor.py
import subprocess, os, tempfile
from pathlib import Path

SHMEM_SIZE = 65536   # AFL++ standard bitmap size

class Executor:
    def __init__(self, target_binary: str, mode: str = "whitebox",
                 timeout_ms: int = 1000):
        self.binary = target_binary
        self.mode = mode
        self.timeout = timeout_ms / 1000
        self.shmem_id = self._setup_shm()

    def run(self, input_data: bytes) -> tuple[bytes, bool]:
        """Returns (coverage_bitmap, crashed)."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(input_data)
            input_path = f.name

        env = os.environ.copy()
        env["__AFL_SHM_ID"] = str(self.shmem_id)

        cmd = [self.binary, input_path]
        if self.mode == "blackbox":
            cmd = ["qemu-x86_64"] + cmd

        try:
            result = subprocess.run(
                cmd, timeout=self.timeout,
                capture_output=True, env=env
            )
            crashed = result.returncode in (-11, -6, 134)   # SIGSEGV, SIGABRT
        except subprocess.TimeoutExpired:
            crashed = False
        finally:
            os.unlink(input_path)

        bitmap = self._read_shm()
        return bitmap, crashed

    def _setup_shm(self) -> int:
        # In production: use sysv_ipc or posix_ipc for shared memory
        # Simplified here — replace with actual SHM setup
        return 0

    def _read_shm(self) -> bytes:
        # Read AFL bitmap from shared memory segment
        # Returns 64KB bytes representing edge hit counts
        return bytes(SHMEM_SIZE)
```

> **Note:** For actual AFL++ integration, use `python-afl` or pipe inputs via `afl-fuzz -i - -o out -- ./target @@`. The subprocess wrapper above is a simplification for unit testing the pipeline.

---

## 6. Module 5 — Coverage Analyzer

Tracks the global edge bitmap. A seed is "interesting" if it flips any previously-zero bit.

```python
# fuzzer/coverage.py

class CoverageAnalyzer:
    def __init__(self):
        self.global_bitmap = bytearray(65536)
        self.edge_count = 0

    def is_interesting(self, bitmap: bytes) -> bool:
        """Returns True if this run covered any new edge."""
        new_edges = False
        for i, byte in enumerate(bitmap):
            if byte and not self.global_bitmap[i]:
                self.global_bitmap[i] = byte
                self.edge_count += 1
                new_edges = True
        return new_edges

    def coverage_summary(self) -> dict:
        return {
            "edges_covered": self.edge_count,
            "bitmap_density": self.edge_count / 65536
        }
```

---

## 7. Module 6 — DL Scheduler (Phase 2)

> **Phase 1:** Skip this module. Use static `havoc_operators` weights from the format config.  
> **Phase 2:** Swap in this module — the mutation engine interface is unchanged.

### Surrogate Model

```python
# dl/surrogate.py
import torch
import torch.nn as nn

class CoverageSurrogate(nn.Module):
    """
    Input:  flattened seed bytes (padded/truncated to MAX_LEN)
    Output: predicted edge coverage bitmap (65536 bits → 65536 sigmoid outputs)
    
    In practice, predict a compressed coverage representation (e.g., 512-dim)
    to keep the output tractable.
    """
    MAX_LEN = 1024
    COV_DIM = 512    # compressed coverage representation

    def __init__(self):
        super().__init__()
        self.embed = nn.Embedding(256, 8)
        self.encoder = nn.Sequential(
            nn.Flatten(),
            nn.Linear(self.MAX_LEN * 8, 1024),
            nn.ReLU(),
            nn.Linear(1024, 512),
            nn.ReLU(),
        )
        self.coverage_head = nn.Linear(512, self.COV_DIM)
        self.confidence_head = nn.Linear(512, 1)    # trustworthiness score

    def forward(self, x: torch.Tensor):
        # x: (batch, MAX_LEN) int tensor of byte values
        emb = self.embed(x)                         # (batch, MAX_LEN, 8)
        h = self.encoder(emb)
        coverage = torch.sigmoid(self.coverage_head(h))
        confidence = torch.sigmoid(self.confidence_head(h))
        return coverage, confidence
```

### Trustworthiness Gate

```python
# dl/trustworthiness.py

CONFIDENCE_THRESHOLD = 0.75

def is_trustworthy(confidence_score: float) -> bool:
    """
    Gate from SMU DL Survey Fig. 6.
    Only use gradient guidance when the model is confident.
    Falls back to Havoc with static priors otherwise.
    """
    return confidence_score >= CONFIDENCE_THRESHOLD
```

### Hot Byte Identification

```python
# dl/surrogate.py (continued)
import torch

def identify_hot_bytes(model, seed: bytes, device="cpu") -> list[int]:
    """
    Compute gradient of predicted coverage w.r.t. each input byte position.
    Returns sorted list of byte indices most likely to increase coverage.
    """
    MAX_LEN = CoverageSurrogate.MAX_LEN
    padded = list(seed[:MAX_LEN]) + [0] * (MAX_LEN - len(seed))
    x = torch.tensor([padded], dtype=torch.long, device=device)
    x.requires_grad_(False)

    # Use embedding gradients as proxy for byte importance
    embed = model.embed(x).float()
    embed.retain_grad()
    embed.requires_grad_(True)

    coverage, _ = model.coverage_head(model.encoder(embed.view(1, -1))), None
    coverage.sum().backward()

    importance = embed.grad.abs().sum(dim=-1).squeeze()  # (MAX_LEN,)
    hot_bytes = importance.argsort(descending=True).tolist()
    return [i for i in hot_bytes if i < len(seed)]
```

### Scheduler Outputs

The DL scheduler produces three outputs consumed by the main loop:

```python
# fuzzer/scheduler.py

class DLScheduler:
    def __init__(self, model, trust_gate, format_config: dict):
        self.model = model
        self.trust_gate = trust_gate
        self.static_weights = format_config["havoc_operators"]   # fallback

    def get_operator_weights(self, seed: bytes) -> dict[str, float]:
        """Returns havoc operator weights — learned or static."""
        coverage, confidence = self.model(self._encode(seed))
        if self.trust_gate(confidence.item()):
            return self._learned_weights(coverage)
        return self.static_weights  # fallback to hand-coded priors

    def get_seed_priority(self, seed: bytes) -> float:
        """Score for corpus seed ordering."""
        _, confidence = self.model(self._encode(seed))
        return confidence.item()

    def get_field_importance(self, seed: bytes) -> list[int]:
        """Hot byte positions for targeted mutation."""
        return identify_hot_bytes(self.model, seed)

    def _encode(self, seed: bytes) -> torch.Tensor:
        MAX_LEN = CoverageSurrogate.MAX_LEN
        padded = list(seed[:MAX_LEN]) + [0] * (MAX_LEN - len(seed))
        return torch.tensor([padded], dtype=torch.long)
```

---

## 8. Main Fuzzing Loop

```python
# main.py
import time
import json
from fuzzer.corpus import Corpus
from fuzzer.seed_generator import JSONSeedGenerator, IPv4SeedGenerator
from fuzzer.mutation.tier1_structure import StructureMutator
from fuzzer.mutation.tier2_semantic import IPv4SemanticMutator
from fuzzer.mutation.tier3_havoc import HavocMutator
from fuzzer.executor import Executor
from fuzzer.coverage import CoverageAnalyzer
from fuzzer.format_loader import load_format

def fuzz(target: str, format_name: str, mode: str = "whitebox",
         time_budget_secs: int = 86400):

    fmt = load_format(format_name)
    corpus = Corpus()

    # --- Seed generation ---
    generator = JSONSeedGenerator() if format_name == "json" else IPv4SeedGenerator()
    for seed in generator.generate_corpus(n=100):
        corpus.add(seed, priority=1.0)

    # --- Mutation engine setup ---
    tier1 = StructureMutator() if format_name == "json" else None
    tier2 = IPv4SemanticMutator() if format_name in ("ipv4", "ipv6") else None
    tier3 = HavocMutator(fmt["havoc_operators"])

    # --- Infrastructure ---
    executor = Executor(target, mode=mode)
    coverage = CoverageAnalyzer()

    # --- Phase 2: swap in DL scheduler here ---
    scheduler = None  # placeholder; set to DLScheduler instance in Phase 2

    start = time.time()
    crashes = []

    while time.time() - start < time_budget_secs:
        seed = corpus.select()

        # Apply mutation tiers in order
        mutated = seed
        if tier1:
            mutated = tier1.mutate(mutated)
        if tier2:
            mutated = tier2.mutate(mutated)

        # Phase 2: use DL-guided operator weights; Phase 1: static weights
        if scheduler:
            weights = scheduler.get_operator_weights(seed)
            tier3 = HavocMutator(weights)

        mutated = tier3.mutate(mutated, iterations=8)

        # Execute and evaluate
        bitmap, crashed = executor.run(mutated)

        if crashed:
            crash_id = len(crashes)
            crash_path = f"crashes/crash_{crash_id}.bin"
            with open(crash_path, "wb") as f:
                f.write(mutated)
            crashes.append(crash_path)
            print(f"[CRASH] #{crash_id} — saved to {crash_path}")

        if coverage.is_interesting(bitmap):
            priority = scheduler.get_seed_priority(mutated) if scheduler else 1.0
            corpus.add(mutated, priority=priority)
            print(f"[NEW PATH] edges={coverage.edge_count} corpus={len(corpus)}")

    print(f"\nDone. Crashes: {len(crashes)} | Edges: {coverage.edge_count}")
    print(coverage.coverage_summary())


if __name__ == "__main__":
    fuzz(
        target="./targets/json_parser/parser",
        format_name="json",
        mode="whitebox",
        time_budget_secs=3600
    )
```

### Corpus Manager

```python
# fuzzer/corpus.py
import random

class Corpus:
    def __init__(self):
        self.seeds: list[bytes] = []
        self.priorities: list[float] = []

    def add(self, seed: bytes, priority: float = 1.0):
        self.seeds.append(seed)
        self.priorities.append(priority)

    def select(self) -> bytes:
        """Priority-weighted seed selection."""
        return random.choices(self.seeds, weights=self.priorities, k=1)[0]

    def __len__(self):
        return len(self.seeds)
```

---

## 9. Evaluation Harness

### Metrics Collection

```python
# evaluation/collect_metrics.py
import time, subprocess, os
from dataclasses import dataclass, field

@dataclass
class FuzzMetrics:
    edges_covered: int = 0
    unique_paths: int = 0
    unique_crashes: int = 0
    time_to_first_bug: float | None = None
    wall_time_secs: float = 0.0
    crash_log: list[str] = field(default_factory=list)

def run_with_metrics(fuzzer_fn, *args, **kwargs) -> FuzzMetrics:
    metrics = FuzzMetrics()
    start = time.time()
    fuzzer_fn(*args, **kwargs, metrics=metrics)
    metrics.wall_time_secs = time.time() - start
    return metrics
```

### Ablation Configurations

| Config | Grammar | Tier 1 | Tier 2 | DL Scheduler |
|---|---|---|---|---|
| Baseline (AFL-style) | ✗ | ✗ | ✗ | ✗ |
| + Grammar | ✓ | ✗ | ✗ | ✗ |
| + Grammar + Structure | ✓ | ✓ | ✗ | ✗ |
| + Grammar + Structure + Semantic | ✓ | ✓ | ✓ | ✗ |
| Full Hybrid (proposed) | ✓ | ✓ | ✓ | ✓ |

Run each configuration with identical seed corpus, time budget (24h), and hardware. Report mean ± σ over 5 runs.

### Baseline Comparison Targets (NEUZZ Table VI parity)

```bash
# evaluation/run_baselines.sh
TARGETS="readelf nm objdump size strip"
TIME=86400   # 24h

for t in $TARGETS; do
  afl-fuzz -i seeds/ -o out_afl/$t/ -t 1000 -- ./targets/$t @@
  afl-fuzz -i seeds/ -o out_aflfast/$t/ -p fast -t 1000 -- ./targets/$t @@
  afl-fuzz++ -i seeds/ -o out_aflpp/$t/ -- ./targets/$t @@
  python main.py --target ./targets/$t --format json --time $TIME --out out_hybrid/$t/
done
```

---

## 10. Implementation Phases

### Phase 1 — Core Fuzzer (Implement First)

```
Week 1–2: Format configs + Grammar-based seed generation
Week 3–4: Tier 1 (Structure) + Tier 3 (Havoc) + static operator weights
Week 5:   Executor wrapper (AFL++ white-box mode)
Week 6:   Coverage analyzer + corpus manager + main loop
Week 7:   Tier 2 (Semantic mutations for IPv4/IPv6 via scapy)
Week 8:   Evaluation harness + baseline comparisons (AFL, AFL++, AFLSmart)
```

**Deliverable:** Fully functional fuzzer without DL. Havoc-primary with hand-coded weights per format.

### Phase 2 — DL Scheduler (Layer On Top)

```
Week 9–10:  Surrogate model training loop (PyTorch)
Week 11:    Trustworthiness gate + hot byte identification
Week 12:    Scheduler integration — replace static weights, same interface
Week 13–14: Full ablation study + DL model accuracy metrics
```

**Key design constraint:** Phase 2 touches *only* `scheduler.py` and `dl/`. The mutation engine and main loop are unchanged — the Phase 1 static weights and Phase 2 learned weights use the same `dict[str, float]` interface.

---

## Dependencies

```
# requirements.txt
scapy>=2.5.0          # IPv4/IPv6 packet construction + mutation
torch>=2.2.0          # Surrogate model (Phase 2)
numpy>=1.26.0         # Bitmap operations
python-afl>=0.8.0     # AFL++ Python bindings (optional)
```

**System dependencies:**
- `afl++` (compile from source for LTO mode)
- `qemu-user` (for black-box binary targets)
- `gdb` + `exploitable` plugin (crash triage)
