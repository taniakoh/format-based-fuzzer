# Improvements Log

Use this file to record meaningful improvements, refactors, feature additions, performance work, and reliability upgrades.

## 2026-03-26

### Hot-byte-guided mutation routing
Improvements:
- Added a generic `SemanticSpan` abstraction so Tier 2 mutators can expose meaningful regions of an input and bias edits toward DL-identified hot bytes.
- Updated the IPv4 and IPv6 semantic mutators to map hot-byte guidance back to octets, groups, separators, and insertion points instead of treating gradient output as raw byte edits.
- Extended Tier 3 havoc so it can bias mutation positions toward trusted hot bytes while preserving random exploration with a guided-versus-random mix.
- Wired the scheduler and main loop so hot-byte guidance is only emitted when the confidence gate trusts the model, then passed into both Tier 2 and Tier 3.
- Documented the routing design in the README as a format-generic extension point for future structured text targets such as stringified JSON.

Reasons:
- Shifted the DL model into an attention role where it says "look here" while structured mutators stay responsible for syntax-aware edits.
- Made the mutation pipeline easier to generalize beyond IPv4/IPv6 by separating byte saliency from format-specific interpretation.
- Preserved the conservative hybrid behavior inspired by Neuzz++ by keeping static mutation behavior available whenever the model is weak or untrusted.

Key files changed:
- `main.py`
- `dl/surrogate.py`
- `fuzzer/mutation/tier2_semantic.py`
- `fuzzer/mutation/tier3_havoc.py`
- `README.md`

### Conservative hybrid scheduler fallback
Improvements:
- Added a hybrid DL scheduler that keeps static mutation weights available at all times instead of switching permanently into learned behavior.
- Blended static and learned scheduling based on confidence, model warm-up state, and recent guided-versus-static performance.
- Persisted lightweight scheduler metadata in checkpoints so fallback maturity survives restarts.

Reasons:
- Made the scheduler more conservative when the learned signal is weak, sparse, or unstable.
- Documented the design rationale using the Neuzz++ motivation for guarded ML guidance on noisy feedback.

Key files changed:
- `main.py`
- `dl/surrogate.py`
- `dl/trainer.py`
- `README.md`

### Batched surrogate training
Improvements:
- Reworked surrogate training to pre-encode the observed seeds and bitmap targets into tensors before the training loop.
- Switched the trainer from one-sample-at-a-time optimization to mini-batch updates with `TensorDataset` and `DataLoader`.
- Added a configurable `batch_size` parameter while keeping the existing `train(...)` entry point compatible with `main.py`.

Reasons:
- Reduced Python and tensor construction overhead by building training tensors once per training run instead of once per sample.
- Improved hardware utilization, especially for GPU execution, by running matrix operations across batches rather than individual examples.
- Made gradient updates less noisy because each optimization step now sees multiple samples.

Key files changed:
- `dl/trainer.py`

### Run observability and campaign output layout
Improvements:
- Added startup logging that prints the selected executor mode and exact binary path at the start of every fuzzing run.
- Added a deduplicated `Unique bugs` metric in the run summary by counting distinct `(bug_type, exception_msg)` signatures.
- Expanded `results/<target>/` to include `fuzzer_config`, `fuzzer_stats`, `plot_data`, and a `queue/` directory for interesting corpus additions, while keeping `bugs.jsonl`, `crashes/`, and `stats.txt`.
- Recorded `plot_data` as CSV progress samples over relative time so campaign growth can be inspected or graphed later.

Reasons:
- Made it immediately obvious which binary the fuzzer actually selected, which helps catch Windows-versus-Linux execution mismatches early.
- Reduced confusion between repeated bug events and genuinely new bug classes by surfacing a unique bug count in the stats output.
- Brought the output layout closer to Neuzz++-style campaign artifacts so runs are easier to inspect, compare, and post-process.
- Preserved backward compatibility for existing scripts and workflows that still read `stats.txt` or `bugs.jsonl`.

Key files changed:
- `main.py`
- `evaluation/collect_metrics.py`

### Trained confidence target for DL trust gating
Improvements:
- Updated surrogate training so the `confidence_head` learns against an explicit per-sample quality target instead of remaining an untrained side output.
- Derived the confidence target from the overlap between the model's top-k predicted coverage bits and the true observed bitmap positions for each sample.
- Combined the existing coverage BCE loss with a lightly weighted confidence regression loss so coverage prediction stays primary while confidence learns prediction reliability.
- Kept the existing trust-gate flow, but grounded it in a score that now reflects observed coverage-prediction quality.

Reasons:
- Removed the mismatch where the scheduler treated confidence as meaningful even though training never taught that concept directly.
- Made the confidence score better aligned with the intended question: "how accurate is this model likely to be on inputs like this?"
- Improved honesty of the learned scheduling path without having to remove the confidence gate entirely.
- Preserved a simple path for later threshold tuning or calibration once more real fuzzing data is available.

Key files changed:
- `dl/trainer.py`
- `dl/surrogate.py`
- `dl/trustworthiness.py`
