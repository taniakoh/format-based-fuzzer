# Improvements Log

Use this file to record meaningful improvements, refactors, feature additions, performance work, and reliability upgrades.

## 2026-03-26

### Refresh README and pipeline docs for executor/oracle changes
Improvements:
- Updated `README.md` and `PIPELINE.md` to document the current executor modes, including Linux `QEMU` edge coverage via `afl-showmap` and the Linux fallback behavior-hash path.
- Documented the oracle-assisted bug classification flow, including the `oracle_mismatch` bug type and the current per-target oracle coverage.
- Corrected stale operational details such as Linux timeout values and current checkpoint/output expectations.

Reasons:
- The implementation has moved beyond the older Windows-only behavior-hash description, so the top-level docs needed to reflect how runs are actually executed today.
- Accurate docs make it much easier to interpret run artifacts and compare static, hybrid, and instrumented campaigns correctly.

Key files changed:
- `README.md`
- `PIPELINE.md`
- `improvements.md`

### One-command fresh restart flag
Improvements:
- Added a `--fresh-start` flag that clears `results/<target>/` and removes `models/<target>_surrogate.pt` before the campaign starts.
- Applied the reset per target, so `python main.py all --fresh-start ...` refreshes each target's run state consistently.

Reasons:
- Restarting experiments by hand was easy to do inconsistently, especially when comparing clean-start and warm-start behavior.
- A single reset flag reduces the chance of accidentally reusing stale artifacts or checkpoints.

Key files changed:
- `main.py`
- `README.md`

### Adaptive corpus energy for expensive targets
Improvements:
- Reworked the in-memory corpus so seed selection is no longer a fixed one-time priority draw and now accounts for seed freshness, historical success, recent reuse, and repeated failed attempts.
- Added execution feedback from the main fuzzing loop back into the corpus so parent seeds that stop producing new behaviors cool off while newly discovered seeds get extra attention early.
- Deduplicated identical seeds at corpus insert time and preserved the stronger base priority when the same seed is rediscovered.

Reasons:
- The opaque parser binaries are expensive to execute, so repeatedly sampling stale seeds wastes a large fraction of the total time budget.
- A dynamic queue makes the campaign spend more of its limited executions around recently productive areas of the input space instead of treating every old seed as equally valuable forever.

Key files changed:
- `fuzzer/corpus.py`
- `main.py`

### Add cidrize target with dedicated semantic mutations
Improvements:
- Added a new `cidrize` fuzz target with its own config, seed corpus, and binary registration for the bundled `cidrize-runner-main` subject.
- Introduced a `CidrizeSemanticMutator` and matching seed generator so ranges, CIDR prefixes, wildcard expressions, and mixed-family IP tokens get target-specific Tier 2 mutations instead of reusing the narrower IPv6 rules.
- Extended the executor to accept per-target fixed command-line arguments, which allows wrappers like `cidrize-runner` to require `--func cidrize` without special-casing the main loop.

Reasons:
- `cidrize` accepts a broader human-oriented IP language than the existing IPv6 literal parser, so sharing the same semantic model and mutation rules would bias the campaign toward the wrong grammar.
- The target’s CLI contract differs slightly from the built-in IPv4/IPv6 parsers, and making that configurable keeps the fuzzer extensible for future binary targets.

Key files changed:
- `config/cidrize_format.json`
- `corpus/cidrize_seeds.txt`
- `fuzzer/mutation/tier2_semantic.py`
- `fuzzer/seed_generator.py`
- `fuzzer/executor.py`
- `main.py`

### Add Atheris-backed JSON target
Improvements:
- Added a new `json` fuzz target for the bundled `json-decoder-main` subject, with `config/json_format.json`, a seed corpus, and an Atheris harness at `fuzzer/json_atheris_harness.py`.
- Taught `main.py` to dispatch `python main.py json ...` into an Atheris-managed campaign while keeping the existing IPv4/IPv6 pipeline unchanged.
- Added a JSON semantic mutator so structure-aware edits can be reused inside the Atheris custom mutator.

Reasons:
- The JSON decoder needs real Python instrumentation rather than the subprocess-only behavior hashing used for the opaque parser binaries.
- Atheris is a better fit for this target because it can instrument the Python parser code path exercised by `json_decoder_stv.py`.

Key files changed:
- `main.py`
- `fuzzer/json_atheris_harness.py`
- `fuzzer/mutation/tier2_semantic.py`
- `config/json_format.json`
- `corpus/json_seeds.txt`

### DL training history artifacts
Improvements:
- Added per-run DL training logs in `results/<target>/dl_training.jsonl` with loss, timing, execution count, buffer size, behaviors seen, and runtime scheduler metadata for each training round.
- Added `results/<target>/dl_summary.json` with the run's initial and final DL metadata, whether a checkpoint was reused, and how many training rounds happened during the run.

Reasons:
- Made it possible to inspect how the surrogate's loss changed during a campaign instead of only seeing the latest checkpoint state.
- Made warm-start versus fresh-start DL runs easier to compare by recording checkpoint reuse and before/after scheduler metadata.

Key files changed:
- `main.py`
- `evaluation/collect_metrics.py`

### Explicit static-mode CLI switch
Improvements:
- Added a `--no-dl` command-line flag that forces the static scheduler even when `torch` is installed.
- Recorded whether DL was enabled in the run configuration output so static-versus-hybrid experiments are easier to audit later.

Reasons:
- Made static baseline runs much easier to launch without creating a separate Python environment or uninstalling dependencies.
- Reduced the risk of accidentally comparing a DL-enabled run against a supposed static baseline.

Key files changed:
- `main.py`

### Startup and execution timing logs
Improvements:
- Added startup phase timing logs for format loading, corpus generation, mutator setup, scheduler initialization, havoc priming, and executor initialization.
- Added explicit logs around the first target execution and follow-up logs for later executions that take at least one second.

Reasons:
- Made it much easier to tell whether perceived startup slowness comes from corpus generation, torch/checkpoint initialization, executor setup, or the first target run.
- Reduced the "silent wait" period at the start of a fuzzing run by surfacing when the first execution begins and how long it took.

Key files changed:
- `main.py`

### Zero-dependency progress plotting
Improvements:
- Added `evaluation/plot_progress.py`, a small standard-library-only utility that reads `results/<target>/plot_data` and renders an SVG dashboard with separate panels for each metric.
- Documented the `plot_data` columns and the new plotting command in the README output section.
- Added a `unique_bugs.json` artifact so deduplicated bug signatures can be inspected directly instead of only appearing as an in-memory count.

Reasons:
- Made the new `plot_data` artifact immediately useful without requiring `matplotlib` or a notebook workflow.
- Made plateaus and slowdowns much easier to read by plotting raw metric values instead of a normalized single overlay.
- Made demo and post-run analysis easier by persisting the unique bug list with first-seen execution metadata and example inputs.

Key files changed:
- `evaluation/collect_metrics.py`
- `evaluation/plot_progress.py`
- `README.md`

### Mutation-payoff learning loop
Improvements:
- Added a lightweight online mutation-payoff tracker that learns from observed success rates and EWMAs for semantic-stage use, havoc operators, semantic fields, guided-versus-random mutations, and seed families.
- Upgraded both the static scheduler and the hybrid DL scheduler to plan mutations from those payoff statistics, including adaptive havoc operator weights, semantic-stage probability, guided mutation ratio, and preferred productive fields.
- Extended Tier 2 and Tier 3 mutators to emit per-iteration mutation traces so the scheduler can learn from the actual operator, field, and guidance decisions that produced new behaviors.
- Wrote learned payoff summaries to `results/<target>/mutation_stats.json` so campaigns can be inspected after a run.

Reasons:
- Shifted the scheduler closer to the real optimization target: which mutation choices pay off, rather than only which inputs correlate with coverage.
- Made the adaptive behavior useful even without neural guidance because mutation success statistics now improve the static path too.
- Created a clearer foundation for future learned policies by separating direct mutation-outcome learning from surrogate coverage prediction.

Key files changed:
- `fuzzer/scheduler.py`
- `dl/surrogate.py`
- `fuzzer/mutation/tier2_semantic.py`
- `fuzzer/mutation/tier3_havoc.py`
- `main.py`
- `evaluation/collect_metrics.py`

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


## 2026-03-26

### Add oracle-based parser classification
Improvements:
- Added lightweight IPv4, IPv6, and cidrize input oracles so the executor can compare parser behavior against expected validity.
- Reclassified oracle-detected false accepts as `oracle_mismatch` and upgraded false rejects from `invalidity` to `validity` when the oracle says the input is valid.
- Stopped counting expected `invalidity` results as unique bugs while preserving them as a separate metric.

Reasons:
- Keeps evaluation results aligned with real bugs instead of treating normal invalid-input rejection as bug discovery.
- Makes it possible to surface acceptance/rejection mismatches that the target binary reports as plain success.

Key files changed:
- `fuzzer/oracle.py`
- `fuzzer/executor.py`
- `evaluation/collect_metrics.py`

## 2026-03-26

### Add JSON stdlib oracle
Improvements:
- Added a JSON oracle to the Atheris harness using Python's standard `json.loads` as the reference parser.
- Reported mismatches where the custom decoder rejects JSON accepted by the stdlib, accepts JSON rejected by the stdlib, or decodes to a different value.
- Normalized special float values before comparison so semantic comparisons stay stable.

Reasons:
- Gives the JSON target the same kind of correctness oracle as the parser binaries instead of relying only on crashes or seeded exceptions.
- Lets Atheris surface semantic and acceptance/rejection bugs directly during fuzzing.

Key files changed:
- `fuzzer/json_atheris_harness.py`
