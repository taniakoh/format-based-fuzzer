# Improvements Log

Use this file to record meaningful improvements, refactors, feature additions, performance work, and reliability upgrades.

## 2026-04-21

### Target the remaining IPv6 triple-colon exception path
Improvements:
- Added curated full-width IPv6 `:::` seeds that keep 8+ token layouts instead of collapsing immediately into the existing short-token branch.
- Added a dedicated `triple_colon_full_width` IPv6 semantic mutator that injects `:::` into otherwise full-width addresses.
- Extended bootstrap checks to lock in both the new seeds and the new mutator output.

Reasons:
- The previous IPv6 campaign was already reaching the overlong-hextet and token-length exceptions, but not the decompiled branch that checks for a parsed `:::` token after normal-width tokenization.
- Keeping this malformed shape in both seeds and Tier 2 mutations gives the fuzzer a much better chance of exercising the remaining exception path without relying on havoc luck.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `evaluation/bootstrap_checks.py`

## 2026-04-21

### Add absolute JSON source-coverage replay for Atheris runs
Improvements:
- Added a post-run `coverage.py` replay step for JSON Atheris campaigns that replays the saved corpus, writes cumulative source-coverage checkpoints to `results/<target>/coverage_replay.json`, and lets the progress chart use that artifact instead of normalizing against the run's final `cov`.

Reasons:
- The previous JSON/Atheris coverage panel could only show progress relative to the final observed libFuzzer `cov`, which always ended at `100%` and overstated what the number meant.

Key files changed:
- `evaluation/json_coverage_replay.py`
- `main.py`
- `evaluation/plot_progress.py`

## 2026-04-21

### Sharpen IPv6 parser-specific malformed paths
Improvements:
- Expanded the IPv6 seed corpus with malformed embedded-IPv4 suffixes and dangling compressed-tail cases observed in the decompiled parser grammar.
- Added IPv6 semantic mutator operations that directly synthesize invalid mixed-notation suffixes and `::1:` / `::1::`-style dangling compression tails.
- Strengthened the extracted-parser probe with direct checks for the `::` false reject plus malformed-address false accepts.

Reasons:
- The decompiled IPv6 parser accepts a few malformed compressed and mixed-notation families that generic RFC-style mutations do not target often enough.
- Keeping these parser-specific shapes in seeds, mutations, and regression probes makes the fuzzer more likely to rediscover the real parser bug paths reliably.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `evaluation/ipv6_bug_path_probe.py`

## 2026-04-20

### Target IPv6 compressed-edge bug shapes
Improvements:
- Expanded the IPv6 seed corpus with curated malformed compressed-address cases such as `:::`, `1:::2`, `::::`, compressed-overflow variants, and extra-group combinations.
- Added IPv6 semantic mutator operations that explicitly synthesize triple-colon and compressed-overflow shapes instead of relying on generic colon damage.
- Rebalanced IPv6 generation so more mutations stay near valid compressed forms while still crossing into the parser's narrow malformed-address bug paths.
- Added `evaluation/ipv6_bug_path_probe.py` to confirm the reachable extracted-parser paths directly, including `InvalidityBug`, `ReliabilityBug`, false accepts, and early `ParseException` rejection.

Reasons:
- The IPv6 campaign was spending most of its executions on generic junk that collapsed into parser-reported `bonus` and `ParseException` outcomes before reaching the interesting compressed-address edge cases.
- The decompiled IPv6 parser appears to have narrow bugs around `:::` handling and structured token overflows, which need targeted inputs rather than random havoc.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `evaluation/ipv6_bug_path_probe.py`

### Add XML unseen-testing onboarding guide
Improvements:
- Added `unseen_testing.md` with a practical guide for using an LLM to onboard XML as a new unseen-format benchmark.
- Included a reusable prompt template, the repository context to provide, starter valid and malformed XML inputs, and oracle/mutation guidance tailored to this fuzzing pipeline.

Reasons:
- The repository already has a staged unseen-format evaluation plan, but there was not yet a single concise note describing what to ask the LLM to generate and which XML inputs to prepare.
- XML is a more standard parser benchmark choice than URL and better matches common fuzzing evaluation targets.

Key files changed:
- `unseen_testing.md`
- `improvements.md`

### Add validity-aware exploration shaping across structured formats
Improvements:
- Downweighted shallow invalidity discoveries in the main fuzz loop so corpus growth, scheduler payoff, and DL training favor valid-input exploration and real bug signal.
- Added oracle-guided semantic operation selection plus valid-example recovery mutations for IPv4, IPv6, CIDRize, and JSON-family targets.

Reasons:
- Hybrid guidance was over-rewarding novel malformed inputs, especially on IPv4, which flooded runs with invalidity findings and starved valid neighborhoods.
- The same reward-path issue affected the other structured formats because they share the corpus, scheduler, and semantic-mutation pipeline.

Key files changed:
- `main.py`
- `fuzzer/mutation/tier2_semantic.py`

## 2026-04-15

### Add a concrete ISO-8601 transfer benchmark to the testing plan
Improvements:
- Extended `testingplan.md` with one fully specified held-out-format benchmark using ISO-8601 datetime strings.
- Added a precise accepted subset, stdlib-based oracle strategy, onboarding budgets, seed examples, and a reusable scorecard template.
- Added concrete success criteria so transfer performance can be judged against the custom-mutation upper bound rather than only described qualitatively.

Reasons:
- The earlier transfer section explained how to evaluate new-format onboarding, but it still required choosing a format and defining the oracle and reporting structure.
- ISO-8601 is a good single-format benchmark because it has optional structure, real semantic constraints, and a practical oracle path in Python.
- A concrete benchmark makes the plan directly executable for this repository instead of leaving key evaluation choices underspecified.

Key files changed:
- `testingplan.md`
- `improvements.md`

### Add new-format onboarding benchmark to the testing plan
Improvements:
- Extended `testingplan.md` with a dedicated benchmarking subsection for evaluating transfer to previously unseen formats.
- Added staged onboarding budgets (`config-only`, `config+hints`, `custom mutator`) so the benchmark measures low-effort format absorption separately from hand-written upper bounds.
- Added recommended held-out formats, transfer-focused metrics, and success criteria centered on how close the generic path gets to the custom-mutation path.

Reasons:
- The existing benchmarking plan focused on performance across current targets but did not directly answer whether the fuzzer generalises well to a genuinely new format.
- The repository already has a meaningful config-driven onboarding path, so the evaluation should measure that capability explicitly rather than only full custom extensions.
- A staged transfer benchmark better matches the lessons from structured-input fuzzing papers, where the real question is how much manual format knowledge is still required.

Key files changed:
- `testingplan.md`
- `improvements.md`

### Align testing plan with NEUZZ and NEUZZ++ methodology
Improvements:
- Updated `testingplan.md` to distinguish between normal online warm-up for `hybrid_dl` runs and the separate bootstrap checkpoint required for the frozen-model A4 ablation.
- Added NEUZZ++ as the preferred modern neural-program-smoothing baseline and tightened the benchmarking guidance around repeated trials, common replayed coverage metrics, and matched time budgets.
- Revised the plan so opaque PyInstaller targets use rolling hold-out validation and staged run budgets, while shared-source targets (`cJSON`, `LAVA-M`) keep the closer-to-NEUZZ setup.

Reasons:
- The current implementation already trains online and keeps the scheduler static until it has enough samples and training rounds, so the previous plan overstated the need for an offline initial-training phase.
- A4 needed a documented bootstrap-checkpoint procedure; otherwise `--no-retrain` plus `--fresh-start` would measure an untrained model rather than a frozen warm-start surrogate.
- NEUZZ++ provides stronger guidance for evaluating ML-guided fuzzers credibly, especially around run counts and common comparison metrics.

Key files changed:
- `testingplan.md`
- `improvements.md`

## 2026-04-15

### Add environment template for bootstrap LLM settings
Improvements:
- Added a repo-root `.env.template` documenting the OpenAI environment variables used by the bootstrap flow.
- Included the default base URL and model so bootstrap setup is easier to reproduce across machines.

Reasons:
- The code reads `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL` from the environment, but the repository did not include a starter template.
- A visible template lowers setup friction for anyone trying the LLM-assisted bootstrap path for new formats.

Key files changed:
- `.env.template`
- `improvements.md`

## 2026-04-14

### Unify bug metrics around canonical bug sites
Improvements:
- Added shared bug-site derivation logic so traceback-bearing crashes, parser-reported bug sites, and fallback bug records all normalize to the same unique-bug identity.
- Extended run artifacts to expose dedup metadata directly in `unique_bugs.json`, `bugs.jsonl`, and summary outputs.
- Brought Atheris post-processing in line with the native metrics collector so both pipelines emit comparable unique-bug totals and line-based `bug_counts.csv` rows.

Reasons:
- The previous outputs mixed parser-site, traceback, and message-based notions of uniqueness, which made cross-run comparisons noisy.
- Shared normalization makes downstream plots, CSV analysis, and manual auditing much more trustworthy.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`
- `improvements.md`

## 2026-04-09

### Added WSL source-instrumentation path for IP parsers
Improvements:
- Added `tools/ip_parser_source_runner.py` to run the extracted IPv4/IPv6 parser modules directly from the PyInstaller payload in WSL/Linux.
- Added `tools/ip_parser_afl_harness.py`, a low-overhead persistent `python-afl` harness that keeps the parser loaded and fuzzes via stdin.
- Added `instrumentation.md` with concrete `coverage.py` and `python-afl` examples for source-level instrumentation.

Reasons:
- The packaged Windows parser binaries are slow to launch and hard to instrument directly.
- The extracted Linux payload already contains importable parser modules, so using them directly is a much cleaner path to real runtime coverage.

Key files changed:
- `tools/ip_parser_source_runner.py`
- `tools/ip_parser_afl_harness.py`
- `instrumentation.md`
- `improvements.md`

### Show coverage percentage in progress charts
Improvements:
- Updated `evaluation/plot_progress.py` so the coverage panel renders percentage-over-time instead of only raw coverage counts.
- For fixed-size bitmap targets, the chart now shows percentage of the 65,536-slot bitmap.
- For Atheris targets, the chart now shows percentage of the final observed `cov` for the run and labels that basis explicitly in the panel title.

Reasons:
- Raw coverage counts are harder to compare visually across runs and targets than a normalized percentage series.
- Atheris logs expose `cov` as a count but do not provide the true denominator, so the chart now uses an honest relative percentage instead of implying an unavailable absolute percentage.

Key files changed:
- `evaluation/plot_progress.py`
- `improvements.md`

## 2026-04-14

### Persist coverage percentage in run outputs
Improvements:
- Added `coverage_percent` to `plot_data`, `bug_coverage_summary.json`, and `stats.txt` / `fuzzer_stats`.
- Kept raw `coverage_seen` alongside the normalized percentage so run artifacts still preserve the absolute bitmap count.
- Updated README output docs to match the new saved metrics.

Reasons:
- Coverage percentage was already shown in charts, but not persisted in the primary machine-readable and text summaries.
- Saving both raw and normalized coverage makes evaluation tables and comparisons easier without forcing downstream scripts to recompute the percentage.

Key files changed:
- `evaluation/collect_metrics.py`
- `README.md`
- `improvements.md`

### Add report-metrics aggregator for RQ1-RQ4
Improvements:
- Added `evaluation/report_metrics.py` to scan finished run directories and aggregate report-ready metrics by target and evaluation mode.
- The script now writes both summary outputs (`report_metrics.json`, `report_metrics.md`) and averaged curve CSVs for the required report graphs.
- Documented the aggregation workflow in the README so repeated-run evaluation can be produced without manual copy-paste.

Reasons:
- The raw fuzzer outputs already contained most single-run metrics, but the course report requires repeated-run summaries, baseline comparisons, and stability reporting.
- Automating the aggregation step reduces reporting mistakes and makes it easier to regenerate RQ1-RQ4 tables and graphs after new runs finish.

Key files changed:
- `evaluation/report_metrics.py`
- `README.md`
- `improvements.md`

### Add cached bootstrap profiles for unknown formats
Improvements:
- Added an opt-in `python main.py bootstrap <target>` flow that generates and caches `config/<target>_bootstrap.json` artifacts with reusable seeds and generic mutation hints.
- Extended generic seed loading to support binary-safe corpus directories, cached bootstrap artifacts, and JSON seed files before falling back to config examples.
- Taught the generic semantic mutator to switch into hint-aware binary/container mutations for unknown formats such as PDF while leaving format-specific mutators unchanged.
- Added focused regression checks for cached bootstrap loading, corpus precedence, PDF-style manual profiles, and binary/container mutation behavior.

Reasons:
- Unknown formats previously fell back to text-oriented generic mutation, which was a poor fit for binary/container inputs.
- A one-time cached bootstrap path keeps LLM usage practical and cost-effective by removing any network dependency from the hot fuzzing loop.

Key files changed:
- `fuzzer/bootstrap.py`
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `main.py`
- `evaluation/bootstrap_checks.py`
- `improvements.md`

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
## 2026-04-05

### Clarify WSL and venv session startup steps
Improvements:
- Expanded `setup.md` with a dedicated quick-start section for opening WSL, changing into the project directory, and activating the Linux virtual environment each session.
- Added a copy-paste startup sequence and a simple verification step so the recurring workflow is easier to follow without rereading the full setup guide.

Reasons:
- The original setup guide focused more on one-time environment creation than on the repeated “start working” steps.
- A short per-session checklist reduces friction and makes it easier to resume work consistently.

Key files changed:
- `setup.md`
- `improvements.md`

### Add explicit evaluation modes and honest DL metadata
Improvements:
- Added explicit evaluation modes for `havoc_only`, `semantic_plus_havoc`, `static_payoff`, and `hybrid_dl` so ablation runs no longer depend on whether torch happens to be installed.
- Added a fixed-policy scheduler for clean baselines and persisted the requested/resolved evaluation mode in run artifacts and stats output.
- Updated the DL summary/config output to describe the model as a compressed behavior proxy instead of implying it learns the full runtime bitmap.

Reasons:
- Makes experimental comparisons reproducible and interpretable across machines.
- Keeps the evaluation story aligned with what the scheduler and surrogate actually do.

Key files changed:
- `main.py`
- `fuzzer/scheduler.py`
- `README.md`

## 2026-04-05

### Generalize cidrize oracle by parsed shape
Improvements:
- Replaced the old branch-order `cidrize` oracle with a shape-first parser plus semantic validators for networks, full ranges, partial IPv4 ranges, and IPv4 wildcard forms.
- Added `shape` and optional `normalized` metadata to `OracleVerdict` so run artifacts can explain what family the oracle recognized.
- Added `evaluation/oracle_checks.py` with family-based regression checks to exercise the oracle beyond the hand-written seed examples.

Reasons:
- Reduces overfitting to the current test cases and makes the oracle judge whole grammar families instead of a few literal patterns.
- Makes oracle decisions easier to inspect when a fuzz run produces unexpected classifications.

Key files changed:
- `fuzzer/oracle.py`
- `evaluation/oracle_checks.py`
- `README.md`

## 2026-04-05

### Add bug coverage summary by taxonomy
Improvements:
- Added `bug_coverage_summary.json` to aggregate total and unique finding counts by internal bug type, parser-reported bug type, and presentation taxonomy tag.
- Extended `stats.txt` with compact taxonomy total/unique rollups so runs can be compared quickly without opening JSON artifacts.
- Kept `unique_findings.json` as the per-finding detail view while the new summary file provides the run-level coverage map.

Reasons:
- Makes it easy to answer questions like "how many `InvalidityBug` findings did we see?" and "how many were unique?" directly from run artifacts.
- Gives bug coverage visibility that matches the presentation taxonomy instead of only the executor's internal labels.

Key files changed:
- `evaluation/collect_metrics.py`

## 2026-04-05

### Ablation study CLI flags (A4 and A5)
Improvements:
- Added `--no-retrain` flag that disables incremental surrogate retraining so the model is used as-is from the cold-start checkpoint only (ablation variant A4).
- Added `--fixed-lr` flag that replaces cosine decay with restarts with a constant learning rate (`1e-3`) during surrogate training (ablation variant A5).
- Both flags are passed through `fuzz()` and into `train()` in `trainer.py`.

Reasons:
- Completes the ablation variant set so all six variants (Full, A1–A5) can be run from the CLI without code changes.
- A4 isolates the value of online learning; A5 isolates the value of the LR schedule.

Key files changed:
- `main.py`
- `dl/trainer.py`

### Run observability: energy log, oracle log, misprediction rate, execs/sec
Improvements:
- Added `energy_log.csv` (`relative_time_sec, seed_id, energy`) logged every fuzzing cycle so seed energy distribution can be plotted at hourly checkpoints.
- Added `oracle_log.csv` (`relative_time_sec, input_hash, is_new_behavior, bug_label, latency_ms`) logged every execution so oracle verdict latency can be audited.
- Added `misprediction_rate` to each entry in `dl_training.jsonl`, computed as per-bit Hamming error rate on the most recent `TRAIN_EVERY` inputs before each retrain event.
- Added `Execs/sec` to `stats.txt` and `fuzzer_stats`.
- Added `compute_misprediction_rate()` function to `dl/trainer.py`.

Reasons:
- Fills the gaps between the required log files in the testing plan (Section 7.1) and what was actually produced.
- Hamming-based misprediction rate is meaningful for incremental retraining diagnosis; the previous all-or-nothing metric always returned 1.0 with 128 output bits.

Key files changed:
- `evaluation/collect_metrics.py`
- `dl/trainer.py`
- `main.py`

### Fix false positive crashes from argparse flag confusion
Improvements:
- Changed `--ipstr <value>` to `--ipstr=<value>` in both the direct binary runner and the AFL QEMU runner.

Reasons:
- Inputs starting with `-` were parsed by argparse inside the binary as a missing flag argument, producing exit code 2 and a spurious `CRASH` classification.
- The `=` form forces argparse to treat the entire string after `=` as the value regardless of leading characters.

Key files changed:
- `fuzzer/executor.py`

### Fix oracle reclassification for parser-reported validity bugs
Improvements:
- `_apply_oracle` now cross-checks the oracle before accepting the parser's "validity" label. When `oracle.expected_valid is False`, the input is invalid and the parser correctly rejected it — reclassified to `INVALIDITY` instead of `VALIDITY`.

Reasons:
- The parser labels all parse exceptions as "validity bugs" in its output regardless of whether the input was actually valid. This produced false positive validity bugs for clearly invalid inputs such as `7255.991U` and `2552`.
- Only inputs the oracle considers valid (or unsupported) should remain as `VALIDITY` real bugs.

Key files changed:
- `fuzzer/executor.py`

### Track clean parse rate
Improvements:
- Added `pass_count` field to `FuzzMetrics` and incremented it before the early return on `BugType.PASS` in `record_execution`.
- Added `Pass (clean): N (X%)` line to `stats.txt` and `fuzzer_stats`.

Reasons:
- A pass rate of 0% indicates mutations are destroying all valid structure before the parser sees it, which prevents the fuzzer from exercising the parser's success path and finding boundary validity bugs.
- Makes this diagnostic visible without inspecting raw logs.

Key files changed:
- `evaluation/collect_metrics.py`

### Unmodified seed pass-through (10%)
Improvements:
- Added a 10% probability in the main fuzzing loop of running the selected seed completely unmodified, skipping all three mutation tiers.

Reasons:
- With aggressive three-tier mutation, valid boundary seeds such as `255.255.255.255` were always destroyed before reaching the parser, preventing discovery of the known validity bug.
- AFL uses the same principle: seeds are run unmodified on first selection to establish a clean baseline before mutations are applied.

Key files changed:
- `main.py`

### Fix plot axes alignment
Improvements:
- Fixed `scale_x` to map times to the actual plot area `[x0+44, x0+width-16]` instead of the full panel bounds `[x0, x0+width]`.
- Fixed `scale_y` to map values to the actual plot area `[y0+38, y0+height-28]` instead of `[y0, y0+height]`.
- Fixed `mid_y` gridline to use the plot area midpoint rather than the panel midpoint.

Reasons:
- The polyline started outside the drawn axes because scaling used the outer panel dimensions rather than the inner plot area bounded by the axis lines.

Key files changed:
- `evaluation/plot_progress.py`

## 2026-04-08

### Mixed valid/invalid seed corpus

Improvements:
- Updated all four seed generators (`IPv4SeedGenerator`, `IPv6SeedGenerator`, `JSONSeedGenerator`, `CidrizeSeedGenerator`) to produce a mixed corpus of roughly 70 % valid and 30 % structured-invalid seeds.
- Each generator now has an explicit set of invalid structural templates or literal seeds covering the most common parser error paths: wrong field counts, out-of-range values, bad separators, truncated input, and malformed notation.
- Updated the module docstring to reflect the mixed-corpus intent.

Reasons:
- A valid-only corpus relies entirely on mutations to reach invalid-input code paths. For expensive targets (20–30 s per execution) this wastes a large fraction of the time budget on seeds that must be mutated "far enough" before they exercise error handling.
- Structured-invalid seeds reach parser error paths directly on first execution and give the mutation engine a foothold in the invalid-input region of the input space, so subsequent mutations can explore that region rather than stumbling into it from scratch.
- The 70/30 split keeps the majority of the corpus valid so Tier 2 semantic mutations still have well-formed starting points for structured edits.

Key files changed:
- `fuzzer/seed_generator.py`

### Fix `_colon_run` to target only isolated group-separator colons

Improvements:
- Restricted the set of eligible positions in `_colon_run` to colons that are not adjacent to another colon, excluding characters that are already part of `::` compressed notation.

Reasons:
- The previous implementation picked any colon position, including those inside `::`. Replacing one half of `::` with a longer run corrupts the compressed address into unstructured noise rather than placing a meaningful separator run between two hex groups, so the mutated input hit trivially early parse failures instead of reaching deeper parser logic.
- Restricting to bare group-separator colons ensures the run always lands at an inter-group boundary, which is the only position where it can exercise the parser's separator-handling logic.

Key files changed:
- `fuzzer/mutation/tier2_semantic.py`

## 2026-04-07

### Refresh pinned dependency set
Improvements:
- Updated `requirements.txt` to use the requested CUDA 12.1 PyTorch stack and aligned supporting package pins.
- Relaxed `setuptools` to a minimum version constraint instead of a single exact pin.

Reasons:
- Keeps the project dependency set consistent with the requested runtime and wheel variants.
- Avoids over-constraining `setuptools` while preserving the intended lower bound.

Key files changed:
- `requirements.txt`

### Add evaluation metrics and graphs
Improvements:
- Added an explicit `interesting_test_cases` series to `plot_data` so interesting test cases vs wall-clock time and vs total tests can be rendered directly from run output.
- Added separate average generation-time and execution-time metrics to `stats.txt` and `bug_coverage_summary.json`.
- `evaluation/plot_progress.py` now writes both `progress.svg` and `eval_graphs.svg`.

Reasons:
- The existing output had enough raw signals for partial evaluation, but the RQ2 timing breakdown was not directly available.
- Separating mutation-generation cost from target-execution cost makes the efficiency table more accurate than using combined `execs/sec` alone.

Key files changed:
- `main.py`
- `evaluation/collect_metrics.py`
- `evaluation/plot_progress.py`
- `README.md`

## 2026-04-14

### Replace Linux black-box QEMU coverage with Frida
Improvements:
- Swapped the Linux binary executor path from AFL++ QEMU coverage to Frida Stalker block tracing for `ipv4`, `ipv6`, `cidrize`, and `cjson`.
- Removed the `--no-qemu` CLI path, marked binary target configs as `frida`-instrumented, and updated the focused regression checks to cover Frida mode selection and missing-runtime handling.
- Updated `setup.md` and `requirements.txt` so WSL setup installs and verifies Frida instead of AFL++.

Reasons:
- The project now uses Frida as the sole Linux black-box instrumentation backend, so the executor, configs, tests, and setup guide needed to converge on the same runtime model.
- Keeping subprocess-based stdout/stderr parsing while collecting coverage through Frida preserves existing oracle and bug classification behavior.

Key files changed:
- `fuzzer/executor.py`
- `main.py`
- `evaluation/oracle_checks.py`
- `setup.md`
- `requirements.txt`
## 2026-04-15

### Rare-edge corpus prioritization
Improvements:
- Added rarity-aware coverage observation so each execution now scores how uncommon its exercised bitmap slots are.
- Fed rare-edge scores into corpus heating and new-seed priority so unusual behaviors remain selectable longer.
- Logged rarity in new-seed console output to make path-discovery dynamics easier to inspect during runs.

Reasons:
- Binary new/not-new feedback was keeping some uncommon-but-useful seeds too cold in the queue.
- Rare-slot prioritization helps spend expensive executions on inputs that are more likely to branch into underexplored logic.

Key files changed:
- fuzzer/coverage.py
- fuzzer/corpus.py
- main.py
- evaluation/oracle_checks.py

## 2026-04-18

### Strengthen hybrid DL guidance and seed diversity
Improvements:
- Switched the surrogate to a less lossy raw-byte encoding, expanded its input window and proxy coverage dimension, and widened the encoder so accuracy-first runs can distinguish more structured inputs.
- Replaced the old new-behavior-only DL buffer with a mixed rolling buffer that keeps new behaviors, parser near-misses, and sampled non-new executions for denser training feedback.
- Added family-aware field ranking and guidance blending so productive seed families receive stronger targeted mutation help.
- Expanded the IPv4 and IPv6 seed generators with curated valid and structured-invalid starter corpora before filling the rest of the initial queue randomly.

Reasons:
- The previous DL setup was underfed and overcompressed, which limited its ability to learn useful distinctions on slow targets where each execution is expensive.
- Mixed training examples and stronger initial corpus diversity give the surrogate and payoff tracker better structural coverage earlier in the run.

Key files changed:
- main.py
- dl/surrogate.py
- dl/trainer.py
- fuzzer/scheduler.py
- fuzzer/seed_generator.py

## 2026-04-19

### Add generalized shallow-rejection cooling
Improvements:
- Added a format-agnostic structure regulator that watches recent invalidity-heavy runs, detects repeated shallow rejection sites, and shifts mutation plans toward more structure-preserving operator mixes.
- Taught both the static payoff scheduler and hybrid DL scheduler to apply that regulator before emitting mutation plans.
- Added parent-seed cooling so corpus entries that repeatedly reproduce the same shallow rejection buckets lose priority faster.

Reasons:
- The previous feedback loops learned operator payoff, but they did not explicitly react when the campaign got trapped rediscovering the same parser rejection sites.
- Cooling repeated shallow rejections is a generalized policy that works across structured formats without hardcoding IPv4-only invariants.

Key files changed:
- main.py
- fuzzer/corpus.py
- fuzzer/scheduler.py
- dl/surrogate.py

## 2026-04-20

### Soften bootstrap seed size guidance
Improvements:
- Relaxed the LLM bootstrap prompt so it still prefers compact examples but now explicitly allows the minimal structure needed for parsing.

Reasons:
- The earlier wording pushed too hard toward tiny seeds and could encourage under-structured examples for formats with a larger parseable minimum.

Key files changed:
- fuzzer/bootstrap.py

## 2026-04-21

### Document rationale for onboarding new formats
Improvements:
- Added contributor-facing documentation explaining why adding a new format matters to this repository's evaluation and architecture story.
- Clarified that new formats are used to test extensibility, transferability, and where the current pipeline still needs target-specific help.

Reasons:
- The docs already described how formats plug in, but they did not clearly explain the motivation for adding one.
- Making that rationale explicit helps keep future format additions aligned with the project's research and engineering goals.

Key files changed:
- README.md
- hybrid_fuzzer_impl_guide.md

### Document rationale for using LLM bootstrap on unseen targets
Improvements:
- Added a dedicated explanation of why the unseen-target workflow uses an LLM as a bootstrap aid.
- Clarified that the LLM is intended to generate first-pass target knowledge for onboarding, while the shared fuzzing engine still performs the actual discovery work.

Reasons:
- The unseen-target guide described how to ask the LLM for artifacts, but it did not clearly explain why the LLM is part of that workflow.
- Making that rationale explicit helps distinguish offline bootstrap assistance from using an LLM inside the hot mutation loop.

Key files changed:
- unseen_testing.md

### Add a runnable XML target
Improvements:
- Added a first-class `xml` target with config, starter seeds, an XML-aware semantic mutator, and an Atheris harness.
- Extended the Atheris runner so harness selection and artifact reclassification work for more than just the JSON target.
- Documented the new XML run path in the main README and setup guide.

Reasons:
- XML was previously only documented as an unseen-target planning exercise, which meant the repo could not actually run the benchmark.
- Making XML runnable gives the repository a concrete cross-format target that is easier to evaluate and demo.

Key files changed:
- config/xml_format.json
- corpus/xml_seeds.txt
- fuzzer/xml_atheris_harness.py
- fuzzer/oracle.py
- fuzzer/mutation/tier2_semantic.py
- main.py
- README.md
- setup.md

### Auto-load bootstrap OpenAI settings from .env
Improvements:
- Added a small dependency-free `.env` loader for the bootstrap path so `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL` are picked up automatically when missing from the shell.
- Updated the `.env` and `.env.template` guidance to match the new behavior.

Reasons:
- Bootstrap profile generation depended on environment variables, but the repository already encouraged storing those values in `.env`.
- Auto-loading the bootstrap settings removes an unnecessary setup step and makes the unseen-target workflow easier to demo and reuse.

Key files changed:
- fuzzer/bootstrap.py
- .env
- .env.template
## 2026-04-21

### Add Linux persistent parser mode
Improvements:
- Added a `--persistent` execution path for Linux `ipv4` and `ipv6` runs that reuses a long-lived worker backed by the extracted parser bundle.
- Routed persistent executions through the existing executor interface so fuzzing, oracle application, and result recording still work with the faster path.
- Documented the new throughput-oriented mode in the README.

Reasons:
- Frida and cold process startup were dominating per-input cost on Linux parser targets.
- Keeping the parser loaded between executions gives a practical persistent-mode option without replacing the rest of the fuzzer pipeline.

Key files changed:
- main.py
- fuzzer/executor.py
- fuzzer/persistent_worker.py
- README.md

## 2026-04-21

### Add bugs-over-time plot utility
Improvements:
- Added a post-processing script that reconstructs cumulative unique bugs over wall-clock time from existing run artifacts.
- The utility prefers `unique_bugs.json` plus `oracle_log.csv` for current runs and falls back to `plot_data` when that series is already present.
- The script emits both `bugs_over_time.csv` and `bugs_over_time.svg` into the selected run directory for direct report use.
- Integrated the same reconstruction path into the main `plot_progress.py` dashboard so the existing "Unique bugs" panel can render from current artifacts even when `plot_data` does not carry a complete bug timeline.
- Expanded the canonical `plot_data` schema for normal fuzzing runs to include per-sample bug and crash deltas (`new_unique_bugs`, `new_unique_crashes`) alongside the cumulative totals.
- Updated the fallback/post-processing `plot_data` writer to synthesize a bugs-over-time series from `oracle_log.csv` and `unique_bugs.json` when execution-time rows are missing.

Reasons:
- Existing results already tracked bug discovery order and execution-relative timing, but there was no dedicated way to turn that into a bugs-vs-time graph.
- Producing a lightweight SVG keeps plotting dependency-free and easy to run on archived result folders.
- Reusing the reconstruction logic inside the existing dashboard keeps the normal plotting workflow intact instead of requiring a separate manual plotting step.
- Making `plot_data` itself carry bug-event information keeps bugs-over-time exportable from the canonical CSV instead of depending on sidecar reconstruction for every consumer.

Key files changed:
- evaluation/plot_bugs_over_time.py
- evaluation/collect_metrics.py
- evaluation/plot_progress.py
- main.py
- improvements.md
## 2026-04-21

### Prefer Frida line-hit coverage when symbols exist
Improvements:
- Updated the Frida Stalker agent to resolve executed addresses to `DebugSymbol` file/line locations and hash those line hits into the existing bitmap.
- Kept the previous block-edge hashing as an automatic fallback when symbolication is missing, so Linux Frida runs still produce coverage on stripped binaries.

Reasons:
- The old Frida path only approximated control-flow edges, which made it impossible to treat coverage as a rough source-line signal even when debug metadata was present.
- Using line hits when available gives the fuzzer a closer approximation to “what code locations executed” without breaking the rest of the bitmap-driven pipeline.

Key files changed:
- `fuzzer/executor.py`
- `evaluation/oracle_checks.py`
- `README.md`

## 2026-04-21

### Broaden directed IPv6 seed and semantic coverage
Improvements:
- Expanded curated IPv6 seeds with valid compressed forms, valid embedded-IPv4 forms, and known-invalid compressed-overflow cases that line up with the parser's hidden bug families.
- Added focused IPv6 semantic mutations that deliberately synthesize valid compressed addresses and valid embedded-IPv4 suffix forms instead of relying on generic colon edits.
- Added bootstrap regression checks to confirm the IPv6 seed corpus contains these targets and the new semantic operations emit the intended shapes.

Reasons:
- The fuzzer was still too dependent on luck to reach valid compressed and IPv4-embedded IPv6 addresses that trigger the parser's false rejects, false accepts, and wrong-value behaviors.
- Making these families first-class seeds and semantic mutations improves reproducibility during short fuzzing runs and gives Tier 2 a better chance of preserving parser-relevant structure.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `config/ipv6_format.json`
- `evaluation/bootstrap_checks.py`
## 2026-04-21

### Improve cidrize bug reachability
Improvements:
- Added dotted hostname seeds and valid examples for the `cidrize` target to exercise near-valid hostname parsing paths.
- Added a `hostname_tld_edge` semantic mutation to preserve hostname structure while stressing short and long TLDs.
- Strengthened repeated-dash seed coverage for `cidrize` separator bugs.

Reasons:
- The `cidrize` campaign was spending too much effort on early syntax failures in `netaddr`, which reduced reachability of deeper hostname and repeated-separator bug sites.
- Near-valid hostname mutations give the fuzzer a better chance of reaching the TLD handling bug in `buggy_cidrize/cidrize_stv.py`.

Key files changed:
- `config/cidrize_format.json`
- `corpus/cidrize_seeds.txt`
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
