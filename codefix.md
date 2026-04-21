# Code Fix Log

Use this file to record bug fixes, regressions fixed, guardrails added, and correctness issues addressed.

Use this entry format:

```md
## YYYY-MM-DD

### Short title
Improvements:
- ...

Reasons:
- ...

Key files changed:
- ...
```

## 2026-04-21

### Bias cidrize mutations toward parser rejection paths
Improvements:
- Retuned the `cidrize` semantic mutator so oracle-guided operation selection now prefers parser-error-oriented malformed families instead of valid-shape recovery operations.
- Expanded the `cidrize` corpus with extra malformed wildcard, duplicate-token, missing-prefix, and dangling-range seeds that are more likely to trigger parser-side invalidity or bonus reports.
- Trimmed the `cidrize` semantic rule list away from hostname/valid-shape expansion operations that were disproportionately leading to oracle mismatches.

Reasons:
- The campaign was spending too much energy inside supported-but-invalid shapes that the oracle could classify, which produced many `oracle_mismatch` results instead of parser-emitted findings.
- Steering Tier 2 toward malformed separators, broken wildcard syntax, duplicate tokens, and incomplete CIDR/range forms gives the parser more opportunities to reject input explicitly.

Key files changed:
- fuzzer/mutation/tier2_semantic.py
- corpus/cidrize_seeds.txt
- config/cidrize_format.json
- codefix.md

### Give cidrize a larger Linux execution timeout
Improvements:
- Added per-target binary timeout registration so slow wrapper targets can override the generic Linux and Windows defaults.
- Configured `cidrize` to use a 90-second Linux timeout instead of the shared 30-second limit.

Reasons:
- The `cidrize` Linux wrapper was repeatedly hitting the generic Frida/Linux timeout, which made runs fill up with untrusted `TIMEOUT` instrumentation noise instead of parser-driven outcomes.
- A target-specific timeout keeps faster binaries on the old default while giving slow wrapper processes enough time to finish.

Key files changed:
- fuzzer/executor.py
- main.py
- config/cidrize_format.json
- codefix.md

### Keep parser-reported bug classes authoritative
Improvements:
- Stopped the executor from rewriting parser-reported bug classes with oracle-based remapping when a target already emitted an explicit classification.
- Parser output now remains the source of truth for runs such as `cidrize`, while the oracle is still attached as supplemental metadata.

Reasons:
- The wrapped parser already reports whether an input was treated as a validity, invalidity, bonus, or related parser-side finding.
- Reclassifying those parser-emitted results through the oracle could make `cidrize` outputs look wrong relative to what the parser actually said.

Key files changed:
- fuzzer/executor.py
- codefix.md

### Add rebuild utility for consolidated bug-count CSVs
Improvements:
- Added `evaluation/consolidate_bug_counts.py` to rebuild a consolidated unique-bug CSV from an existing run's `logs/bug_counts.csv`.
- Added a `--replace` mode that can preserve the original event-style CSV as `bug_counts_raw.csv` and rewrite `bug_counts.csv` in place.

Reasons:
- Existing JSON results may already be on disk with the old per-artifact bug-count CSV layout, and rerunning fuzzing just to regenerate the summary is unnecessary.
- A standalone rebuild utility makes old runs easy to normalize for later analysis and plotting.

Key files changed:
- `evaluation/consolidate_bug_counts.py`

## 2026-04-21

### Consolidate JSON bug-count CSV by unique bug site
Improvements:
- Changed the JSON Atheris harness to rewrite `results/json/logs/bug_counts.csv` as an aggregated summary keyed by bug type, exception type, filename, and line number instead of appending one `count=1` row per saved artifact.
- Kept a representative exception message while incrementing the count for repeated sightings of the same JSON bug site.

Reasons:
- The JSON target's `bug_counts.csv` was behaving like an event log, which made repeated hits of the same bug site look like separate unique bugs.
- A consolidated CSV makes the JSON target easier to analyze and aligns it with the repository's unique-bug reporting intent.

Key files changed:
- `fuzzer/json_atheris_harness.py`

## 2026-04-21

### Reclassify IPv6 parse rejections
Improvements:
- Reclassified parser-reported `ParseException` rejects from `bonus` to `invalidity` when the oracle already confirms the IPv6 input is invalid.
- Added a regression check covering parser-reported `bonus` parse rejections on invalid IPv6 input.

Reasons:
- The IPv6 target was surfacing ordinary parse failures as headline `bonus` bugs even when the oracle agreed the input was simply invalid.
- This skewed IPv6 bug reporting toward one large third-party parser bucket instead of reserving headline bug counts for real target faults.

Key files changed:
- fuzzer/executor.py
- evaluation/oracle_checks.py

## 2026-04-21

### Restore extracted IPv6 bug surface for fuzzing
Improvements:
- Switched the extracted IPv6 persistent worker and source-level helpers back to the original `ipv6_mstv.pyc` bytecode instead of importing the strict repo-local source override.
- Restored IPv6 parser exception mapping for `functional`, `boundary`, `performance`, `reliability`, and parse-driven `invalidity` classifications in persistent mode.
- Re-enabled oracle upgrading so valid inputs that the parser rejects are counted as `validity`, and accepted oracle-invalid inputs are counted as `oracle_mismatch`.
- Added a source fallback when the extracted IPv6 `.pyc` has an incompatible Python magic number so persistent/source tooling can still start under a different interpreter.
- Hid the extracted bundle root from `sys.path` while loading the IPv6 source fallback so it imports the environment's `pyparsing` instead of the bundle's incompatible `.pyc` copy.

Reasons:
- The source override made the extracted IPv6 fuzzing path behave like a strict validator, which removed the seeded validity/oracle-mismatch style bug surface and left campaigns disproportionately reporting `bonus`.
- The executor was also preserving parser-reported `invalidity` on valid IPv6 inputs like `::`, which hid real false-reject bugs from the headline metrics.
- Loading the original bytecode again keeps the extracted tooling aligned with the intended buggy target for fuzzing and regression reproduction.
- WSL runs can use a Python version that does not match the extracted `.pyc`, which otherwise crashes the persistent worker before the campaign even starts.
- Even with source fallback, leaving the extracted bundle first on `sys.path` caused imports like `pyparsing` to resolve to bundled incompatible bytecode and crash during module import.

Key files changed:
- fuzzer/persistent_worker.py
- fuzzer/executor.py
- tools/ip_parser_source_runner.py
- tools/ip_parser_afl_harness.py
- evaluation/oracle_checks.py

## 2026-04-21

### Add explicit bonus-path trigger for JSON harness
Improvements:
- Added an opt-in `--trigger-bonus` flag to `json-decoder-main/json_decoder_stv.py` that raises a dedicated `BonusBug` after a successful decode.
- Kept default decoder behavior unchanged so ordinary runs still reflect real parser outcomes.

Reasons:
- The harness already reported unexpected exceptions as `bonus`, but normal CLI inputs had no clean, intentional way to exercise that path.
- An explicit trigger makes it possible to validate logging, counting, and coverage for all harness bug buckets without relying on accidental crashes.

Key files changed:
- `json-decoder-main/json_decoder_stv.py`
- `codefix.md`

### Reject over-nested JSON arrays without crashing Atheris
Improvements:
- Changed the bundled `buggy_json` decoder to translate Python recursion overflows during parse into a normal `JSONDecodeError` for excessive nesting.
- Added a focused regression check that feeds a deeply nested JSON array and asserts the decoder rejects it cleanly.

Reasons:
- Deeply nested array inputs were escaping the target as `RecursionError`, which Atheris/libFuzzer treated as a crash artifact instead of a normal invalid-input rejection.
- Converting this path into a parser error keeps fuzzing runs stable and lets post-processing/replay continue instead of aborting on interpreter recursion limits.

Key files changed:
- `json-decoder-main/buggy_json/decoder_stv.py`
- `evaluation/oracle_checks.py`

### Make fresh-start cleanup resilient on WSL Windows mounts
Improvements:
- Hardened `--fresh-start` result cleanup to retry directory removal and clear read-only bits before retrying.
- Added a fallback that clears the contents of the target results directory without deleting the directory itself when WSL cannot remove the mount-backed root folder.

Reasons:
- JSON runs on WSL against the repo under `/mnt/c/...` could fail before fuzzing started when `shutil.rmtree()` hit `PermissionError` on `results/json`.
- Fresh-start should behave like a robust cleanup step across Windows/WSL filesystem quirks instead of aborting the whole run.

Key files changed:
- `main.py`

### Target JSON decoder bug-bearing paths more directly
Improvements:
- Expanded the JSON seed generator and Atheris harness seed pool with targeted escape, malformed `\u`, deep-nesting, and oversized-integer families.
- Added JSON semantic mutator operations that inject bug-bearing escapes, break unicode escape lengths, stress recursion depth, and replace literals with huge integer tokens.
- Added bootstrap regression checks so these JSON-specific seed and mutator capabilities stay wired in.

Reasons:
- The bundled buggy decoder hides most of its seeded bugs behind specific string-escape and parser-depth shapes that general JSON mutations reach too slowly.
- Making those shapes first-class seeds and mutations improves hit rate for `performance_bug`, `wrong_exception_type`, recursion-driven `bonus`, and large-number conversion failures.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `fuzzer/json_atheris_harness.py`
- `evaluation/bootstrap_checks.py`
- `config/json_format.json`
- `corpus/json_seeds.txt`

### Replace fake 100 percent JSON Atheris coverage with replayed source totals
Improvements:
- Switched JSON Atheris plotting to prefer a saved `coverage.py` replay artifact that measures cumulative `buggy_json` statement-and-branch coverage across the discovered corpus.

Reasons:
- The old chart always reached `100%` because it divided each Atheris `cov` sample by that same run's final `cov`, which was a relative progress signal rather than an absolute target-coverage percentage.

Key files changed:
- `evaluation/json_coverage_replay.py`
- `main.py`
- `evaluation/plot_progress.py`

## 2026-04-20

### Replay JSON timeout artifacts before classifying them
Improvements:
- Changed JSON Atheris artifact post-processing to replay `timeout-*` and `slow-*` inputs through `buggy_json` instead of classifying them purely from the artifact filename.
- Added a bounded replay alarm so genuine unreplayed hangs still stay visible as `TIMEOUT`, while reproducing inputs collapse onto the real `PerformanceBug` traceback site.

Reasons:
- Generic timeout filenames were creating noisy duplicate findings such as `Buggy JSON decoder timed out` even when the same input deterministically raised the intended `PerformanceBug`.
- Replaying the artifact gives source-location deduplication and keeps JSON reports closer to the binary-target reporting style.

Key files changed:
- `main.py`
- `codefix.md`

## 2026-04-21

### Fix evaluation graph generation for Atheris rows
Improvements:
- Added `interesting_test_cases` to the row shape produced from `atheris.log`, using corpus size so the evaluation graph renderer sees the same fallback metric as CSV-backed runs.

Reasons:
- `python evaluation/plot_progress.py json` could finish `progress.svg` and then crash on `eval_graphs.svg` generation with `KeyError: 'interesting_test_cases'`.

Key files changed:
- `evaluation/plot_progress.py`
- `codefix.md`

## 2026-04-20

### JSON harness explores a small decoder mode set
Improvements:
- Added a deterministic mode selector to the JSON Atheris harness so part of the campaign exercises `strict=False`, string-preserving number parsing, and `object_pairs_hook=list` in addition to the default decoder path.
- Mirrored the same mode on the stdlib oracle so these extra option paths expand coverage without creating artificial oracle mismatches.

Reasons:
- Some decoder branches are unreachable when the harness only calls the default `loads(data)` path.
- Keeping the option set tiny preserves fuzzer efficiency while still exercising meaningful library-level behavior beyond the CLI wrapper.

Key files changed:
- `fuzzer/json_atheris_harness.py`
- `codefix.md`

## 2026-04-20

### JSON harness reaches seeded escape bugs
Improvements:
- Raised the JSON Atheris timeout budget so the seeded `PerformanceBug` can raise before libFuzzer aborts the input as a generic timeout.
- Changed the JSON harness to learn skip patterns only after it has already recorded a real performance reproducer, instead of training itself to miss the bug.
- Expanded the JSON seed corpus with escape-heavy inputs that drive the mutator into the `\t`/`\b`/`\f` loop and the greedy `\uXXXX` invalidity path.

Reasons:
- The previous 3 second internal alarm and 5 second outer timeout hid the intended performance bug behind `TIMEOUT` artifacts.
- The old seeds mostly exercised JSON structure, so the mutator rarely reached the bug-bearing string escape logic.

Key files changed:
- `fuzzer/json_atheris_harness.py`
- `main.py`
- `corpus/json_seeds.txt`
- `codefix.md`

## 2026-04-21

### Restore graph unique bugs to real-bug count
Improvements:
- Changed `plot_data` back to recording real deduplicated bugs in the `unique_bugs` series instead of the broader parser-site signature count.
- Renamed the progress panel label from `Unique bug sites` back to `Unique bugs` so the chart matches `stats.txt` and `unique_bugs.json`.

Reasons:
- IPv6 runs produced many parser-message variants from the same parse-error location, which made the graph look like dozens of unique bugs even when only a couple of real bug sites were present.

Key files changed:
- `evaluation/collect_metrics.py`
- `evaluation/plot_progress.py`
- `codefix.md`

## 2026-04-20

### Align progress graph bug counts with parser-site dedup
Improvements:
- Changed `plot_data` so the graphed `unique_bugs` series records parser-site deduplicated bug sites, matching the logic used in `logs/bug_counts.csv`.
- Renamed the SVG panel label from `Unique bugs` to `Unique bug sites` so the chart reflects the broader parser-site count it now shows.

Reasons:
- The previous graph used the narrower real-bug dedup metric, which made runs like IPv4 look inconsistent against `bug_counts.csv` even though both outputs were individually correct under different rules.

Key files changed:
- `evaluation/collect_metrics.py`
- `evaluation/plot_progress.py`
- `codefix.md`

## 2026-04-20

### Flush Frida coverage before teardown
Improvements:
- Updated the Frida Stalker agent to flush buffered events periodically and again during `dispose()` so short-lived parser runs still emit edge coverage before the session detaches.
- Removed the unreachable host-side post-detach flush branch and covered the new agent flush hooks with a regression check.

Reasons:
- Frida runs were successfully following target threads but still finishing with `edge_slots=0`, which strongly indicated buffered coverage was being lost during teardown.

Key files changed:
- `fuzzer/executor.py`
- `evaluation/oracle_checks.py`
- `codefix.md`

## 2026-04-15

### Confirm Frida crashes with hash-mode replay
Improvements:
- Added a metrics-time confirmation step that replays Frida-reported `CRASH` and `TIMEOUT` inputs through the non-Frida `hash` executor before counting them as real crashes.
- Marked Frida-only crash records as instrumentation noise when the same input replays cleanly as a non-crashing outcome such as `invalidity` or `PASS`.
- Saved the replay confirmation result into `bugs.jsonl` for post-run auditability.

Reasons:
- Prevents instrumentation-sensitive failures from inflating real-bug, unique-crash, and `bug_counts.csv` totals.
- Keeps stable target crashes while suppressing false positives that disappear outside the Frida path.

Key files changed:
- `evaluation/collect_metrics.py`
- `fuzzer/executor.py`

### Filter Frida transport failures from crash counts
Improvements:
- Expanded instrumentation-noise detection so Frida agent disconnects and stop-wait timeouts are excluded from aggregated crash bug counts.
- Preserved real target signal-based crashes such as `signal 6` and `signal 11` so only Frida transport/control failures are filtered.

Reasons:
- Prevents `bug_counts.csv` from mixing Frida session failures with actual parser or target-process crashes.
- Keeps downstream crash summaries aligned with the intent of the existing instrumentation-noise filtering.

Key files changed:
- `fuzzer/executor.py`

### Use emitted bug_counts.csv as the parser bug source of truth
Improvements:
- Changed the binary executor to snapshot `results/<target>/logs/bug_counts.csv` before and after each target invocation and derive the parser-reported bug row from the positive count delta.
- Made executor classification prefer that CSV-derived bug type, exception class, filename, and line number before falling back to stdout banner parsing.

Reasons:
- Keeps `bug_type` aligned with the subject binary's own recorded taxonomy instead of re-inferring it from potentially misleading stdout labels.
- Fixes cases where the launcher printed a `validity` banner but the binary's persisted `bug_counts.csv` row classified the same failure as `invalidity`.

Key files changed:
- `fuzzer/executor.py`

### Prefer parser-reported bug kinds over crash fallback
Improvements:
- Reordered executor classification so explicit parser-reported bug kinds such as `validity` and `invalidity` override the provisional `CRASH` fallback when the target still emitted a structured bug report.

Reasons:
- Prevents inputs like `255.00.254.254` from being recorded as crashes when direct replay shows the parser actually reported a semantic bug.
- Keeps abnormal exit codes from hiding more specific parser classifications that are already present in stdout.

Key files changed:
- `fuzzer/executor.py`

### Exclude instrumentation noise from bug-count CSVs
Improvements:
- Filtered `logs/bug_counts.csv` generation so known runtime and instrumentation failures no longer appear in the aggregated bug-count output.
- Applied the same exclusion in the metrics collector and the JSON/Atheris post-processing path to keep CSV behavior consistent across targets.

Reasons:
- Prevents Frida and loader failures such as `loader crashed`, `process not found`, and allocator/runtime crashes from being mistaken for parser bugs in downstream CSV review.
- Aligns `bug_counts.csv` with the repository's existing instrumentation-noise and real-bug classification rules.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`

## 2026-03-26

### Stop classifying bugs from target bug-count text
Improvements:
- Removed bug-type classification based on the target program's printed `Final bug count` summary and custom labels.
- Reworked executor classification to use process outcomes, oracle expectations, and traceback exception class instead: timeouts stay `TIMEOUT`, non-zero exits stay `CRASH`, oracle-valid rejections become `validity`, oracle-invalid parse rejections become `invalidity`, and oracle-invalid non-`ParseException` tracebacks become `bonus`.

Reasons:
- Keeps bug classification grounded in observable runtime behavior and the independent oracle instead of depending on target-specific report formatting.
- Makes the harness more portable across targets that do not emit the same textual bug summaries.

Key files changed:
- `fuzzer/executor.py`

### Strengthen bug bucketing with runtime metadata
Improvements:
- Changed unique bug and unique crash bucketing to use a richer signature built from `bug_type`, `exit_code`, derived signal name when available, normalized exception/output text, and a compact bitmap digest.
- Added the computed signature object to `bugs.jsonl`, `unique_bugs.json`, and saved crash repro files so runs can be compared without re-deriving the bucket logic.

Reasons:
- Makes deduplication less dependent on parser-friendly error strings and closer to standard crash bucketing based on runtime metadata.
- Keeps target `stdout` and `stderr` visible next to the saved signature so it is easier to compare what the buggy program actually reported.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`

### Make executor argv-safe and preserve launcher crash signatures
Improvements:
- Escaped non-transportable fuzz bytes such as embedded NULs into CLI-safe `\x..` sequences before passing them through `--ipstr`, so the harness no longer crashes inside Python before the target launches.
- Filled empty `CRASH` exception messages from stderr/stdout for non-zero process exits, which gives stable deduplication for launcher failures such as PyInstaller startup errors.

Reasons:
- Prevented harness-side `embedded null byte` failures from being misreported as parser crashes.
- Kept crash artifacts and unique-bug signatures useful when the executable fails before producing its normal parser output.

Key files changed:
- `fuzzer/executor.py`

### Preserve parser output in bug artifacts
Improvements:
- Added `stdout`, `stderr`, and `traceback` to `results/<target>/bugs.jsonl` so each recorded bug keeps the parser output that produced it.
- Added the same first-seen parser output fields to `results/<target>/unique_bugs.json` for quick validation of unique bug signatures.
- Expanded saved crash repro files to include the bug type, exit code, input, and captured parser output instead of only the raw input.

Reasons:
- Makes it easy to verify whether a reported bug came from the parser itself or from a harness-side launch failure.
- Preserves enough context to audit timeout and crash classifications after a long fuzzing run without rerunning the target immediately.

Key files changed:
- `evaluation/collect_metrics.py`

### Deduplicate unique crash metrics
Improvements:
- Fixed `unique_crashes` so it counts distinct crash signatures instead of incrementing on every repeated crash event.
- Saved crash repro files only for the first instance of each unique crash signature to keep the metric aligned with the artifact count.
- Handled `exit_code=None` for timeout and launcher-failure paths so crash deduplication works on Linux and Windows without throwing.

Reasons:
- Corrected a misleading metric in `stats.txt` and `plot_data` that made repeated crashes look like steady discovery progress.

## 2026-04-14

### Count unique bugs by source line instead of message text
Improvements:
- Redefined the primary unique-bug metric around canonical bug sites derived from traceback frames, parser-reported filenames and line numbers, and normalized fallback fields.
- Updated `unique_bugs.json`, `bug_coverage_summary.json`, `stats.txt`, and `bugs.jsonl` to carry explicit dedup metadata such as exception class, filename, line number, fault location, and dedup source.
- Changed `logs/bug_counts.csv` aggregation to group findings by bug type, exception class, filename, and line number, while treating exception message as descriptive context only.

Reasons:
- Prevents the same exception class from being merged across different source lines and avoids overcounting message-only variations from the same bug site.
- Makes native runs and Atheris post-processing report unique bugs using the same line-based definition.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`
- Kept post-run charts and summaries honest when a campaign gets stuck repeating the same crash.

Key files changed:
- `evaluation/collect_metrics.py`
## 2026-04-05

### Correct bug timing and oracle-unknown reporting
Improvements:
- Split interesting-result timing from real-bug timing so expected `invalidity` results no longer populate the first-bug metric.
- Added explicit `oracle_unknown_accept` and `oracle_unknown_reject` classifications so unsupported oracle shapes remain visible without being counted as headline bugs.
- Normalized crash/timeout interestingness across executor modes by overlaying stable fallback result signals on top of the runtime bitmap.

Reasons:
- Fixes misleading evaluation metrics and removes silent classification gaps.
- Keeps crash and timeout discovery behavior consistent between behavior-hash and QEMU execution modes.

Key files changed:
- `evaluation/collect_metrics.py`
- `fuzzer/executor.py`
- `PIPELINE.md`

## 2026-04-05

### Reduce oracle unknowns for documented cidrize families
Improvements:
- Reclassified malformed-but-recognizable `cidrize` inputs as invalid supported families instead of letting them fall through to oracle-unknown handling.
- Added structured wildcard and partial-range validation so those families are judged generically rather than by test-case-shaped regexes.
- Stored richer oracle metadata in bug artifacts so shape and normalization context survive after the run.

Reasons:
- Keeps `oracle_unknown_*` focused on truly unmodeled inputs instead of documented families with bad syntax.
- Improves the signal quality of bug classification and post-run debugging.

Key files changed:
- `fuzzer/oracle.py`
- `evaluation/collect_metrics.py`

## 2026-04-05

### Use parser stdout as the primary bug classifier
Improvements:
- Parsed the IPv4 parser's stdout bug markers so executor classification now trusts `validity` and `invalidity` messages emitted by the subject binary.
- Fell back to stderr traceback text when the parser prints an empty stdout traceback block, which fixes prior mislabeling as `oracle_mismatch` or `PASS`.
- Added taxonomy metadata plus `unique_findings.json` so parser-reported findings can be matched directly to presentation labels such as `ValidityBug`, `InvalidityBug`, and `BoundaryBug`.

Reasons:
- Keeps saved bug artifacts aligned with the parser's own declared bug families instead of inferring everything from oracle heuristics.
- Makes it practical to map findings to the project bug taxonomy without hand-auditing stdout after each run.

Key files changed:
- `fuzzer/executor.py`
- `evaluation/collect_metrics.py`

## 2026-04-07

### Align SymPy with PyTorch 2.5.1 CUDA wheel
Improvements:
- Changed `requirements.txt` from `sympy==1.14.0` to `sympy==1.13.1` to match the dependency metadata required by `torch==2.5.1+cu121`.

Reasons:
- `uv pip install` could not resolve the environment because the selected PyTorch wheel requires `sympy==1.13.1` exactly.

Key files changed:
- `requirements.txt`

### Keep JSON fuzzing alive after oracle mismatches
Improvements:
- Changed the Atheris JSON harness to save mismatch reproducers and return cleanly instead of raising `AssertionError` and terminating the libFuzzer campaign.
- Updated JSON post-processing to classify saved artifacts by replaying them through the oracle, including `wrong_exception_type` findings.

Reasons:
- The previous harness stopped the JSON campaign on the first discovered mismatch, which prevented continued in-vivo testing and meaningful progress-over-time evaluation.
- Persisting the reproducer without aborting the process keeps bug discovery intact while allowing the fuzzer to continue exploring new inputs.

Key files changed:
- `fuzzer/json_atheris_harness.py`
- `main.py`

## 2026-04-09

### Default cJSON target to ASan build
Improvements:
- Switched the `cjson` format config to the `cjson_driver_asan` binary so memory-safety findings are surfaced directly during normal `cjson` fuzzing runs.
- Updated the README to list `cjson` as a first-class target and document the ASan-backed default.

Reasons:
- This makes cJSON memory errors visible immediately instead of requiring a separate manual crash triage pass with a different executable.

Key files changed:
- `config/cjson_format.json`
- `README.md`
## 2026-04-09

### Align coverage wording and bug-site deduplication
Improvements:
- Changed user-facing metrics and plots to report `coverage` / `coverage_seen` instead of `behavior` / `behaviors_seen`.
- Reworked unique bug counting to deduplicate explicit parser-raised bug sites using the parser-reported bug kind, exception class, filename, line number, and parser-reported message.
- Added parser bug-site metadata to saved findings and a `unique_real` breakdown in the coverage summary so parser-site counts are visible in machine-readable outputs.

Reasons:
- The previous wording suggested a softer behavior proxy even in places where the metric is used and presented as the run's main coverage signal.
- The previous unique bug metric counted broader failure signatures and oracle mismatches, which did not match the intended interpretation of "actual parser bug raises".

Key files changed:
- `fuzzer/executor.py`
- `evaluation/collect_metrics.py`
- `evaluation/plot_progress.py`
- `main.py`

## 2026-04-09

### Use pure AFL-style novelty in QEMU mode
Improvements:
- Removed the extra bug/outcome signal overlay from the QEMU executor path so `afl-showmap -Q` coverage is now consumed directly.
- Switched QEMU novelty tracking to an AFL-style virgin bitmap with hit-count bucketing, while keeping the existing behavior-hash fallback for non-QEMU modes.
- Added a regression check covering repeated hits, repeated buckets, and new hit-count buckets on the same edge.

Reasons:
- The previous QEMU path mixed real edge coverage with synthetic bug-result bits, which made "new behavior" broader than the raw AFL/QEMU signal.
- Using the virgin-bitmap method keeps QEMU runs aligned with the intended AFL-style notion of new coverage.

Key files changed:
- `fuzzer/executor.py`
- `fuzzer/coverage.py`
- `main.py`
- `evaluation/oracle_checks.py`
- `codefix.md`

## 2026-04-09

### Make parser output and exceptions the classification source of truth
Improvements:
- Changed executor classification so parser-reported bug kinds and observable exception outcomes determine `bug_type`, while oracle data is kept only as attached metadata.
- Stopped counting binary-target `functional` findings under the old `oracle_mismatch` label and updated stats output to report `Functional bugs` instead.
- Updated regression checks so terminal labels and saved artifacts now follow the same parser/exception-based classification path.

Reasons:
- The previous flow could relabel results based on oracle interpretation, which made terminal output and saved bug labels drift away from what the parser or traceback actually reported.
- Keeping classification grounded in parser output and runtime evidence makes the bitmap, logs, and unique-bug accounting easier to reason about.

Key files changed:
- `fuzzer/executor.py`
- `evaluation/collect_metrics.py`
- `evaluation/oracle_checks.py`
- `codefix.md`

## 2026-04-15

### Collapse unique bug counts by bug site
Improvements:
- Changed unique-bug deduplication so findings with the same source filename and line count as one bug even when their parser messages or exception classes differ.
- Added explicit `site_hit_count` values to saved unique-bug entries so each deduplicated bug still records how many times that source line was hit.
- Updated the saved `unique_bugs.json` count definition text in both the live metrics collector and the Atheris post-processing path to match the new rule.

Reasons:
- Repeated failures from the same code site were being split into multiple unique bugs purely because the message text or exception flavor changed.
- This overstated headline unique-bug totals and disagreed with the intended "same line means same bug" interpretation across bug types.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`
- `codefix.md`

## 2026-04-14

### Add opt-in Frida executor diagnostics
Improvements:
- Added `FRIDA_DEBUG_FUZZER=1` tracing around the Linux Frida executor path so attach, script load, non-`send` script messages, and final edge-slot counts are visible during debugging.
- Surfaced otherwise-silent Frida script errors in the executor's message handler to make Stalker and agent failures easier to distinguish from empty coverage.
- Moved the temporary process stop from `preexec_fn` to a parent-side `SIGSTOP` immediately after spawn so the first Frida execution no longer wedges inside `subprocess.Popen(...)`.
- Updated the embedded Frida agent to use the current `Process.enumerateModules()` and `Process.enumerateThreads()` APIs instead of removed `...Sync()` variants.
- Added Frida agent debug messages for target-module selection, thread enumeration, and thread-follow attempts so zero-coverage runs can be narrowed down without guessing.
- Fixed Linux `--coverage hash` runs to use the Linux binary instead of falling back to the Windows PyInstaller executable.
- Removed the parent-side `SIGSTOP`/`SIGCONT` around Frida attach after debugging showed the stopped process exposed zero threads to the agent and led to timeouts with no coverage.
- Excluded known Frida/runtime failure strings such as `loader crashed`, `process not found`, `the connection is closed`, and allocator crash messages from headline real-bug and unique-crash counts while keeping them logged as instrumentation noise.

Reasons:
- `Executor mode : Frida` only confirms mode selection, not that attach, script injection, or edge collection actually succeeded.
- The previous message handler dropped non-`send` messages, hiding useful Frida error output during instrumentation failures.
- Stopping the child in `preexec_fn` can block `Popen` before the parent regains control, which makes the first execution look stuck before any Frida debug output appears.
- Frida 17 rejected the agent at load time with `TypeError: not a function`, which prevented Stalker from starting and left coverage empty.
- The remaining zero-edge timeout needed more visibility into which module and threads the agent was actually following.
- On WSL, forcing `hash` should still keep execution on the native Linux binary so performance comparisons are meaningful.
- The extra diagnostics showed that attaching while the child was stopped yielded `threadCount: 0`, so the agent had no threads to follow and never produced Stalker events.
- Known Frida/runtime failure modes were inflating crash-centric headline metrics even though they were harness artifacts rather than target bugs.

Key files changed:
- `fuzzer/executor.py`
- `codefix.md`

## 2026-04-20

### Reduce Frida edge transport volume
Improvements:
- Changed the Frida agent to send each edge slot at most once per execution instead of repeatedly forwarding every hit.
- Extended the Frida flush debug summary with the total number of unique slots seen during the run.

Reasons:
- After the attach/resume fixes, the remaining instability showed up while Stalker was successfully producing very large event batches, pointing to message transport pressure between the Frida agent and Python host.
- Coverage novelty for this fuzzer is driven primarily by edge presence, so deduplicating per-execution slot messages keeps the useful signal while sharply reducing transport load.

Key files changed:
- `fuzzer/executor.py`
- `codefix.md`

## 2026-04-20

### Avoid double-cleaning detached Frida sessions
Improvements:
- Stopped calling Frida script flush/unload and session detach paths after the session has already reported `process-terminated`.
- Kept output callback cleanup but skipped redundant teardown work on already-detached sessions.

Reasons:
- Coverage collection now works, so the remaining WSL-side instability is most likely in the post-detach cleanup path rather than in Stalker setup.
- Touching an already-detached Frida session or script can trigger native cleanup races in the bindings.

Key files changed:
- `fuzzer/executor.py`
- `codefix.md`

## 2026-04-20

### Split bug-count outputs into dedup and raw CSVs
Improvements:
- Kept `logs/bug_counts.csv` as the deduplicated parser-bug summary used by the executor and plotting code.
- Added `logs/bug_counts_raw.csv` with one row per logged finding so post-run analysis can inspect raw bug sightings without losing event-level detail.
- Applied the same split to Atheris post-processing so JSON-target runs now emit both CSV views too.

Reasons:
- The existing `bug_counts.csv` was useful as a unique-bug summary, but it could not answer questions about repeated sightings or per-execution bug volume.
- Keeping the deduplicated filename stable avoids breaking parser-site delta tracking in the binary executor.

Key files changed:
- `evaluation/collect_metrics.py`
- `main.py`
- `codefix.md`

## 2026-04-20

### Suppress Frida crash headlines on unstable backend
Improvements:
- Marked all Frida-mode `CRASH` and `TIMEOUT` results as untrusted for headline crash counting on this machine while still logging them to `bugs.jsonl` for debugging.
- Added an explicit `frida_crash_untrusted` flag to saved bug entries and a summary note in `stats.txt` so post-run analysis does not accidentally treat those crash counts as authoritative.

## 2026-04-21

### Replace buggy extracted IPv6 parser with strict source override
Improvements:
- Added a repo-local `buggy_ipyparse/ipv6_mstv.py` source override that shadows the extracted bytecode and validates IPv6 strings with `ipaddress.IPv6Address`.
- Fixed the extracted Linux IPv6 path so valid inputs like `::` and `2001:db8::1` parse successfully while malformed forms such as `1::2::3`, `1:::2`, and `::ffff:192.0.2.999` now fail with `ParseException` instead of surfacing custom parser bug exceptions.
- Updated the persistent worker and directed IPv6 probe so regression checks exercise the fixed source module rather than forcing the stale `.pyc`.

Reasons:
- The original extracted IPv6 parser bytecode contained seeded functional, invalidity, and reliability bugs that inflated fuzzer findings with parser defects rather than oracle-relevant behavior.
- The Linux persistent path was still loading the old sourceless module directly, which would have bypassed any repo-local fix.

Key files changed:
- `linux-ipv6-parser_extracted/PYZ.pyz_extracted/buggy_ipyparse/ipv6_mstv.py`
- `fuzzer/persistent_worker.py`
- `evaluation/ipv6_bug_path_probe.py`

Reasons:
- The current Frida backend is unstable in this environment and can terminate the harness or emit native runtime failures unrelated to target correctness.
- Treating those events as trusted crash counts was overstating crash-centric results and obscuring which findings actually come from the parser.

Key files changed:
- `evaluation/collect_metrics.py`
- `codefix.md`

## 2026-04-20

## 2026-04-21

### Keep JSON Atheris invalidities tied to parser sites
Improvements:
- Changed the JSON Atheris harness to log traceback-derived exception type, filename, and line number into `results/json/logs/bug_counts.csv`.
- Switched invalidity dedup from message-only to `(message, filename, lineno)` so distinct parser rejection sites are preserved.
- Kept artifact dedup by input hash, so repeated bytes still do not flood the crash directory.

Reasons:
- Message-only invalidity dedup hid parser-owned sites such as `Expecting ':' delimiter` whenever another input had already produced the same text.
- Matching the direct runner's traceback ownership makes Atheris findings easier to compare against `json_decoder_stv.py` output during triage.

Key files changed:
- `fuzzer/json_atheris_harness.py`
- `codefix.md`

### Switch Frida executor to Frida-managed spawn flow
Improvements:
- Reworked the Linux Frida executor to use Frida-managed `spawn -> attach -> load -> resume` instead of launching the target with `subprocess.Popen()` and racing to attach afterward.
- Captured spawned-process stdout/stderr through Frida piped stdio and waited on session detachment rather than `communicate()`.
- Preserved the existing parser-output and oracle classification flow on top of the new Frida lifecycle.

Reasons:
- Local Frida sanity checks succeeded when Frida owned the spawn/attach sequence, while the repo's `Popen -> attach(pid)` flow was still triggering abrupt harness exits on WSL.
- Suspending the process before first instruction removes the attach race that was most likely causing intermittent `process not found` and early native failures.

Key files changed:
- `fuzzer/executor.py`
- `codefix.md`
## 2026-04-21

### Expand cidrize malformed-family coverage
Improvements:
- Added explicit CIDRize seed and Tier 2 semantic mutation support for parser-facing malformed families that trigger repeated separator and fallback parsing paths.
- Seed generation now emits examples for extra hyphens, extra CIDR slashes, repeated glob stars, missing digits before a range hyphen, and IPv4-plus-netmask fallback strings.
- Added oracle regression checks for these malformed CIDRize inputs so future changes keep them classified as supported invalid inputs.

Reasons:
- The fuzzer already explored many invalid CIDRize forms, but it was not targeting the exact malformed families needed to hit `InvalidCidrFormatError` and fallback `AddrFormatError` branches in the bundled subject reliably.
- Making these families first-class seeds and semantic mutations improves reproducibility and reduces dependence on luck during short fuzzing runs.

Key files changed:
- `fuzzer/seed_generator.py`
- `fuzzer/mutation/tier2_semantic.py`
- `evaluation/oracle_checks.py`
- `corpus/cidrize_seeds.txt`
- `config/cidrize_format.json`

## 2026-04-21

### Ignore XML namespace declarations in oracle summaries
Improvements:
- Excluded `xmlns` namespace declaration attributes from the XML `minidom` structural summary so it matches `ElementTree`'s semantic attribute view.
- Applied the same normalization in artifact replay classification so saved XML crashes and live harness findings use the same comparison rule.

Reasons:
- Namespace-qualified XML such as `<ns:root xmlns:ns="urn:test"><ns:item/></ns:root>` was being mislabeled as `oracle_mismatch` only because `minidom` exposes namespace declarations as DOM attributes while `ElementTree` does not.
- Normalizing away namespace declarations removes this false positive without hiding genuine attribute-structure differences.

Key files changed:
- `fuzzer/xml_atheris_harness.py`
- `main.py`
- `codefix.md`

## 2026-04-21

### Keep traceback findings parser-owned
Improvements:
- Changed executor classification so parser-reported bugs and traceback-backed rejections no longer attach structured-oracle verdicts.
- Left quiet accepted executions on the existing oracle path so non-bug passes still keep oracle metadata for scheduling and analysis.
- Added regression checks covering parser-reported findings, traceback-backed invalidity, traceback-backed bonus bugs, and quiet-pass oracle attachment.

Reasons:
- When the parser already explains a failure with its own traceback or explicit bug report, layering oracle metadata on top makes the finding harder to interpret and can blur whether the bug was parser-discovered or oracle-derived.
- Keeping these findings parser-owned makes IPv6 traceback triage cleaner while preserving the oracle for cases where it still adds value.

Key files changed:
- `fuzzer/executor.py`
- `evaluation/oracle_checks.py`
- `codefix.md`
## 2026-04-21

### Handle JSON recursion-depth findings without aborting Atheris
Improvements:
- Treated `RecursionError` from the JSON target as a classified parser outcome in the Atheris harness instead of letting it escape and terminate the fuzz run.
- Extended JSON artifact reclassification and coverage replay to tolerate recursion-depth failures during post-processing.

Reasons:
- Deeply nested JSON arrays were being reported as generic harness crashes even when they represented a real decoder rejection bug.
- Uncaught `RecursionError` also caused source-coverage replay to be skipped for affected runs.

Key files changed:
- fuzzer/json_atheris_harness.py
- main.py
- evaluation/json_coverage_replay.py
