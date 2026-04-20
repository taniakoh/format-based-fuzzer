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

Reasons:
- The current Frida backend is unstable in this environment and can terminate the harness or emit native runtime failures unrelated to target correctness.
- Treating those events as trusted crash counts was overstating crash-centric results and obscuring which findings actually come from the parser.

Key files changed:
- `evaluation/collect_metrics.py`
- `codefix.md`

## 2026-04-20

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
