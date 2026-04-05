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
