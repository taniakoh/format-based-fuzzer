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
