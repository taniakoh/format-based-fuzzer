"""
Traceback-based bug analysis.

Reads bugs.jsonl produced by a fuzzing run and deduplicates bugs using
their traceback text instead of the oracle.  Produces:

  results/<target>/traceback_unique_bugs.json   — one entry per unique traceback
  results/<target>/traceback_bugs.csv           — flat CSV for spreadsheet analysis

Usage
-----
  python -m evaluation.traceback_analysis ipv4
  python -m evaluation.traceback_analysis ipv6
  python -m evaluation.traceback_analysis all   # both targets
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).parent.parent
RESULTS_DIR = _HERE / "results"


# ── Core extraction ────────────────────────────────────────────────────────────

_FRAME_RE = __import__("re").compile(
    r'^\s*File\s+"([^"]+)",\s+line\s+(\d+)'
)
_TAIL_FRAMES = 3   # how many bottom frames to use for deduplication


def extract_traceback(bug_entry: dict) -> str:
    """Return the raw traceback string from a bugs.jsonl entry, or ''."""
    return (bug_entry.get("traceback") or "").strip()


def _parse_traceback_frames(tb: str) -> list[tuple[str, str]]:
    """Return a list of (file, lineno) pairs for every frame in the traceback."""
    frames = []
    for line in tb.splitlines():
        m = _FRAME_RE.match(line)
        if m:
            frames.append((m.group(1), m.group(2)))
    return frames


def _exception_class(tb: str) -> str:
    """
    Return the exception *class* name from the last line of the traceback.

    e.g. ``buggy_ipyparse.ipv4_stv.InvalidityBug: message`` → ``InvalidityBug``
         ``pyparsing.exceptions.ParseException: ...``         → ``ParseException``
    """
    for line in reversed(tb.splitlines()):
        line = line.strip()
        if not line or line.startswith("File ") or line.startswith("Traceback"):
            continue
        # Take everything before the first colon, then grab the last dotted segment
        class_part = line.split(":")[0].strip()
        return class_part.rsplit(".", 1)[-1]
    return ""


def traceback_dedup_key(bug_entry: dict) -> str:
    """
    Stable deduplication key based on *where* the bug was raised, not its message.

    Key components (in order of preference):
      bug_type + exception_class + bottom N frames (file + line number only)

    Two inputs are the **same bug** when they hit the same exception type at
    the same source location, even if the exception message differs
    (e.g. ``ParseException: Expected '.', found '5'`` vs ``found 'A'``).

    Falls back to the exception message when no parseable traceback exists
    (covers CRASH / TIMEOUT results).
    """
    bug_type = str(bug_entry.get("bug_type", "unknown"))
    tb = extract_traceback(bug_entry)

    if tb:
        frames = _parse_traceback_frames(tb)
        tail = frames[-_TAIL_FRAMES:] if frames else []
        exc_class = _exception_class(tb)
        frame_str = "|".join(f"{f}:{n}" for f, n in tail)
        payload = f"{bug_type}|{exc_class}|{frame_str}"
    else:
        exc = str(bug_entry.get("exception", "")).strip()
        payload = f"{bug_type}|exc|{exc}" if exc else f"{bug_type}|no_traceback"

    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:32]


# ── Per-target analysis ────────────────────────────────────────────────────────

def analyse_target(target: str) -> None:
    bugs_path = RESULTS_DIR / target / "bugs.jsonl"
    if not bugs_path.exists():
        print(f"[traceback_analysis] No bugs.jsonl found for target '{target}' — skipping.")
        return

    # ── Pass 1: read all entries ───────────────────────────────────────────────
    all_entries: list[dict] = []
    for line in bugs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                all_entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not all_entries:
        print(f"[traceback_analysis] bugs.jsonl for '{target}' is empty.")
        return

    # ── Pass 2: deduplicate by traceback key ──────────────────────────────────
    total_by_type: Counter[str] = Counter()
    unique_entries: dict[str, dict] = {}   # key → first-seen entry
    key_total_hits: Counter[str] = Counter()

    for entry in all_entries:
        bug_type = str(entry.get("bug_type", "unknown"))
        total_by_type[bug_type] += 1

        key = traceback_dedup_key(entry)
        key_total_hits[key] += 1
        if key not in unique_entries:
            tb = extract_traceback(entry)
            frames = _parse_traceback_frames(tb)
            tail = frames[-_TAIL_FRAMES:] if frames else []
            unique_entries[key] = {
                "traceback_key":    key,
                "bug_type":         bug_type,
                "exception_class":  _exception_class(tb) if tb else "",
                "fault_location":   f"{tail[-1][0]}:{tail[-1][1]}" if tail else "",
                "bottom_frames":    [f"{f}:{n}" for f, n in tail],
                "first_seen_exec":  entry.get("exec", None),
                "total_occurrences": 0,          # filled in below
                "example_input":    entry.get("input", ""),
                "exception":        entry.get("exception", ""),
                "traceback":        tb,
                "traceback_snippet": tb[:300] + ("…" if len(tb) > 300 else ""),
                "has_traceback":    bool(tb),
            }

    # Attach total hit counts
    unique_by_type: Counter[str] = Counter()
    for key, rec in unique_entries.items():
        rec["total_occurrences"] = key_total_hits[key]
        unique_by_type[rec["bug_type"]] += 1

    # ── Build JSON payload ─────────────────────────────────────────────────────
    sorted_entries = sorted(
        unique_entries.values(),
        key=lambda r: (r["first_seen_exec"] or 0),
    )
    json_payload = {
        "target": target,
        "total_bugs_logged": len(all_entries),
        "unique_by_traceback": len(unique_entries),
        "by_bug_type": {
            "total": dict(sorted(total_by_type.items())),
            "unique_by_traceback": dict(sorted(unique_by_type.items())),
        },
        "entries": sorted_entries,
    }

    out_dir = RESULTS_DIR / target
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "traceback_unique_bugs.json"
    json_path.write_text(
        json.dumps(json_payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    # ── Build CSV ──────────────────────────────────────────────────────────────
    csv_path = out_dir / "traceback_bugs.csv"
    csv_columns = [
        "traceback_key",
        "bug_type",
        "exception_class",
        "fault_location",
        "first_seen_exec",
        "total_occurrences",
        "has_traceback",
        "exception",
        "traceback_snippet",
        "example_input",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted_entries)

    # ── Summary to stdout ──────────────────────────────────────────────────────
    print(f"\n=== Traceback analysis: {target} ===")
    print(f"  Total bugs logged      : {len(all_entries)}")
    print(f"  Unique (by traceback)  : {len(unique_entries)}")
    print("  By bug type (total / unique):")
    for bt in sorted(set(list(total_by_type) + list(unique_by_type))):
        print(f"    {bt:<25} total={total_by_type[bt]:>4}  unique={unique_by_type[bt]:>4}")
    print(f"  -> JSON : {json_path}")
    print(f"  -> CSV  : {csv_path}")


# ── CLI entry point ────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("Usage: python -m evaluation.traceback_analysis <target|all>")
        sys.exit(1)

    targets_arg = args[0].lower()
    if targets_arg == "all":
        available = [p.name for p in RESULTS_DIR.iterdir() if p.is_dir()] if RESULTS_DIR.exists() else []
        if not available:
            print("No results directories found.")
            sys.exit(1)
        for t in sorted(available):
            analyse_target(t)
    else:
        analyse_target(targets_arg)


if __name__ == "__main__":
    main()
