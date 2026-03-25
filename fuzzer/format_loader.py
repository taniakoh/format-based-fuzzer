import json
from pathlib import Path

_HERE = Path(__file__).parent.parent  # project root


def load_format(name: str) -> dict:
    """Load config/<name>_format.json.

    Returns an empty dict (with a warning) if the file does not exist so the
    pipeline can still run with defaults instead of crashing on import.
    """
    path = _HERE / "config" / f"{name.lower()}_format.json"
    if not path.exists():
        print(f"[format_loader] No config found for '{name}' ({path}) — using empty config.")
        return {}
    return json.loads(path.read_text())
