import json
from pathlib import Path

_HERE = Path(__file__).parent.parent  # project root


def load_format(name: str) -> dict:
    path = _HERE / "config" / f"{name.lower()}_format.json"
    return json.loads(path.read_text())
