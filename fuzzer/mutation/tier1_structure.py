"""
Tier 1 — Structural Mutations.

For JSON inputs this tier parses the value and applies one structural
transformation: adding/removing keys, changing nesting depth, wrapping the
root, or coercing a leaf to a boundary type.  Non-JSON inputs (IPv4, IPv6,
etc.) pass through unchanged.

Operates on the *parsed* object so mutations always produce well-formed JSON,
giving tier 2 (syntax damage) a structurally different but valid starting
point.
"""

from __future__ import annotations

import json
import random

_BOUNDARY_VALUES: list = [None, True, False, 0, 1, -1, 1.7976931348623157e308, 1e-308, "", [], {}]

_INJECT_KEYS = [
    "x", "id", "type", "value", "data", "key", "flag", "n", "extra",
    "__proto__", "constructor", "null", "true", "false", "0", "",
]


def _rkey() -> str:
    return random.choice(_INJECT_KEYS)


def _rval():
    return random.choice(_BOUNDARY_VALUES)


# ── structural helpers ────────────────────────────────────────────────────────

def _add_key(obj):
    """Insert a random key-value pair into a dict (recursing with 30% chance)."""
    if isinstance(obj, dict):
        if not obj or random.random() < 0.70:
            obj[_rkey()] = _rval()
        else:
            k = random.choice(list(obj.keys()))
            obj[k] = _add_key(obj[k])
    elif isinstance(obj, list) and obj:
        obj[random.randrange(len(obj))] = _add_key(random.choice(obj))
    return obj


def _remove_key(obj):
    """Delete a random key from a dict; preserves at least one key."""
    if isinstance(obj, dict) and len(obj) > 1:
        if random.random() < 0.70:
            del obj[random.choice(list(obj.keys()))]
        else:
            k = random.choice(list(obj.keys()))
            obj[k] = _remove_key(obj[k])
    elif isinstance(obj, list) and obj:
        obj[random.randrange(len(obj))] = _remove_key(random.choice(obj))
    return obj


def _nest_value(obj):
    """Wrap a leaf value one level deeper: v → {"<key>": v}."""
    if isinstance(obj, dict) and obj:
        k = random.choice(list(obj.keys()))
        if isinstance(obj[k], (dict, list)):
            obj[k] = _nest_value(obj[k])
        else:
            obj[k] = {_rkey(): obj[k]}
    elif isinstance(obj, list) and obj:
        i = random.randrange(len(obj))
        if isinstance(obj[i], (dict, list)):
            obj[i] = _nest_value(obj[i])
        else:
            obj[i] = {_rkey(): obj[i]}
    return obj


def _wrap_root(obj):
    """Wrap the entire root in an array or a single-key object."""
    if random.random() < 0.5:
        return [obj]
    return {_rkey(): obj}


def _type_coerce(obj):
    """Replace one leaf value with a boundary-type value."""
    if isinstance(obj, dict) and obj:
        k = random.choice(list(obj.keys()))
        if isinstance(obj[k], (dict, list)):
            obj[k] = _type_coerce(obj[k])
        else:
            obj[k] = _rval()
    elif isinstance(obj, list) and obj:
        i = random.randrange(len(obj))
        if isinstance(obj[i], (dict, list)):
            obj[i] = _type_coerce(obj[i])
        else:
            obj[i] = _rval()
    return obj


def _append_element(obj):
    """Append a random value to an array, or wrap a scalar root in a list."""
    if isinstance(obj, list):
        obj.append(_rval())
    elif isinstance(obj, dict) and obj:
        k = random.choice(list(obj.keys()))
        if isinstance(obj[k], list):
            obj[k].append(_rval())
        else:
            obj[k] = _append_element(obj[k])
    else:
        return [obj, _rval()]
    return obj


# ── mutator ───────────────────────────────────────────────────────────────────

class StructureMutator:
    """
    Structural mutator for JSON seeds; transparent pass-through for all others.

    Parses the seed as JSON on each call.  On success it applies one randomly
    chosen structural operation and re-serialises.  Any parse error or
    unexpected exception returns the original bytes unchanged so downstream
    tiers always receive valid input.
    """

    APPLY_PROB = 0.40

    _OPERATIONS = [
        "add_key",
        "remove_key",
        "nest_value",
        "wrap_root",
        "type_coerce",
        "append_element",
    ]

    def mutate(self, data: bytes) -> bytes:
        if random.random() > self.APPLY_PROB:
            return data
        try:
            obj = json.loads(data.decode("latin-1"))
        except Exception:
            return data

        op = random.choice(self._OPERATIONS)
        try:
            result = self._apply(op, obj)
            return json.dumps(result, ensure_ascii=False, allow_nan=True).encode()
        except Exception:
            return data

    def _apply(self, op: str, obj):
        if op == "add_key":
            return _add_key(obj)
        if op == "remove_key":
            return _remove_key(obj)
        if op == "nest_value":
            return _nest_value(obj)
        if op == "wrap_root":
            return _wrap_root(obj)
        if op == "type_coerce":
            return _type_coerce(obj)
        if op == "append_element":
            return _append_element(obj)
        return obj
