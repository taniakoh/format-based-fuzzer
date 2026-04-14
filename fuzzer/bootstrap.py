from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
CORPUS_DIR = PROJECT_ROOT / "corpus"

DEFAULT_BOOTSTRAP_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")

_PRINTABLE_ASCII = set(range(32, 127)) | {9, 10, 13}


def _bootstrap_path(
    target: str,
    fmt_config: dict | None = None,
    *,
    project_root: Path | None = None,
) -> Path:
    root = project_root or PROJECT_ROOT
    explicit = (fmt_config or {}).get("bootstrap_profile_path")
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = root / path
        return path
    return root / "config" / f"{target.lower()}_bootstrap.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    printable = sum(byte in _PRINTABLE_ASCII for byte in data)
    return (printable / len(data)) >= 0.85


def infer_format_kind(target: str, fmt_config: dict | None = None) -> str:
    config = fmt_config or {}
    explicit = str(config.get("format_kind", "")).strip().lower()
    if explicit in {"text", "binary", "container"}:
        return explicit

    target_lower = target.lower()
    if any(token in target_lower for token in ("pdf", "zip", "png", "gif", "jpeg", "jpg", "bmp")):
        return "container"

    examples = config.get("valid_examples", [])
    if examples:
        decoded = [example.encode("utf-8", errors="replace") for example in examples if isinstance(example, str)]
        if decoded and all(_is_probably_text(example) for example in decoded):
            return "text"
        return "binary"
    return "text"


def load_bootstrap_profile(
    target: str,
    fmt_config: dict | None = None,
    *,
    project_root: Path | None = None,
) -> dict:
    path = _bootstrap_path(target, fmt_config, project_root=project_root)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[bootstrap] Failed to read {path}: {exc}")
        return {}


def enrich_format_config(
    target: str,
    fmt_config: dict,
    *,
    project_root: Path | None = None,
) -> dict:
    config = dict(fmt_config)
    profile = load_bootstrap_profile(target, config, project_root=project_root)
    config["bootstrap_profile"] = profile
    if not profile:
        return config

    for key in (
        "format_kind",
        "seed_encoding",
        "source",
        "token_hints",
        "mutation_hints",
        "generic_mutation_hints",
    ):
        if key in profile and key not in config:
            config[key] = profile[key]
    return config


def _decode_seed_entry(entry: object, seed_encoding: str) -> bytes:
    if isinstance(entry, dict):
        if "data" in entry:
            payload = entry["data"]
        elif "value" in entry:
            payload = entry["value"]
        else:
            payload = ""
    else:
        payload = entry

    if isinstance(payload, bytes):
        return payload

    text = str(payload)
    if seed_encoding == "base64":
        return base64.b64decode(text.encode("ascii"))
    if seed_encoding == "latin-1":
        return text.encode("latin-1", errors="replace")
    return text.encode("utf-8", errors="replace")


def decode_bootstrap_seed_examples(profile: dict) -> list[bytes]:
    if not profile:
        return []
    seed_encoding = str(profile.get("seed_encoding", "utf-8")).lower()
    seeds: list[bytes] = []
    for bucket in ("seed_examples_valid", "seed_examples_invalid"):
        for entry in profile.get(bucket, []):
            try:
                seeds.append(_decode_seed_entry(entry, seed_encoding))
            except (ValueError, TypeError, base64.binascii.Error):
                continue
    return seeds


def _decode_seed_json_entries(entries: list[object]) -> list[bytes]:
    decoded: list[bytes] = []
    for entry in entries:
        if isinstance(entry, dict):
            encoding = str(entry.get("encoding", "utf-8")).lower()
            decoded.append(_decode_seed_entry(entry, encoding))
        elif isinstance(entry, str):
            decoded.append(entry.encode("utf-8", errors="replace"))
    return decoded


def load_corpus_seed_bytes(
    target: str,
    *,
    project_root: Path | None = None,
) -> list[bytes]:
    root = project_root or PROJECT_ROOT
    corpus_dir = root / "corpus"
    seeds: list[bytes] = []

    seed_dir = corpus_dir / f"{target}_seeds"
    if seed_dir.exists() and seed_dir.is_dir():
        for path in sorted(p for p in seed_dir.iterdir() if p.is_file()):
            try:
                seeds.append(path.read_bytes())
            except OSError:
                continue

    txt_path = corpus_dir / f"{target}_seeds.txt"
    if txt_path.exists():
        try:
            for line in txt_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    seeds.append(line.encode("utf-8"))
        except OSError:
            pass

    json_path = corpus_dir / f"{target}_seeds.json"
    if json_path.exists():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                seeds.extend(_decode_seed_json_entries(payload))
        except (OSError, json.JSONDecodeError):
            pass

    return seeds


def load_seed_inputs(
    target: str,
    fmt_config: dict | None = None,
    *,
    allow_bootstrap: bool,
    project_root: Path | None = None,
) -> list[bytes]:
    seeds = load_corpus_seed_bytes(target, project_root=project_root)
    if seeds:
        return seeds

    config = fmt_config or {}
    if allow_bootstrap:
        profile = config.get("bootstrap_profile") or load_bootstrap_profile(
            target,
            config,
            project_root=project_root,
        )
        bootstrap_seeds = decode_bootstrap_seed_examples(profile)
        if bootstrap_seeds:
            return bootstrap_seeds

    examples = config.get("valid_examples", [])
    if examples:
        return [str(example).encode("utf-8", errors="replace") for example in examples]
    return [b""]


def _encode_seed(seed: bytes, seed_encoding: str) -> str:
    if seed_encoding == "base64":
        return base64.b64encode(seed).decode("ascii")
    if seed_encoding == "latin-1":
        return seed.decode("latin-1", errors="replace")
    return seed.decode("utf-8", errors="replace")


def _extract_ascii_markers(data: bytes) -> list[str]:
    text = data.decode("latin-1", errors="ignore")
    candidates = re.findall(r"[A-Za-z][A-Za-z0-9/_-]{2,16}", text)
    seen: list[str] = []
    for token in candidates:
        if token not in seen:
            seen.append(token)
        if len(seen) >= 8:
            break
    return seen


def _token_hints_from_examples(target: str, examples: list[bytes], format_kind: str) -> dict:
    hints: dict[str, list[str]] = {
        "magic_bytes": [],
        "delimiters": [],
        "section_markers": [],
        "length_fields": [],
        "field_like_regions": [],
    }
    if not examples:
        return hints

    if format_kind in {"binary", "container"}:
        prefix = examples[0][:8]
        if prefix:
            if _is_probably_text(prefix):
                hints["magic_bytes"] = [prefix.decode("latin-1", errors="ignore")]
            else:
                hints["magic_bytes"] = [base64.b64encode(prefix).decode("ascii")]
        ascii_markers = _extract_ascii_markers(examples[0])
        hints["section_markers"] = ascii_markers[:6]
        hints["delimiters"] = [token for token in ("obj", "endobj", "stream", "endstream", "xref", "%%EOF") if token in ascii_markers or token in examples[0].decode("latin-1", errors="ignore")]
        hints["length_fields"] = [token for token in ("Length", "Size", "Count") if token in examples[0].decode("latin-1", errors="ignore")]
        return hints

    sample_text = examples[0].decode("latin-1", errors="ignore")
    delimiters = []
    for ch in "./:?#@=&;,|~+-_":
        if ch in sample_text:
            delimiters.append(ch)
    hints["delimiters"] = delimiters[:8]
    return hints


def _default_mutation_hints(format_kind: str) -> dict:
    if format_kind in {"binary", "container"}:
        return {
            "prefer_operations": [
                "magic_tail_flip",
                "marker_duplicate",
                "marker_delete",
                "chunk_duplicate",
                "chunk_truncate",
                "length_field_stress",
                "delimiter_replace",
                "object_marker_insert",
            ],
            "avoid_operations": [],
            "preserve_magic_bytes": True,
            "avoid_magic_prefix_damage": True,
        }
    return {
        "prefer_operations": [],
        "avoid_operations": [],
        "preserve_magic_bytes": False,
        "avoid_magic_prefix_damage": False,
    }


def _minimal_pdf_examples() -> tuple[list[bytes], list[bytes]]:
    valid = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f \n0000000010 00000 n \n0000000059 00000 n \n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n108\n%%EOF\n"
    )
    invalid = [
        valid.replace(b"%%EOF", b""),
        valid.replace(b"xref", b"xre!"),
        valid[:80],
    ]
    return [valid], invalid


def build_manual_bootstrap_profile(
    target: str,
    fmt_config: dict | None = None,
    *,
    examples_limit: int = 12,
) -> dict:
    config = fmt_config or {}
    format_kind = infer_format_kind(target, config)
    examples = [str(example).encode("utf-8", errors="replace") for example in config.get("valid_examples", [])]
    invalid_examples: list[bytes] = []

    if target.lower() == "pdf" and not examples:
        examples, invalid_examples = _minimal_pdf_examples()

    seed_encoding = "base64" if format_kind in {"binary", "container"} else str(config.get("seed_encoding", "utf-8")).lower()
    examples = examples[:examples_limit]
    invalid_examples = invalid_examples[: max(0, examples_limit - len(examples))]
    token_hints = _token_hints_from_examples(target, examples or invalid_examples, format_kind)
    mutation_hints = _default_mutation_hints(format_kind)

    return {
        "source": "manual",
        "generated_at": _now_iso(),
        "target": target,
        "format_kind": format_kind,
        "seed_encoding": seed_encoding,
        "seed_examples_valid": [_encode_seed(seed, seed_encoding) for seed in examples],
        "seed_examples_invalid": [_encode_seed(seed, seed_encoding) for seed in invalid_examples],
        "token_hints": token_hints,
        "mutation_hints": mutation_hints,
        "generic_mutation_hints": mutation_hints,
    }


def _bootstrap_prompt(target: str, fmt_config: dict, examples_limit: int) -> str:
    format_kind = infer_format_kind(target, fmt_config)
    return (
        "You are generating a small, reusable bootstrap corpus for a format-aware fuzzer.\n"
        "Return only valid JSON with these top-level keys:\n"
        "source, format_kind, seed_encoding, seed_examples_valid, seed_examples_invalid, token_hints, mutation_hints.\n"
        "Constraints:\n"
        f"- target format name: {target}\n"
        f"- inferred format kind: {format_kind}\n"
        f"- maximum total examples: {examples_limit}\n"
        "- keep examples tiny and cost-effective\n"
        "- include a mix of valid and slightly malformed examples\n"
        "- if the format is binary or container-like, use seed_encoding=base64 and base64-encode each seed\n"
        "- token_hints must stay lightweight and may include magic_bytes, delimiters, section_markers, length_fields, field_like_regions\n"
        "- mutation_hints must include prefer_operations, avoid_operations, preserve_magic_bytes, avoid_magic_prefix_damage\n"
        "- do not include code, prose, markdown fences, or explanations\n"
        f"Known local config:\n{json.dumps(fmt_config, indent=2, sort_keys=True)}\n"
    )


def _call_openai_chat_json(prompt: str, *, model: str) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    payload = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You produce compact JSON bootstrap artifacts for fuzzing targets. "
                    "Always return a single JSON object."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(
        url=f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI bootstrap request failed: {exc}") from exc

    content = data["choices"][0]["message"]["content"]
    if not isinstance(content, str):
        raise RuntimeError("OpenAI bootstrap response was not a JSON string")
    return json.loads(content)


def _normalize_llm_profile(target: str, raw_profile: dict, fmt_config: dict, examples_limit: int) -> dict:
    format_kind = str(raw_profile.get("format_kind") or infer_format_kind(target, fmt_config)).lower()
    if format_kind not in {"text", "binary", "container"}:
        format_kind = infer_format_kind(target, fmt_config)
    seed_encoding = str(raw_profile.get("seed_encoding") or ("base64" if format_kind in {"binary", "container"} else "utf-8")).lower()
    mutation_hints = raw_profile.get("mutation_hints") or _default_mutation_hints(format_kind)

    profile = {
        "source": "llm_bootstrap",
        "generated_at": _now_iso(),
        "target": target,
        "format_kind": format_kind,
        "seed_encoding": seed_encoding,
        "seed_examples_valid": list(raw_profile.get("seed_examples_valid", []))[:examples_limit],
        "seed_examples_invalid": list(raw_profile.get("seed_examples_invalid", []))[:examples_limit],
        "token_hints": raw_profile.get("token_hints", {}),
        "mutation_hints": mutation_hints,
        "generic_mutation_hints": raw_profile.get("generic_mutation_hints", mutation_hints),
    }
    decode_bootstrap_seed_examples(profile)
    return profile


def save_bootstrap_profile(
    target: str,
    profile: dict,
    fmt_config: dict | None = None,
    *,
    project_root: Path | None = None,
) -> Path:
    path = _bootstrap_path(target, fmt_config, project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def ensure_bootstrap_profile(
    target: str,
    fmt_config: dict,
    *,
    refresh: bool = False,
    examples_limit: int | None = None,
    model: str | None = None,
) -> tuple[dict, Path]:
    limit = max(1, min(examples_limit or int(fmt_config.get("bootstrap_examples_limit", 12) or 12), 30))
    existing = load_bootstrap_profile(target, fmt_config)
    path = _bootstrap_path(target, fmt_config)
    if existing and not refresh:
        return existing, path

    use_llm = bool(fmt_config.get("bootstrap_enabled", True))
    if use_llm:
        selected_model = model or DEFAULT_BOOTSTRAP_MODEL
        try:
            raw_profile = _call_openai_chat_json(
                _bootstrap_prompt(target, fmt_config, limit),
                model=selected_model,
            )
            profile = _normalize_llm_profile(target, raw_profile, fmt_config, limit)
            return profile, save_bootstrap_profile(target, profile, fmt_config)
        except Exception as exc:
            print(f"[bootstrap] LLM bootstrap unavailable for '{target}': {exc}")

    profile = build_manual_bootstrap_profile(target, fmt_config, examples_limit=limit)
    return profile, save_bootstrap_profile(target, profile, fmt_config)
