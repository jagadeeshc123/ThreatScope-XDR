import json
import re
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = set(json.loads((Path(__file__).parent / "rules" / "sensitive_keys.json").read_text(encoding="utf-8")))
SECRET_TEXT_PATTERNS = [
    re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|authorization|cookie|session|credential|private_key|client_secret)\b\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"),
]


def is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
    return normalized in SENSITIVE_KEYS or any(part in SENSITIVE_KEYS for part in normalized.split("_"))


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if is_sensitive_key(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(value: str, limit: int | None = None) -> str:
    result = value
    for pattern in SECRET_TEXT_PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]" if match.lastindex else "[REDACTED]", result)
    if limit is not None and len(result) > limit:
        result = result[:limit] + "…"
    return result


def safe_json(value: Any) -> str:
    return json.dumps(redact(value), ensure_ascii=False, sort_keys=True, default=str)
