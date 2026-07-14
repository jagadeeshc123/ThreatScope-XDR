import json
from pathlib import Path
from typing import Any


_KEYS = tuple(
    item.casefold()
    for item in json.loads((Path(__file__).with_name("rules") / "sensitive_keys.json").read_text(encoding="utf-8"))
)


def _sensitive(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(part in normalized for part in _KEYS)


def redact(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:50]:
            key_text = str(key)[:100]
            result[key_text] = "[REDACTED]" if _sensitive(key_text) else redact(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, str):
        return value[:500]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:500]

