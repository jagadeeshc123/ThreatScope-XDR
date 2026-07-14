import re
from typing import Any

SENSITIVE = re.compile(r"password|secret|token|cookie|authorization|csrf|totp|mfa|recovery|private.?key|session|jwt", re.I)
ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:\\|/(?:home|Users|app|var|tmp)/)[^\s\"']+")


def redact(value: Any, key: str = "", depth: int = 0) -> Any:
    if depth > 8:
        return "[BOUNDED]"
    if SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k)[:80]: redact(v, str(k), depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple, set)):
        return [redact(v, key, depth + 1) for v in list(value)[:100]]
    if isinstance(value, str):
        text = ABSOLUTE_PATH.sub("[LOCAL_PATH]", value[:2000])
        return "[REDACTED]" if SENSITIVE.search(key) else text
    return value
