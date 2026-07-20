import re

from app.modules.production.logging import SENSITIVE_KEY, redact as _production_redact


ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:\\|/(?:home|Users|app|var|tmp)/)[^\s\"']+")


def redact(value, key: str = "", depth: int = 0):
    if depth > 8:
        return "[BOUNDED]"
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k)[:80]: redact(v, str(k), depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple, set)):
        return [redact(item, key, depth + 1) for item in list(value)[:100]]
    redacted = _production_redact(value, key, depth)
    if isinstance(redacted, str):
        return ABSOLUTE_PATH.sub("[LOCAL_PATH]", redacted)
    return redacted
