import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

KEYS = re.compile(r"(?i)(password|passwd|token|secret|authorization|cookie|api[_-]?key|otp|pin|credential|jwt)\s*[:=]\s*[^\s;,]+")
BEARER = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def redact(value, limit=1000):
    if value is None:
        return None
    text = BEARER.sub("Bearer [REDACTED]", KEYS.sub(lambda m: m.group(1) + "=[REDACTED]", str(value)))
    return text[:limit]


def internal_route(value):
    return redact(value, 500) if isinstance(value, str) and value.startswith("/") and not value.startswith("//") else None
