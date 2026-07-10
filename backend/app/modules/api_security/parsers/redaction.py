import re
from typing import Any


REDACTED = "[REDACTED]"
SENSITIVE_KEYS = {
    "authorization",
    "bearer",
    "token",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "api_key",
    "apikey",
    "apiKey",
    "password",
    "secret",
    "client_secret",
    "clientSecret",
    "cookie",
    "set-cookie",
    "session",
    "sessionid",
    "session_id",
}


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(re.sub(r"[^a-z0-9]", "", candidate.lower()) in normalized for candidate in SENSITIVE_KEYS)


def redact_text(value: str) -> str:
    redacted = re.sub(r"(?i)(authorization\s*[:=]\s*)([^\r\n,}]+)", rf"\1{REDACTED}", value)
    redacted = re.sub(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})", rf"\1{REDACTED}", redacted)
    redacted = re.sub(
        r"(?i)((?:token|api[_-]?key|password|secret|client[_-]?secret|cookie|session)\s*[:=]\s*)([^&\s,}\]]+)",
        rf"\1{REDACTED}",
        redacted,
    )
    redacted = re.sub(
        r'(?i)("(?:token|api[_-]?key|password|secret|client[_-]?secret|authorization|cookie|session)"\s*:\s*")[^"]*(")',
        rf"\1{REDACTED}\2",
        redacted,
    )
    return redacted


def redact_data(value: Any) -> Any:
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, dict):
        declared_key = value.get("key") or value.get("name")
        sibling_value_is_sensitive = isinstance(declared_key, str) and _is_sensitive_key(declared_key)
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)) or (sibling_value_is_sensitive and str(key).lower() in {"value", "initialvalue", "currentvalue"}):
                result[key] = REDACTED
            else:
                result[key] = redact_data(item)
        return result
    if isinstance(value, str):
        return redact_text(value)
    return value
