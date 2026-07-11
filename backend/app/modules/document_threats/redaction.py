import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE = set(json.loads((Path(__file__).parent / "rules" / "sensitive_keys.json").read_text(encoding="utf-8")))
PATTERN = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|authorization|cookie|session|credential|private_key|client_secret)\b\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)")
AUTH_PATTERN = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")

def sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
    return normalized in SENSITIVE or any(part in SENSITIVE for part in normalized.split("_"))

def redact_text(value: Any, limit: int = 500) -> str:
    text = AUTH_PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(value or ""))
    text = PATTERN.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = "".join(char if char >= " " or char in "\n\t" else "�" for char in text)
    return text[:limit] + ("…" if len(text) > limit else "")

def redact(value: Any) -> Any:
    if isinstance(value, dict): return {str(k): "[REDACTED]" if sensitive_key(k) else redact(v) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)): return [redact(v) for v in value[:100]]
    if isinstance(value, str): return redact_text(value, 2000)
    return value

def sanitize_filename(value: str) -> str:
    if not value or value != Path(value).name or ".." in value.replace("\\", "/").split("/"):
        raise ValueError("Unsafe or path-traversal filename")
    safe = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" .")[:255]
    if not safe: raise ValueError("Filename is empty after sanitization")
    return safe

def sanitize_url(value: str) -> tuple[str, bool]:
    raw = redact_text(value, 4000).strip()
    sensitive_found = False
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        netloc = host + port
        query = []
        for key, item in parse_qsl(parts.query, keep_blank_values=True):
            if sensitive_key(key): item = "[REDACTED]"; sensitive_found = True
            query.append((key[:120], item[:500]))
        clean = urlunsplit((parts.scheme.lower(), netloc, parts.path[:1500], urlencode(query), ""))
        if parts.username or parts.password: sensitive_found = True
        return clean[:2000], sensitive_found
    except ValueError:
        return raw[:2000], sensitive_found
