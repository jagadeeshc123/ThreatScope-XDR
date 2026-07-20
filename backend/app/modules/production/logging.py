from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_KEY = re.compile(
    r"authorization|cookie|set-cookie|password|secret|token|api[_-]?key|webhook|signature|credential|private[_-]?key|csrf|session|recovery[_-]?code|totp",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|authorization|cookie|csrf|session|signature|credential)\s*[=:]\s*([^\s,;&]+)"
)


def redact(value, key: str = "", depth: int = 0):
    if depth > 8:
        return "[BOUNDED]"
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k)[:100]: redact(v, str(k), depth + 1) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple, set)):
        return [redact(item, key, depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        text = value[:4000]
        try:
            parsed = urlsplit(text)
            if parsed.scheme and parsed.netloc and (parsed.username or parsed.password or parsed.query):
                host = parsed.hostname or ""
                if parsed.port:
                    host = f"{host}:{parsed.port}"
                text = urlunsplit((parsed.scheme, host, parsed.path, "[REDACTED]" if parsed.query else "", ""))
        except ValueError:
            pass
        return SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    return value if isinstance(value, (int, float, bool)) or value is None else str(value)[:500]


class ProductionJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "threatscope-backend",
            "event": getattr(record, "event_name", "application_log"),
            "request_id": getattr(record, "request_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
            "actor_user_id": getattr(record, "actor_user_id", None),
            "route_template": getattr(record, "route_template", None),
            "method": getattr(record, "method", None),
            "status": getattr(record, "status_code", None),
            "duration_ms": getattr(record, "duration_ms", None),
            "revision": getattr(record, "revision", None),
            "metadata": redact(getattr(record, "safe_metadata", {})),
            "message": redact(record.getMessage(), "message"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def configure_production_logging(level: str = "INFO", json_mode: bool = True) -> logging.Logger:
    logger = logging.getLogger("threatscope")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    if json_mode:
        handler.setFormatter(ProductionJsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.propagate = False
    return logger
