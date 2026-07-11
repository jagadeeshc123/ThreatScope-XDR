import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.modules.soc_monitor.redaction import redact, redact_text


ALIASES = {
    "timestamp": ["timestamp", "time", "event_time", "datetime", "date"],
    "source_ip": ["src_ip", "source_ip", "client_ip", "remote_addr", "ip"],
    "destination_ip": ["dst_ip", "destination_ip"],
    "username": ["user", "username", "account", "identity"],
    "http_method": ["method", "http_method"],
    "request_path": ["path", "uri", "request_path", "endpoint"],
    "status_code": ["status", "status_code", "http_status"],
    "outcome": ["result", "outcome", "status_text"],
    "message": ["msg", "message", "event_message"],
    "user_agent": ["agent", "user_agent"],
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any, fallback: Optional[datetime] = None) -> datetime:
    fallback = fallback or utcnow()
    if value is None or value == "":
        return ensure_utc(fallback)
    if isinstance(value, datetime):
        return ensure_utc(value)
    text = str(value).strip()
    if text.isdigit():
        try:
            return datetime.fromtimestamp(float(text), timezone.utc)
        except (ValueError, OSError):
            return ensure_utc(fallback)
    variants = [text, text.replace("Z", "+00:00")]
    for item in variants:
        try:
            return ensure_utc(datetime.fromisoformat(item))
        except ValueError:
            pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=fallback.year)
            return ensure_utc(parsed)
        except ValueError:
            pass
    return ensure_utc(fallback)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def first(data: Dict[str, Any], field: str) -> Any:
    lowered = {str(k).lower(): v for k, v in data.items()}
    for alias in ALIASES.get(field, [field]):
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def normalize_outcome(value: Any, status_code: Optional[int] = None) -> str:
    text = str(value or "").lower()
    if any(word in text for word in ("deny", "denied", "forbid", "unauthor")) or status_code in (401, 403):
        return "denied"
    if any(word in text for word in ("block", "drop", "reject")):
        return "blocked"
    if any(word in text for word in ("fail", "invalid", "error")) or (status_code is not None and status_code >= 400):
        return "failure"
    if any(word in text for word in ("success", "allow", "accept", "ok")) or (status_code is not None and status_code < 400):
        return "success"
    return "unknown"


def normalize_event_type(data: Dict[str, Any], outcome: str) -> str:
    explicit = str(data.get("event_type") or data.get("type") or "").lower().replace("-", "_").replace(" ", "_")
    approved = {"authentication", "authorization", "web_request", "api_request", "administrative_action", "security_control", "system", "unknown"}
    if explicit in approved:
        return explicit
    combined = " ".join(str(value).lower() for value in data.values())
    path = str(first(data, "request_path") or "")
    if any(word in combined for word in ("login", "logon", "authentication", "password", "sshd")):
        return "authentication"
    if any(word in combined for word in ("authorization", "permission", "access denied")) or outcome == "denied" and not path:
        return "authorization"
    if any(word in path.lower() for word in ("/admin", "/manage", "/privileged")):
        return "administrative_action"
    if first(data, "http_method") or path:
        return "api_request" if path.startswith("/api/") else "web_request"
    return "system" if combined else "unknown"


def valid_ip(value: Any) -> Optional[str]:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def normalize_event(data: Dict[str, Any], raw_text: str, fallback_time: Optional[datetime] = None) -> Dict[str, Any]:
    redacted = redact(data)
    status_raw = first(redacted, "status_code")
    try:
        status_code = int(status_raw) if status_raw not in (None, "") else None
    except (ValueError, TypeError):
        status_code = None
    outcome = normalize_outcome(first(redacted, "outcome"), status_code)
    event_type = normalize_event_type(redacted, outcome)
    event_time = parse_timestamp(first(redacted, "timestamp"), fallback_time)
    normalized = {
        **redacted,
        "event_time": event_time.isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": valid_ip(first(redacted, "source_ip")),
        "destination_ip": valid_ip(first(redacted, "destination_ip")),
        "username": str(first(redacted, "username"))[:160] if first(redacted, "username") else None,
        "http_method": str(first(redacted, "http_method")).upper()[:16] if first(redacted, "http_method") else None,
        "request_path": str(first(redacted, "request_path"))[:1000] if first(redacted, "request_path") else None,
        "status_code": status_code,
        "message": redact_text(str(first(redacted, "message") or ""), 4000) or None,
        "user_agent": redact_text(str(first(redacted, "user_agent") or ""), 1000) or None,
    }
    canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, default=str)
    event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    severity = str(redacted.get("severity", "info")).lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    return {
        "event_time": event_time,
        "event_type": event_type,
        "action": str(redacted.get("action"))[:120] if redacted.get("action") else None,
        "outcome": outcome,
        "severity": severity,
        "source_ip": normalized["source_ip"],
        "destination_ip": normalized["destination_ip"],
        "username": normalized["username"],
        "http_method": normalized["http_method"],
        "request_path": normalized["request_path"],
        "status_code": status_code,
        "user_agent": normalized["user_agent"],
        "message": normalized["message"],
        "normalized_json": canonical,
        "raw_event_hash": event_hash,
        "raw_preview_redacted": redact_text(raw_text, 2000),
    }
