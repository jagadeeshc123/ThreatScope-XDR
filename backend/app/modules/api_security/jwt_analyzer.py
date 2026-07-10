import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

from app.modules.api_security.parsers.redaction import redact_data
from app.modules.api_security.rules_loader import sensitive_fields


DISCLAIMER = "Decoded structure only - cryptographic signature not verified"
WEAK_ALGORITHMS = {"none", "hs256"}
PREFERRED_ALGORITHMS = {"rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512", "eddsa"}


class JwtAnalyzeError(ValueError):
    pass


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except Exception as exc:
        raise JwtAnalyzeError("JWT segment is not valid base64url.") from exc


def _json_segment(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_b64url_decode(segment).decode("utf-8"))
    except Exception as exc:
        raise JwtAnalyzeError(f"JWT {label} could not be decoded as JSON.") from exc
    if not isinstance(value, dict):
        raise JwtAnalyzeError(f"JWT {label} must decode to a JSON object.")
    return value


def _epoch_to_datetime(value: Any) -> datetime | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _audience(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def _claim_names(value: Any, prefix: str = "") -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            names.append(path)
            names.extend(_claim_names(nested, path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            names.extend(_claim_names(nested, f"{prefix}[{index}]"))
    return names


def _sensitive_claims(payload: dict[str, Any]) -> list[str]:
    keywords = [item.lower().replace("_", "") for item in sensitive_fields()]
    matches: list[str] = []
    for path in _claim_names(payload):
        normalized = path.lower().replace("_", "").replace("-", "")
        if any(keyword in normalized for keyword in keywords):
            matches.append(path)
    return sorted(set(matches))


def analyze_jwt(token: str, expected_issuer: str | None = None, expected_audience: str | None = None) -> dict[str, Any]:
    normalized = token.strip().removeprefix("Bearer ").strip()
    parts = normalized.split(".")
    if len(parts) != 3:
        raise JwtAnalyzeError("JWT must have header, payload, and signature segments.")

    header = _json_segment(parts[0], "header")
    payload = _json_segment(parts[1], "payload")
    now = datetime.now(timezone.utc)
    now_epoch = time.time()

    algorithm = str(header.get("alg")) if header.get("alg") is not None else None
    issuer = str(payload.get("iss")) if payload.get("iss") is not None else None
    audience = _audience(payload.get("aud"))
    issued_at = _epoch_to_datetime(payload.get("iat"))
    expires_at = _epoch_to_datetime(payload.get("exp"))
    not_before = _epoch_to_datetime(payload.get("nbf"))
    findings: list[dict[str, Any]] = []

    def add(code: str, title: str, severity: str, detail: str) -> None:
        findings.append({"code": code, "title": title, "severity": severity, "detail": detail})

    alg_normalized = (algorithm or "").lower()
    if alg_normalized == "none":
        add("alg_none", "JWT uses alg none", "critical", "The header declares an unsigned token algorithm.")
    elif alg_normalized in WEAK_ALGORITHMS:
        add("weak_algorithm", "JWT uses weak or shared-secret algorithm metadata", "medium", f"Algorithm metadata is {algorithm}. Signature validity is not verified in this phase.")
    elif alg_normalized and alg_normalized not in PREFERRED_ALGORITHMS:
        add("unexpected_algorithm", "JWT uses unexpected algorithm metadata", "low", f"Algorithm metadata is {algorithm}.")
    elif not algorithm:
        add("missing_algorithm", "JWT algorithm is missing", "medium", "The decoded header does not declare alg.")

    expiration_status = "unknown"
    if expires_at is None:
        expiration_status = "missing"
        add("missing_exp", "JWT expiration is missing", "high", "No exp claim was present.")
    elif expires_at < now:
        expiration_status = "expired"
        add("expired", "JWT is expired", "medium", "The exp claim is earlier than the current time.")
    else:
        lifetime_seconds = float(payload.get("exp", now_epoch)) - float(payload.get("iat", now_epoch)) if payload.get("iat") is not None else 0
        if lifetime_seconds > 86400:
            expiration_status = "long_lived"
            add("long_lived", "JWT lifetime is unusually long", "medium", "The iat-to-exp lifetime is greater than 24 hours.")
        else:
            expiration_status = "valid"

    if issued_at and issued_at.timestamp() > now_epoch + 300:
        add("future_iat", "JWT issued-at is in the future", "medium", "The iat claim is more than five minutes ahead of current time.")
    if not_before and not_before.timestamp() > now_epoch + 300:
        add("future_nbf", "JWT not-before is in the future", "medium", "The nbf claim indicates the token should not be accepted yet.")

    if not issuer:
        add("missing_issuer", "JWT issuer is missing", "low", "No iss claim was present.")
    elif expected_issuer and issuer != expected_issuer:
        add("issuer_mismatch", "JWT issuer mismatch", "medium", "The iss claim does not match the expected issuer.")

    if not audience:
        add("missing_audience", "JWT audience is missing", "low", "No aud claim was present.")
    elif expected_audience and expected_audience not in audience:
        add("audience_mismatch", "JWT audience mismatch", "medium", "The aud claim does not include the expected audience.")

    sensitive = _sensitive_claims(payload)
    if sensitive:
        add("sensitive_claims", "JWT contains sensitive claim names", "high", f"Sensitive claim paths: {', '.join(sensitive)}.")

    roles = payload.get("roles", payload.get("role", payload.get("permissions", [])))
    role_values = roles if isinstance(roles, list) else [roles] if roles else []
    privileged = [str(item) for item in role_values if str(item).lower() in {"admin", "root", "owner", "superuser", "*"}]
    if len(role_values) > 8 or privileged:
        add("excessive_privileges", "JWT contains excessive privilege indicators", "medium", "Role or permission claims appear broad and require review.")

    if "jti" not in payload and expiration_status in {"long_lived", "valid"}:
        add("missing_jti", "JWT identifier is missing", "info", "No jti claim was present for replay tracking.")

    risk_score = min(10, sum({"critical": 5, "high": 4, "medium": 2, "low": 1, "info": 0}.get(item["severity"], 0) for item in findings))

    return {
        "token_fingerprint": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "header": redact_data(header),
        "payload": redact_data(payload),
        "algorithm": algorithm,
        "issuer": issuer,
        "audience": audience,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "not_before": not_before,
        "expiration_status": expiration_status,
        "risk_score": risk_score,
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }

