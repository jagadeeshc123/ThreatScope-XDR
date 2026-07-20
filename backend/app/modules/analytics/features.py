import hashlib
import json
import math
from datetime import datetime, timezone
from statistics import fmean, median, pstdev
from typing import Iterable

from sqlalchemy.orm import Session

from .catalog import FEATURE_CATALOG, PEER_GROUP_KEYS, SEASONALITIES, WINDOWS, feature


MAX_VALUES = 10000
MAX_RANGE_SECONDS = 366 * 86400
ROUND_DIGITS = 6


def utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("A valid timestamp is required")
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def validate_window(start: datetime, end: datetime, *, approved_only: bool = False) -> tuple[datetime, datetime]:
    start, end = utc(start), utc(end)
    seconds = int((end - start).total_seconds())
    if seconds <= 0 or seconds > MAX_RANGE_SECONDS:
        raise ValueError("Time range must be positive and within the server bound")
    if approved_only and seconds not in WINDOWS:
        raise ValueError("Observation window is not server-approved")
    return start, end


def finite(value: object, *, non_negative: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Feature values must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("NaN and Infinity are prohibited")
    if non_negative and result < 0:
        raise ValueError("Negative values are invalid for this feature")
    if abs(result) > 1e300:
        raise ValueError("Feature value exceeds the safe numeric bound")
    return result


def clean_values(values: Iterable[object], *, allow_missing: bool = True, non_negative: bool = False) -> tuple[list[float], int]:
    result: list[float] = []
    missing = 0
    for value in values:
        if len(result) + missing >= MAX_VALUES:
            raise ValueError("Feature sample limit exceeded")
        if value is None:
            if not allow_missing:
                raise ValueError("Missing feature value is not allowed")
            missing += 1
            continue
        result.append(finite(value, non_negative=non_negative))
    return result, missing


def stable_round(value: float | None) -> float | None:
    if value is None:
        return None
    return round(finite(value), ROUND_DIGITS)


def mean(values: Iterable[object]) -> float | None:
    clean, _ = clean_values(values)
    return stable_round(fmean(clean)) if clean else None


def median_value(values: Iterable[object]) -> float | None:
    clean, _ = clean_values(values)
    return stable_round(median(clean)) if clean else None


def median_absolute_deviation(values: Iterable[object]) -> float | None:
    clean, _ = clean_values(values)
    if not clean:
        return None
    center = median(clean)
    return stable_round(median(abs(item - center) for item in clean))


def percentile(values: Iterable[object], quantile: float) -> float | None:
    clean, _ = clean_values(values)
    q = finite(quantile)
    if not 0 <= q <= 100:
        raise ValueError("Percentile must be between 0 and 100")
    if not clean:
        return None
    ordered = sorted(clean)
    position = (len(ordered) - 1) * q / 100
    lower, upper = math.floor(position), math.ceil(position)
    result = ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    return stable_round(result)


def interquartile_range(values: Iterable[object]) -> float | None:
    clean, _ = clean_values(values)
    if not clean:
        return None
    return stable_round((percentile(clean, 75) or 0) - (percentile(clean, 25) or 0))


def ewma(values: Iterable[object], alpha: float = 0.3) -> float | None:
    clean, _ = clean_values(values)
    alpha = finite(alpha)
    if not 0 < alpha <= 1:
        raise ValueError("EWMA alpha must be in (0, 1]")
    if not clean:
        return None
    result = clean[0]
    for item in clean[1:]:
        result = alpha * item + (1 - alpha) * result
    return stable_round(result)


def ratio(numerator: object, denominator: object) -> float | None:
    left, right = finite(numerator, non_negative=True), finite(denominator, non_negative=True)
    return None if right == 0 else stable_round(left / right)


def rate(count: object, duration_seconds: object) -> float | None:
    return ratio(count, duration_seconds)


def rate_of_change(current: object, previous: object) -> float | None:
    current_value, previous_value = finite(current), finite(previous)
    if previous_value == 0:
        return 0.0 if current_value == 0 else None
    return stable_round((current_value - previous_value) / abs(previous_value))


def consecutive_failures(values: Iterable[object]) -> int:
    sequence = list(values)
    if len(sequence) > MAX_VALUES:
        raise ValueError("Feature sample limit exceeded")
    count = 0
    for value in reversed(sequence):
        failed = value is False or value == 0 or (isinstance(value, str) and value.casefold() in {"failed", "failure", "error", "rejected", "timeout"})
        if not failed:
            break
        count += 1
    return count


def seasonal_bucket(value: datetime, seasonality: str, fixed_bucket_hours: int = 6) -> str:
    value = utc(value)
    if seasonality not in SEASONALITIES:
        raise ValueError("Unknown server-owned seasonality")
    if seasonality == "none": return "all"
    if seasonality == "hour_of_day": return f"hour:{value.hour:02d}"
    if seasonality == "day_of_week": return f"weekday:{value.weekday()}"
    if seasonality == "weekday_weekend": return "weekend" if value.weekday() >= 5 else "weekday"
    if seasonality in {"fixed_utc_bucket", "source_periodic_bucket"}:
        if fixed_bucket_hours not in {1, 2, 3, 4, 6, 8, 12}:
            raise ValueError("Fixed UTC bucket is not server-approved")
        start = (value.hour // fixed_bucket_hours) * fixed_bucket_hours
        return f"utc:{start:02d}-{start + fixed_bucket_hours:02d}"
    raise ValueError("Unsupported seasonality")


def deterministic_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded_scope(scope: dict | None) -> dict:
    scope = scope or {}
    if not isinstance(scope, dict) or set(scope) - {"entity_id", "peer_group_key", "peer_group_value"}:
        raise ValueError("Only server-approved scope fields are allowed")
    if scope.get("entity_id") is not None and (not isinstance(scope["entity_id"], int) or scope["entity_id"] < 1):
        raise ValueError("Entity identifier must be a positive integer")
    if scope.get("peer_group_key") is not None and scope["peer_group_key"] not in PEER_GROUP_KEYS:
        raise ValueError("Peer-group key is not server-approved")
    if scope.get("peer_group_value") is not None and (not isinstance(scope["peer_group_value"], str) or len(scope["peer_group_value"]) > 100):
        raise ValueError("Peer-group value exceeds its bound")
    return scope


def _count(db: Session, model, timestamp, start: datetime, end: datetime, *filters) -> float:
    return float(db.query(model.id).filter(timestamp >= start, timestamp < end, *filters).limit(MAX_VALUES + 1).count())


def extract_feature(db: Session, feature_key: str, start: datetime, end: datetime, scope: dict | None = None) -> dict:
    definition = feature(feature_key)
    start, end = validate_window(start, end)
    scope = _bounded_scope(scope)
    entity_id = scope.get("entity_id")
    value: float | None

    if feature_key.startswith("auth.") and feature_key in {"auth.failure_count", "auth.success_count"}:
        from app.modules.access_control.models import LoginAttempt
        expected = feature_key == "auth.success_count"
        value = _count(db, LoginAttempt, LoginAttempt.attempted_at, start, end, LoginAttempt.success.is_(expected))
    elif feature_key.startswith("auth.") and feature_key != "auth.session_creation_count" and feature_key != "auth.session_invalidation_count":
        from app.modules.access_control.models import SecurityAuditEvent
        mapping = {
            "auth.access_denial_count": SecurityAuditEvent.event_type == "authorization_denied",
            "auth.permission_change_count": SecurityAuditEvent.action.in_(["set_role_permissions", "permission_check"]),
            "auth.role_assignment_count": SecurityAuditEvent.event_type == "role_assigned",
            "auth.mfa_failure_count": SecurityAuditEvent.event_type.in_(["mfa_login_failure", "totp_enrollment_failed"]),
        }
        value = _count(db, SecurityAuditEvent, SecurityAuditEvent.occurred_at, start, end, mapping[feature_key])
    elif feature_key.startswith("auth.session_"):
        from app.modules.access_control.models import AuthSession
        timestamp = AuthSession.created_at if feature_key.endswith("creation_count") else AuthSession.revoked_at
        value = _count(db, AuthSession, timestamp, start, end)
    elif feature_key == "web.finding_count":
        from app.models import Finding
        value = _count(db, Finding, Finding.created_at, start, end, *((Finding.target_id == entity_id,) if entity_id else ()))
    elif feature_key.startswith("api."):
        from app.modules.api_security.models import ApiEndpoint, ApiFinding
        model = ApiEndpoint if feature_key == "api.endpoint_count" else ApiFinding
        filters = []
        if feature_key == "api.high_severity_finding_count": filters.append(ApiFinding.severity.in_(["high", "critical"]))
        if entity_id: filters.append(model.assessment_id == entity_id)
        value = _count(db, model, model.created_at, start, end, *filters)
    elif feature_key.startswith("soc."):
        from app.modules.soc_monitor.models import SocAlert
        filters = [SocAlert.severity.in_(["high", "critical"])] if feature_key == "soc.high_severity_alert_count" else []
        value = _count(db, SocAlert, SocAlert.created_at, start, end, *filters)
    elif feature_key.startswith("document."):
        from app.modules.document_threats.models import DocumentAnalysis, DocumentFinding
        if feature_key == "document.finding_count": value = _count(db, DocumentFinding, DocumentFinding.created_at, start, end)
        else: value = _count(db, DocumentAnalysis, DocumentAnalysis.created_at, start, end, DocumentAnalysis.analysis_status == "failed")
    elif feature_key == "phishing.finding_count":
        from app.modules.phishing_defense.models import PhishingFinding
        value = _count(db, PhishingFinding, PhishingFinding.created_at, start, end)
    elif feature_key == "case.creation_count":
        from app.modules.unified_correlation.models import IncidentCase
        value = _count(db, IncidentCase, IncidentCase.created_at, start, end)
    elif feature_key.startswith("threat_intel."):
        from app.modules.threat_intelligence.models import IndicatorMatch, ThreatIndicator
        if feature_key == "threat_intel.match_count": value = _count(db, IndicatorMatch, IndicatorMatch.created_at, start, end)
        else: value = float(db.query(ThreatIndicator.id).filter(ThreatIndicator.active.is_(True), ThreatIndicator.valid_until.is_not(None), ThreatIndicator.valid_until < end).limit(MAX_VALUES + 1).count())
    elif feature_key.startswith("detections."):
        from app.modules.detection_engineering.models import DetectionExecution, DetectionMatch
        if feature_key == "detections.match_count": value = _count(db, DetectionMatch, DetectionMatch.event_timestamp, start, end)
        else: value = _count(db, DetectionExecution, DetectionExecution.started_at, start, end, DetectionExecution.status == "failed")
    elif feature_key.startswith("vulnerability."):
        from app.modules.vulnerability_management.models import RemediationTask, VulnerabilityRecord
        if feature_key == "vulnerability.new_count": value = _count(db, VulnerabilityRecord, VulnerabilityRecord.first_seen_at, start, end)
        elif feature_key == "vulnerability.critical_count": value = _count(db, VulnerabilityRecord, VulnerabilityRecord.first_seen_at, start, end, VulnerabilityRecord.severity == "critical")
        elif feature_key == "vulnerability.remediation_backlog_count": value = float(db.query(RemediationTask.id).filter(RemediationTask.created_at < end, ~RemediationTask.status.in_(["done", "cancelled"])).limit(MAX_VALUES + 1).count())
        else: value = float(db.query(VulnerabilityRecord.id).filter(VulnerabilityRecord.due_at.is_not(None), VulnerabilityRecord.due_at < end, ~VulnerabilityRecord.status.in_(["resolved", "closed"])).limit(MAX_VALUES + 1).count())
    elif feature_key.startswith("soar."):
        from app.modules.soar.models import SoarApproval, SoarExecution
        if feature_key == "soar.execution_failure_count": value = _count(db, SoarExecution, SoarExecution.created_at, start, end, SoarExecution.status.in_(["failed", "rollback_failed"]))
        else: value = _count(db, SoarApproval, SoarApproval.created_at, start, end, SoarApproval.status == "rejected")
    elif feature_key.startswith("integration."):
        from app.modules.integrations.models import ConnectorDeadLetter, ConnectorDelivery, ConnectorHealthCheck, ConnectorInboundEvent, ConnectorInstance
        if feature_key == "integration.delivery_failure_count": value = _count(db, ConnectorDelivery, ConnectorDelivery.created_at, start, end, ConnectorDelivery.status.in_(["failed", "dead_letter"]))
        elif feature_key == "integration.delivery_latency_ms":
            query = db.query(ConnectorDelivery).filter(ConnectorDelivery.created_at >= start, ConnectorDelivery.created_at < end, ConnectorDelivery.started_at.is_not(None), ConnectorDelivery.completed_at.is_not(None))
            if entity_id: query = query.filter(ConnectorDelivery.connector_id == entity_id)
            rows = query.order_by(ConnectorDelivery.id).limit(MAX_VALUES + 1).all()
            durations = [max(0.0, (item.completed_at - item.started_at).total_seconds() * 1000) for item in rows]
            value = mean(durations)
        elif feature_key == "integration.retry_count":
            query = db.query(ConnectorDelivery.attempt_count).filter(ConnectorDelivery.created_at >= start, ConnectorDelivery.created_at < end)
            if entity_id: query = query.filter(ConnectorDelivery.connector_id == entity_id)
            values = [row[0] for row in query.limit(MAX_VALUES + 1).all()]; value = stable_round(sum(values))
        elif feature_key == "integration.circuit_open_count": value = float(db.query(ConnectorInstance.id).filter(ConnectorInstance.circuit_state == "open").limit(MAX_VALUES + 1).count())
        elif feature_key == "integration.dead_letter_count": value = _count(db, ConnectorDeadLetter, ConnectorDeadLetter.created_at, start, end)
        elif feature_key == "integration.signature_failure_count": value = _count(db, ConnectorInboundEvent, ConnectorInboundEvent.created_at, start, end, ConnectorInboundEvent.signature_status != "valid")
        elif feature_key == "integration.replay_attempt_count": value = _count(db, ConnectorInboundEvent, ConnectorInboundEvent.created_at, start, end, ConnectorInboundEvent.replay_status != "accepted")
        else: value = _count(db, ConnectorHealthCheck, ConnectorHealthCheck.created_at, start, end, ConnectorHealthCheck.status != "passed")
    elif feature_key.startswith("operations."):
        from app.modules.platform_operations.models import BackupRecord, OperationalJob, RestoreRecord
        if feature_key == "operations.backup_failure_count": value = _count(db, BackupRecord, BackupRecord.created_at, start, end, BackupRecord.status.in_(["failed", "invalid"]))
        elif feature_key == "operations.restore_failure_count": value = _count(db, RestoreRecord, RestoreRecord.created_at, start, end, RestoreRecord.status.in_(["failed", "invalid"]))
        else:
            filters = [OperationalJob.status == "failed"]
            if feature_key == "operations.diagnostic_failure_count": filters.append(OperationalJob.job_type.in_(["diagnostics", "health_check"]))
            else: filters.append(OperationalJob.job_type.like("%report%"))
            value = _count(db, OperationalJob, OperationalJob.created_at, start, end, *filters)
    elif feature_key in {"audit.integrity_warning_count", "platform.rate_limit_count"}:
        from app.modules.access_control.models import SecurityAuditEvent
        condition = SecurityAuditEvent.event_type.in_(["audit_integrity_warning", "audit_integrity_failure"]) if feature_key.startswith("audit.") else SecurityAuditEvent.status_code == 429
        value = _count(db, SecurityAuditEvent, SecurityAuditEvent.occurred_at, start, end, condition)
    else:
        raise ValueError("Feature source is unavailable")

    status = "available" if value is not None else "insufficient_data"
    safe_value = stable_round(value) if value is not None else None
    result = {
        "feature_key": feature_key, "feature_version": definition.implementation_version,
        "window_start": start.isoformat() + "Z", "window_end": end.isoformat() + "Z",
        "value": safe_value, "status": status, "missing_count": 1 if value is None else 0,
        "source_domain": definition.source_domain, "source_entity": definition.source_entity,
        "scope": {key: scope[key] for key in sorted(scope)}, "unit": definition.unit,
        "limitations": ["Derived aggregate only; no raw evidence or payload is retained."],
    }
    result["data_hash"] = deterministic_hash(result)
    return result


def window_series(db: Session, feature_key: str, start: datetime, end: datetime, window_seconds: int, scope: dict | None = None) -> list[dict]:
    from datetime import timedelta
    if window_seconds not in WINDOWS:
        raise ValueError("Window is not server-approved")
    start, end = validate_window(start, end)
    windows = int(math.ceil((end - start).total_seconds() / window_seconds))
    if windows > 1000:
        raise ValueError("Historical window count exceeds the server bound")
    result = []
    cursor = start
    while cursor < end:
        boundary = min(cursor + timedelta(seconds=window_seconds), end)
        if int((boundary - cursor).total_seconds()) == window_seconds:
            result.append(extract_feature(db, feature_key, cursor, boundary, scope))
        cursor = boundary
    return result


def catalog_health() -> dict:
    return {"loaded": bool(FEATURE_CATALOG), "feature_count": len(FEATURE_CATALOG), "server_owned": True, "raw_payload_retained": False}
