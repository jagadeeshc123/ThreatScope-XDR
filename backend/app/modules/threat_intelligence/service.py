import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.modules.access_control.audit_service import append_event
from app.modules.soc_monitor.models import SocActivity

from .models import ThreatIndicator, ThreatWatchlist
from .normalization import IndicatorValidationError, defang, normalize_indicator


SEVERITY_WEIGHT = {"info": 0, "low": 20, "medium": 45, "high": 70, "critical": 90}
TLPS = {"clear", "green", "amber", "amber+strict", "red"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def bounded(value: Any, maximum: int, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise HTTPException(422, "Required text is missing")
        return None
    text = str(value).strip()
    if required and not text:
        raise HTTPException(422, "Required text is missing")
    return text[:maximum]


def clean_tags(values: list[str] | None) -> list[str]:
    result = []
    for value in values or []:
        tag = " ".join(str(value).split())[:64]
        if tag and tag.casefold() not in {x.casefold() for x in result}:
            result.append(tag)
        if len(result) >= 30:
            break
    return result


def validate_lifecycle(first_seen: datetime | None, last_seen: datetime | None, valid_until: datetime | None, valid_from: datetime | None = None):
    if first_seen and last_seen and first_seen > last_seen:
        raise HTTPException(422, "first_seen must not be after last_seen")
    if valid_from and valid_until and valid_from > valid_until:
        raise HTTPException(422, "valid_until must not be before valid_from")


def dump(item: Any, *, raw: bool = True) -> dict[str, Any]:
    if hasattr(item, "__table__"):
        data = {column.name: getattr(item, column.name) for column in item.__table__.columns if column.name != "html_content"}
    else:
        data = {key: value for key, value in vars(item).items() if not key.startswith("_") and key != "html_content"}
    for key in list(data):
        if key.endswith("_json"):
            try:
                data[key[:-5]] = json.loads(data.pop(key) or "[]")
            except (TypeError, json.JSONDecodeError):
                data[key[:-5]] = []
    if isinstance(item, ThreatIndicator):
        data["display_value"] = defang(item.normalized_value, item.indicator_type)
        data["expired"] = bool(item.valid_until and comparable(item.valid_until) < now())
        if not raw:
            data.pop("value", None)
            data.pop("normalized_value", None)
    return data


def comparable(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def create_or_merge_indicator(db: Session, payload: dict[str, Any], user_id: int | None, *, externally_supplied: bool = False) -> tuple[ThreatIndicator, bool]:
    try:
        normalized = normalize_indicator(payload.get("type") or payload.get("indicator_type"), payload.get("value"))
    except IndicatorValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    first_seen = payload.get("first_seen") or payload.get("first_seen_at")
    last_seen = payload.get("last_seen") or payload.get("last_seen_at")
    valid_until = payload.get("valid_until")
    valid_from = payload.get("valid_from")
    validate_lifecycle(first_seen, last_seen, valid_until, valid_from)
    source_id = payload.get("source_id")
    if source_id is not None and not db.get(models.ThreatIntelSource, source_id):
        raise HTTPException(422, "Threat-intelligence source not found")
    existing = db.query(ThreatIndicator).filter_by(indicator_type=normalized.indicator_type, normalized_value=normalized.normalized).first()
    tags = clean_tags(payload.get("tags"))
    confidence = int(payload.get("confidence", 50))
    if not 0 <= confidence <= 100:
        raise HTTPException(422, "confidence must be between 0 and 100")
    if existing:
        prior_tags = json.loads(existing.tags_json or "[]")
        existing.tags_json = json.dumps(clean_tags(prior_tags + tags), sort_keys=True)
        existing.confidence = max(existing.confidence, confidence)
        if first_seen and (not existing.first_seen_at or first_seen < existing.first_seen_at):
            existing.first_seen_at = first_seen
        if last_seen and (not existing.last_seen_at or last_seen > existing.last_seen_at):
            existing.last_seen_at = last_seen
        # Source identity and revoked lifecycle are intentionally never overwritten by a duplicate.
        return existing, True
    item = ThreatIndicator(
        source_id=source_id,
        indicator_type=normalized.indicator_type,
        value=normalized.original,
        normalized_value=normalized.normalized,
        value_hash=normalized.value_hash,
        title=bounded(payload.get("title"), 240),
        description=bounded(payload.get("description"), 4000),
        severity=payload.get("severity", "medium"),
        confidence=confidence,
        tlp=payload.get("tlp", "amber"),
        tags_json=json.dumps(tags, sort_keys=True),
        first_seen_at=first_seen,
        last_seen_at=last_seen,
        valid_from=valid_from,
        valid_until=valid_until,
        externally_supplied=externally_supplied,
        created_by_user_id=user_id,
    )
    if item.severity not in SEVERITY_WEIGHT or item.tlp not in TLPS:
        raise HTTPException(422, "Unsupported severity or TLP")
    db.add(item)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = db.query(ThreatIndicator).filter_by(indicator_type=normalized.indicator_type, normalized_value=normalized.normalized).first()
        if existing:
            return existing, True
        raise HTTPException(409, "Indicator identity conflict") from exc
    return item, False


def seed_watchlists(db: Session):
    admin = db.query(models.UserAccount).filter_by(is_system_admin=True).order_by(models.UserAccount.id).first()
    if not admin:
        return
    definitions = [
        ("High-Risk Indicators", "Protected collection for high and critical indicators.", "high"),
        ("Confirmed Malicious", "Protected collection for analyst-confirmed malicious indicators.", None),
        ("Under Investigation", "Protected collection for active analyst review.", None),
    ]
    changed = False
    for name, description, threshold in definitions:
        if not db.query(ThreatWatchlist).filter_by(name=name).first():
            db.add(ThreatWatchlist(name=name, description=description, severity_threshold=threshold, system_owned=True, created_by_user_id=admin.id))
            changed = True
    if changed:
        db.commit()


def post_commit_event(db: Session, request: Request, user, action: str, resource_type: str, resource_id: int, message: str, *, notify: tuple[str, str, str] | None = None):
    append_event(db, event_type="threat_intelligence", action=action, request_id=getattr(request.state, "request_id", "unknown"), outcome="success", actor=user, resource_type=resource_type, resource_id=resource_id, route_template=request.url.path, request_method=request.method, status_code=200)
    db.add(SocActivity(action=action[:80], message=message[:1000], entity_type=resource_type[:40], entity_id=resource_id))
    if notify:
        title, body, level = notify
        exists = db.query(models.Notification).filter_by(title=title[:255], message=body[:1000], entity_type=resource_type, entity_id=resource_id).first()
        if not exists:
            db.add(models.Notification(title=title[:255], message=body[:1000], type=level, entity_type=resource_type, entity_id=resource_id))
    db.commit()
