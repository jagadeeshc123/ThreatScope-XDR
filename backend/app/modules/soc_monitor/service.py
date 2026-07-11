import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException, UploadFile
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor import schemas
from app.modules.soc_monitor.normalization import normalize_event
from app.modules.soc_monitor.parsers import parse_content
from app.modules.soc_monitor.redaction import redact_text
from app.modules.soc_monitor.simulator import DISCLAIMER as SIMULATOR_DISCLAIMER, generate


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_IMPORT_EVENTS = 10_000
SOURCE_PARSER_COMPATIBILITY = {
    "simulator": {"simulator"}, "jsonl": {"jsonl"}, "csv": {"csv"},
    "access_log": {"access_log"}, "auth_log": {"auth_log"}, "key_value": {"key_value"},
}
EXTENSIONS = {"jsonl": {".jsonl", ".ndjson"}, "csv": {".csv"}, "access_log": {".log", ".txt"}, "auth_log": {".log", ".txt"}, "key_value": {".log", ".txt"}}


def utcnow():
    return datetime.now(timezone.utc)


def add_activity(db: Session, action: str, message: str, entity_type: str, entity_id: Optional[int] = None):
    db.add(models.SocActivity(action=action, message=redact_text(message, 2000), entity_type=entity_type, entity_id=entity_id))


def notify(db: Session, title: str, message: str, kind: str, entity_type: str, entity_id: Optional[int]):
    db.add(models.Notification(title=title, message=redact_text(message, 2000), type=kind, entity_type=entity_type, entity_id=entity_id))


def validate_source_pair(source_type: str, parser_type: str):
    if parser_type not in SOURCE_PARSER_COMPATIBILITY.get(source_type, set()):
        raise HTTPException(status_code=422, detail="Parser type is incompatible with this source type")


def get_source(db: Session, source_id: int):
    source = db.query(models.SocLogSource).filter(models.SocLogSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="SOC log source not found")
    return source


def create_source(db: Session, payload: schemas.SourceCreate):
    validate_source_pair(payload.source_type, payload.parser_type)
    source = models.SocLogSource(**payload.model_dump())
    db.add(source)
    db.flush()
    add_activity(db, "source_created", f"Log source {source.name} created.", "soc_source", source.id)
    db.commit(); db.refresh(source)
    return source


def update_source(db: Session, source_id: int, payload: schemas.SourceUpdate):
    source = get_source(db, source_id)
    changes = payload.model_dump(exclude_unset=True)
    source_type = changes.get("source_type", source.source_type)
    parser_type = changes.get("parser_type", source.parser_type)
    validate_source_pair(source_type, parser_type)
    for key, value in changes.items():
        setattr(source, key, value)
    db.commit(); db.refresh(source)
    return source


def delete_source(db: Session, source_id: int):
    source = get_source(db, source_id)
    if db.query(models.SocEvent).filter(models.SocEvent.source_id == source_id).count() or db.query(models.SocLogImport).filter(models.SocLogImport.source_id == source_id).count():
        raise HTTPException(status_code=409, detail="Source has related imports or events and cannot be deleted")
    db.delete(source); db.commit()


def event_to_read(event) -> Dict[str, Any]:
    return {key: getattr(event, key) for key in (
        "id", "source_id", "import_id", "event_time", "received_at", "event_type", "action", "outcome", "severity", "source_ip", "destination_ip", "username", "http_method", "request_path", "status_code", "user_agent", "message", "raw_event_hash", "raw_preview_redacted", "created_at"
    )} | {"normalized_json": json.loads(event.normalized_json or "{}")}


def rule_to_read(rule) -> Dict[str, Any]:
    return {key: getattr(rule, key) for key in ("id", "rule_code", "name", "description", "rule_type", "enabled", "severity", "confidence", "window_seconds", "threshold", "group_by", "remediation", "is_default", "created_at", "updated_at")} | {"conditions_json": json.loads(rule.conditions_json or "{}")}


def alert_to_read(alert) -> Dict[str, Any]:
    return {key: getattr(alert, key) for key in ("id", "rule_id", "title", "description", "severity", "confidence", "status", "first_seen", "last_seen", "event_count", "correlation_key", "source_ip", "username", "evidence_summary", "fingerprint", "analyst_notes", "created_at", "updated_at")} | {"rule_code": alert.rule.rule_code, "rule_name": alert.rule.name}


def report_to_read(report) -> Dict[str, Any]:
    return {"id": report.id, "title": report.title, "report_type": report.report_type, "html_content": report.html_content, "summary_json": json.loads(report.summary_json), "created_at": report.created_at}


def enrichment_to_read(result) -> Dict[str, Any]:
    return {key: getattr(result, key) for key in ("id", "alert_id", "indicator_type", "indicator_value", "reputation", "confidence", "source_name", "explanation", "created_at")} | {"tags_json": json.loads(result.tags_json or "[]"), "disclaimer": "This enrichment uses local demonstration intelligence and is not live reputation data."}


def insert_event(db: Session, source, data: Dict[str, Any], raw: str, import_id: int | None = None, fallback_time: datetime | None = None) -> bool:
    normalized = normalize_event(data, raw, fallback_time)
    if db.query(models.SocEvent.id).filter(models.SocEvent.raw_event_hash == normalized["raw_event_hash"]).first():
        return False
    db.add(models.SocEvent(source_id=source.id, import_id=import_id, **normalized))
    db.flush()
    return True


async def import_log(db: Session, source_id: int, file: UploadFile):
    source = get_source(db, source_id)
    if source.parser_type == "simulator":
        raise HTTPException(status_code=422, detail="Simulator sources do not accept file imports")
    filename = Path(file.filename or "").name
    if filename != (file.filename or "") or Path(filename).suffix.lower() not in EXTENSIONS[source.parser_type]:
        raise HTTPException(status_code=422, detail="Unsupported file extension")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded log exceeds the 5 MB limit")
    file_hash = hashlib.sha256(content).hexdigest()
    record = models.SocLogImport(source_id=source.id, filename=filename, file_hash=file_hash, status="processing")
    db.add(record); db.flush()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        record.status = "failed"; record.error_summary = "File must use UTF-8 text encoding"; record.completed_at = utcnow(); db.commit()
        raise HTTPException(status_code=422, detail=record.error_summary)
    rows = parse_content(source.parser_type, text)
    record.total_lines = len(rows)
    accepted = rejected = 0
    errors = []
    for index, (data, raw, error) in enumerate(rows):
        if accepted >= MAX_IMPORT_EVENTS:
            rejected += 1
            if len(errors) < 5: errors.append("10,000-event import limit reached")
            continue
        if error or data is None:
            rejected += 1
            if len(errors) < 5: errors.append(f"Line {index + 1}: {redact_text(error or 'Malformed row', 240)}")
            continue
        try:
            if insert_event(db, source, data, raw, record.id): accepted += 1
            else: rejected += 1
        except Exception:
            rejected += 1
            if len(errors) < 5: errors.append(f"Line {index + 1}: normalization rejected")
    record.accepted_events, record.rejected_events = accepted, rejected
    record.status, record.completed_at = "completed", utcnow()
    record.error_summary = "; ".join(errors) or None
    source.event_count += accepted; source.last_ingested_at = record.completed_at
    add_activity(db, "import_completed", f"Import {filename} completed: {accepted} accepted, {rejected} rejected.", "soc_import", record.id)
    notify(db, "SOC Log Import Completed", f"{filename}: {accepted} events accepted and {rejected} rejected.", "success", "soc_import", record.id)
    db.commit(); db.refresh(record)
    return record


def simulate(db: Session, payload: schemas.SimulatorRequest):
    if payload.source_id:
        source = get_source(db, payload.source_id)
        if source.source_type != "simulator": raise HTTPException(status_code=422, detail="Selected source is not a simulator source")
    else:
        source = db.query(models.SocLogSource).filter(models.SocLogSource.source_type == "simulator").order_by(models.SocLogSource.id).first()
        if not source:
            source = models.SocLogSource(name="Safe Synthetic Events", description=SIMULATOR_DISCLAIMER, source_type="simulator", parser_type="simulator", enabled=True)
            db.add(source); db.flush()
            add_activity(db, "source_created", "Safe synthetic event source created.", "soc_source", source.id)
    events = generate(payload.scenario, payload.number_of_events, payload.seed, payload.start_time)
    created = skipped = 0
    for event in events:
        raw = json.dumps(event, sort_keys=True)
        if insert_event(db, source, event, raw): created += 1
        else: skipped += 1
    source.event_count += created
    if created: source.last_ingested_at = utcnow()
    add_activity(db, "synthetic_events_generated", f"Generated {created} {payload.scenario} synthetic events; {skipped} duplicates skipped.", "soc_source", source.id)
    db.commit()
    times = [datetime.fromisoformat(event["timestamp"]) for event in events]
    return {"events_created": created, "events_skipped_as_duplicates": skipped, "source_id": source.id, "start_time": min(times), "end_time": max(times), "disclaimer": SIMULATOR_DISCLAIMER}


def validate_indicator(indicator_type: str, value: str):
    value = value.strip()
    if indicator_type == "ip":
        try: ipaddress.ip_address(value)
        except ValueError: raise HTTPException(status_code=422, detail="Invalid IP indicator")
    elif indicator_type == "domain":
        if len(value) > 253 or not all(part and part.replace("-", "").isalnum() for part in value.lower().rstrip(".").split(".")):
            raise HTTPException(status_code=422, detail="Invalid domain indicator")
    elif indicator_type == "username":
        if not value or any(char in value for char in "\r\n\0"):
            raise HTTPException(status_code=422, detail="Invalid username indicator")
    return value


def overview(db: Session):
    now = utcnow(); since = now - timedelta(hours=24)
    def grouped(model, field): return {str(key or "unknown"): count for key, count in db.query(field, func.count(model.id)).group_by(field).all()}
    top_ips = [{"value": value, "count": count} for value, count in db.query(models.SocEvent.source_ip, func.count(models.SocEvent.id)).filter(models.SocEvent.source_ip.isnot(None)).group_by(models.SocEvent.source_ip).order_by(func.count(models.SocEvent.id).desc()).limit(8).all()]
    top_users = [{"value": value, "count": count} for value, count in db.query(models.SocEvent.username, func.count(models.SocEvent.id)).filter(models.SocEvent.username.isnot(None)).group_by(models.SocEvent.username).order_by(func.count(models.SocEvent.id).desc()).limit(8).all()]
    alerts = db.query(models.SocAlert).order_by(models.SocAlert.last_seen.desc()).limit(8).all()
    return {"total_events": db.query(models.SocEvent).count(), "events_last_24_hours": db.query(models.SocEvent).filter(models.SocEvent.event_time >= since).count(), "open_alerts": db.query(models.SocAlert).filter(models.SocAlert.status.in_(["open", "investigating"])).count(), "high_alerts": db.query(models.SocAlert).filter(models.SocAlert.severity == "high").count(), "critical_alerts": db.query(models.SocAlert).filter(models.SocAlert.severity == "critical").count(), "total_sources": db.query(models.SocLogSource).count(), "enabled_sources": db.query(models.SocLogSource).filter(models.SocLogSource.enabled == True).count(), "active_rules": db.query(models.SocDetectionRule).filter(models.SocDetectionRule.enabled == True).count(), "active_blocklist_entries": db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.status == "active", or_(models.SocBlocklistEntry.expires_at.is_(None), models.SocBlocklistEntry.expires_at > now)).count(), "events_by_type": grouped(models.SocEvent, models.SocEvent.event_type), "alerts_by_severity": grouped(models.SocAlert, models.SocAlert.severity), "alerts_by_status": grouped(models.SocAlert, models.SocAlert.status), "top_source_ips": top_ips, "top_usernames": top_users, "recent_alerts": [alert_to_read(a) for a in alerts], "recent_imports": db.query(models.SocLogImport).order_by(models.SocLogImport.created_at.desc()).limit(8).all(), "recent_activity": db.query(models.SocActivity).order_by(models.SocActivity.created_at.desc()).limit(12).all()}
