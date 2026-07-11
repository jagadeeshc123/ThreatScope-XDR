import hashlib
import json
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.redaction import redact_text
from app.modules.soc_monitor.schemas import DetectionRunRequest
from app.modules.soc_monitor.service import add_activity, notify


DISCLAIMER = "Offline correlation completed locally — no external systems contacted."


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def matches(event, conditions: dict) -> bool:
    if conditions.get("event_types") and event.event_type not in conditions["event_types"]: return False
    if conditions.get("outcomes") and event.outcome not in conditions["outcomes"]: return False
    if conditions.get("status_codes") and event.status_code not in conditions["status_codes"]: return False
    return True


def group_value(event, group_by: str):
    value = getattr(event, group_by, None)
    if group_by == "username" and not value: value = event.source_ip
    return str(value) if value not in (None, "") else "unknown"


def qualifying_windows(rule, events: Iterable, active_blocklist: set[str]) -> List[tuple[str, list]]:
    conditions = json.loads(rule.conditions_json or "{}")
    groups: Dict[str, deque] = defaultdict(deque)
    results: Dict[str, list] = {}
    window_seconds = rule.window_seconds
    for event in events:
        if rule.rule_type == "blocklist":
            if event.source_ip not in active_blocklist: continue
        elif rule.rule_type == "admin_after_failures":
            key = group_value(event, rule.group_by)
            window = groups[key]
            while window and (aware(event.event_time) - aware(window[0].event_time)).total_seconds() > window_seconds: window.popleft()
            window.append(event)
            path = (event.request_path or "").lower()
            is_admin = any(fragment in path for fragment in conditions.get("path_contains", []))
            failures = [item for item in window if item.outcome in {"failure", "denied"} and item.id != event.id]
            if is_admin and len(failures) >= rule.threshold:
                results[key] = failures + [event]
            continue
        elif not matches(event, conditions):
            continue
        key = group_value(event, rule.group_by)
        window = groups[key]
        while window and (aware(event.event_time) - aware(window[0].event_time)).total_seconds() > window_seconds: window.popleft()
        window.append(event)
        if rule.rule_type == "distinct_threshold":
            distinct_field = conditions.get("distinct_field")
            qualifies = len({getattr(item, distinct_field, None) for item in window if getattr(item, distinct_field, None)}) >= rule.threshold
        else:
            qualifies = len(window) >= rule.threshold
        if qualifies: results[key] = list(window)
    return list(results.items())


def run(db: Session, payload: DetectionRunRequest):
    rule_query = db.query(models.SocDetectionRule).filter(models.SocDetectionRule.enabled == True)
    if payload.rule_ids: rule_query = rule_query.filter(models.SocDetectionRule.id.in_(payload.rule_ids))
    rules = rule_query.order_by(models.SocDetectionRule.id).all()
    event_query = db.query(models.SocEvent)
    if payload.source_id: event_query = event_query.filter(models.SocEvent.source_id == payload.source_id)
    if payload.start_time: event_query = event_query.filter(models.SocEvent.event_time >= payload.start_time)
    if payload.end_time: event_query = event_query.filter(models.SocEvent.event_time <= payload.end_time)
    events = event_query.order_by(models.SocEvent.event_time.asc(), models.SocEvent.id.asc()).all()
    active_blocklist = {row.indicator_value for row in db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.indicator_type == "ip", models.SocBlocklistEntry.status == "active").all()}
    created = updated = skipped = 0
    for rule in rules:
        for correlation_key, contributing in qualifying_windows(rule, events, active_blocklist):
            first_seen = aware(contributing[0].event_time); last_seen = aware(contributing[-1].event_time)
            bucket = int(first_seen.timestamp()) // rule.window_seconds
            fingerprint = hashlib.sha256(f"{rule.rule_code}|{correlation_key}|{bucket}".encode()).hexdigest()
            existing = db.query(models.SocAlert).filter(models.SocAlert.fingerprint == fingerprint).first()
            ids = {event.id for event in contributing}
            evidence = redact_text(f"{len(ids)} correlated events for {rule.group_by}={correlation_key} from {first_seen.isoformat()} through {last_seen.isoformat()}.", 2000)
            if existing:
                existing_ids = {link.event_id for link in existing.event_links}
                new_ids = ids - existing_ids
                if not new_ids and existing.last_seen == contributing[-1].event_time:
                    skipped += 1; continue
                for event_id in new_ids: db.add(models.SocAlertEvent(alert_id=existing.id, event_id=event_id))
                existing.first_seen = min(aware(existing.first_seen), first_seen)
                existing.last_seen = max(aware(existing.last_seen), last_seen)
                existing.event_count = len(existing_ids | ids); existing.evidence_summary = evidence
                updated += 1
            else:
                sample = contributing[-1]
                alert = models.SocAlert(rule_id=rule.id, title=rule.name, description=rule.description, severity=rule.severity, confidence=rule.confidence, status="open", first_seen=first_seen, last_seen=last_seen, event_count=len(ids), correlation_key=f"{rule.group_by}:{correlation_key}", source_ip=sample.source_ip if rule.group_by == "source_ip" or sample.source_ip else None, username=sample.username, evidence_summary=evidence, fingerprint=fingerprint)
                db.add(alert); db.flush()
                for event_id in ids: db.add(models.SocAlertEvent(alert_id=alert.id, event_id=event_id))
                if rule.severity in {"high", "critical"}:
                    notify(db, f"{rule.severity.title()} SOC Alert", f"{rule.name}: {evidence}", "danger" if rule.severity == "critical" else "warning", "soc_alert", alert.id)
                created += 1
    add_activity(db, "detection_run_completed", f"Detection run processed {len(events)} events and created {created} alerts.", "soc_detection", None)
    db.commit()
    return {"rules_processed": len(rules), "events_processed": len(events), "alerts_created": created, "alerts_updated": updated, "duplicate_alerts_skipped": skipped, "disclaimer": DISCLAIMER}

