from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.service import add_activity, notify, validate_indicator


DISCLAIMER = "Local simulation only — this does not modify any real firewall or network control."


def create(db: Session, payload):
    value = validate_indicator(payload.indicator_type, payload.indicator_value)
    if payload.source_alert_id and not db.query(models.SocAlert.id).filter(models.SocAlert.id == payload.source_alert_id).first(): raise HTTPException(status_code=404, detail="SOC alert not found")
    existing = db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.indicator_type == payload.indicator_type, models.SocBlocklistEntry.indicator_value == value).first()
    if existing:
        existing.reason, existing.source_alert_id, existing.expires_at, existing.status = payload.reason, payload.source_alert_id, payload.expires_at, "active"
        entry = existing
    else:
        entry = models.SocBlocklistEntry(**payload.model_dump(exclude={"indicator_value"}), indicator_value=value, status="active")
        db.add(entry); db.flush()
    add_activity(db, "simulated_blocklist_updated", f"{payload.indicator_type} indicator added to the local simulated blocklist.", "soc_blocklist", entry.id)
    notify(db, "Simulated Blocklist Updated", DISCLAIMER, "warning", "soc_blocklist", entry.id)
    db.commit(); db.refresh(entry)
    return entry


def update(db: Session, entry_id: int, payload):
    entry = db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.id == entry_id).first()
    if not entry: raise HTTPException(status_code=404, detail="Blocklist entry not found")
    for key, value in payload.model_dump(exclude_unset=True).items(): setattr(entry, key, value)
    add_activity(db, "simulated_blocklist_updated", f"Simulated blocklist entry marked {entry.status}.", "soc_blocklist", entry.id)
    db.commit(); db.refresh(entry); return entry


def delete(db: Session, entry_id: int):
    entry = db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.id == entry_id).first()
    if not entry: raise HTTPException(status_code=404, detail="Blocklist entry not found")
    entry.status = "removed"; add_activity(db, "simulated_blocklist_updated", "Simulated blocklist entry removed.", "soc_blocklist", entry.id); db.commit()

