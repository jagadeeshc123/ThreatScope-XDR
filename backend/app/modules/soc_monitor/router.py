import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.modules.soc_monitor import blocklist, correlation, enrichment, report_service, schemas, service
from app.modules.soc_monitor.detection_rules import seed_default_rules
from app.modules.soc_monitor.redaction import redact_text


router = APIRouter()


@router.get("/overview", response_model=schemas.Overview)
def get_overview(db: Session = Depends(get_db)):
    seed_default_rules(db)
    return service.overview(db)


@router.get("/sources", response_model=list[schemas.SourceRead])
def list_sources(db: Session = Depends(get_db)):
    return db.query(models.SocLogSource).order_by(models.SocLogSource.created_at.desc()).all()


@router.post("/sources", response_model=schemas.SourceRead)
def create_source(payload: schemas.SourceCreate, db: Session = Depends(get_db)):
    return service.create_source(db, payload)


@router.get("/sources/{source_id}", response_model=schemas.SourceRead)
def get_source(source_id: int, db: Session = Depends(get_db)):
    return service.get_source(db, source_id)


@router.patch("/sources/{source_id}", response_model=schemas.SourceRead)
def update_source(source_id: int, payload: schemas.SourceUpdate, db: Session = Depends(get_db)):
    return service.update_source(db, source_id, payload)


@router.delete("/sources/{source_id}")
def delete_source(source_id: int, db: Session = Depends(get_db)):
    service.delete_source(db, source_id); return {"ok": True}


@router.post("/sources/{source_id}/imports", response_model=schemas.ImportRead)
async def import_source_log(source_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    return await service.import_log(db, source_id, file)


@router.get("/imports", response_model=list[schemas.ImportRead])
def list_imports(source_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(models.SocLogImport)
    if source_id: query = query.filter(models.SocLogImport.source_id == source_id)
    return query.order_by(models.SocLogImport.created_at.desc()).all()


@router.get("/imports/{import_id}", response_model=schemas.ImportRead)
def get_import(import_id: int, db: Session = Depends(get_db)):
    item = db.query(models.SocLogImport).filter(models.SocLogImport.id == import_id).first()
    if not item: raise HTTPException(status_code=404, detail="SOC log import not found")
    return item


@router.get("/events", response_model=schemas.EventPage)
def list_events(
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), source_id: Optional[int] = None,
    event_type: Optional[str] = None, severity: Optional[str] = None, source_ip: Optional[str] = None,
    username: Optional[str] = None, outcome: Optional[str] = None, status_code: Optional[int] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, q: Optional[str] = Query(None, max_length=200),
    db: Session = Depends(get_db),
):
    query = db.query(models.SocEvent)
    filters = {"source_id": source_id, "event_type": event_type, "severity": severity, "source_ip": source_ip, "username": username, "outcome": outcome, "status_code": status_code}
    for field, value in filters.items():
        if value is not None: query = query.filter(getattr(models.SocEvent, field) == value)
    if start_time: query = query.filter(models.SocEvent.event_time >= start_time)
    if end_time: query = query.filter(models.SocEvent.event_time <= end_time)
    if q:
        term = f"%{q}%"
        query = query.filter(or_(models.SocEvent.message.ilike(term), models.SocEvent.raw_preview_redacted.ilike(term), models.SocEvent.request_path.ilike(term), models.SocEvent.username.ilike(term), models.SocEvent.source_ip.ilike(term)))
    total = query.count(); items = query.order_by(models.SocEvent.event_time.desc(), models.SocEvent.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [service.event_to_read(item) for item in items], "total": total, "page": page, "page_size": page_size}


@router.get("/events/{event_id}", response_model=schemas.EventRead)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(models.SocEvent).filter(models.SocEvent.id == event_id).first()
    if not event: raise HTTPException(status_code=404, detail="SOC event not found")
    return service.event_to_read(event)


@router.get("/rules", response_model=list[schemas.RuleRead])
def list_rules(db: Session = Depends(get_db)):
    seed_default_rules(db)
    return [service.rule_to_read(item) for item in db.query(models.SocDetectionRule).order_by(models.SocDetectionRule.rule_code).all()]


@router.post("/rules", response_model=schemas.RuleRead)
def create_rule(payload: schemas.RuleCreate, db: Session = Depends(get_db)):
    rule = models.SocDetectionRule(**payload.model_dump(exclude={"conditions_json"}), conditions_json=json.dumps(payload.conditions_json, sort_keys=True), is_default=False)
    db.add(rule)
    try: db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(status_code=409, detail="Rule code already exists")
    db.refresh(rule); return service.rule_to_read(rule)


def rule_or_404(db, rule_id):
    rule = db.query(models.SocDetectionRule).filter(models.SocDetectionRule.id == rule_id).first()
    if not rule: raise HTTPException(status_code=404, detail="SOC detection rule not found")
    return rule


@router.get("/rules/{rule_id}", response_model=schemas.RuleRead)
def get_rule(rule_id: int, db: Session = Depends(get_db)): return service.rule_to_read(rule_or_404(db, rule_id))


@router.patch("/rules/{rule_id}", response_model=schemas.RuleRead)
def update_rule(rule_id: int, payload: schemas.RuleUpdate, db: Session = Depends(get_db)):
    rule = rule_or_404(db, rule_id)
    changes = payload.model_dump(exclude_unset=True)
    if "conditions_json" in changes: changes["conditions_json"] = json.dumps(changes["conditions_json"], sort_keys=True)
    for key, value in changes.items(): setattr(rule, key, value)
    db.commit(); db.refresh(rule); return service.rule_to_read(rule)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = rule_or_404(db, rule_id)
    if rule.is_default: raise HTTPException(status_code=409, detail="Default rules cannot be deleted")
    if rule.alerts: raise HTTPException(status_code=409, detail="Rule has related alerts and cannot be deleted")
    db.delete(rule); db.commit(); return {"ok": True}


@router.post("/simulator/generate", response_model=schemas.SimulatorResult)
def generate_simulator_events(payload: schemas.SimulatorRequest, db: Session = Depends(get_db)): return service.simulate(db, payload)


@router.post("/detections/run", response_model=schemas.DetectionRunResult)
def run_detections(payload: schemas.DetectionRunRequest, db: Session = Depends(get_db)):
    seed_default_rules(db); return correlation.run(db, payload)


@router.get("/alerts", response_model=schemas.AlertPage)
def list_alerts(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), status: Optional[str] = None, severity: Optional[str] = None, confidence: Optional[str] = None, rule_id: Optional[int] = None, source_ip: Optional[str] = None, username: Optional[str] = None, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, db: Session = Depends(get_db)):
    query = db.query(models.SocAlert)
    for field, value in {"status": status, "severity": severity, "confidence": confidence, "rule_id": rule_id, "source_ip": source_ip, "username": username}.items():
        if value is not None: query = query.filter(getattr(models.SocAlert, field) == value)
    if start_time: query = query.filter(models.SocAlert.last_seen >= start_time)
    if end_time: query = query.filter(models.SocAlert.first_seen <= end_time)
    total = query.count(); items = query.order_by(models.SocAlert.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [service.alert_to_read(item) for item in items], "total": total, "page": page, "page_size": page_size}


def alert_or_404(db, alert_id):
    alert = db.query(models.SocAlert).filter(models.SocAlert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404, detail="SOC alert not found")
    return alert


@router.get("/alerts/{alert_id}", response_model=schemas.AlertDetail)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = alert_or_404(db, alert_id)
    entries = db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.source_alert_id == alert.id).all()
    return service.alert_to_read(alert) | {"events": [service.event_to_read(link.event) for link in sorted(alert.event_links, key=lambda link: link.event.event_time)], "enrichments": [service.enrichment_to_read(item) for item in alert.enrichments], "blocklist_entries": [{"id": item.id, "indicator_type": item.indicator_type, "indicator_value": item.indicator_value, "status": item.status, "reason": item.reason} for item in entries]}


@router.patch("/alerts/{alert_id}", response_model=schemas.AlertRead)
def update_alert(alert_id: int, payload: schemas.AlertUpdate, db: Session = Depends(get_db)):
    alert = alert_or_404(db, alert_id)
    transitions = {"open": {"investigating", "false_positive"}, "investigating": {"contained", "resolved", "false_positive", "open"}, "contained": {"resolved", "investigating"}, "resolved": {"investigating"}, "false_positive": {"investigating"}}
    if payload.status and payload.status != alert.status and payload.status not in transitions[alert.status]: raise HTTPException(status_code=422, detail="Invalid alert status transition")
    if payload.status: alert.status = payload.status
    if payload.analyst_notes is not None: alert.analyst_notes = redact_text(payload.analyst_notes, 8000)
    service.add_activity(db, "alert_status_changed", f"Alert {alert.id} updated to {alert.status}.", "soc_alert", alert.id)
    db.commit(); db.refresh(alert); return service.alert_to_read(alert)


@router.post("/enrichment", response_model=schemas.EnrichmentRead)
def enrich_indicator(payload: schemas.EnrichmentRequest, db: Session = Depends(get_db)):
    return service.enrichment_to_read(enrichment.enrich(db, payload.alert_id, payload.indicator_type, payload.indicator_value))


@router.get("/blocklist", response_model=list[schemas.BlocklistRead])
def list_blocklist(db: Session = Depends(get_db)): return db.query(models.SocBlocklistEntry).order_by(models.SocBlocklistEntry.created_at.desc()).all()


@router.post("/blocklist", response_model=schemas.BlocklistRead)
def create_blocklist(payload: schemas.BlocklistCreate, db: Session = Depends(get_db)): return blocklist.create(db, payload)


@router.patch("/blocklist/{entry_id}", response_model=schemas.BlocklistRead)
def update_blocklist(entry_id: int, payload: schemas.BlocklistUpdate, db: Session = Depends(get_db)): return blocklist.update(db, entry_id, payload)


@router.delete("/blocklist/{entry_id}")
def delete_blocklist(entry_id: int, db: Session = Depends(get_db)): blocklist.delete(db, entry_id); return {"ok": True}


@router.post("/reports", response_model=schemas.ReportRead)
def create_report(payload: schemas.ReportCreate, db: Session = Depends(get_db)): return service.report_to_read(report_service.generate(db, payload.report_type))


@router.get("/reports", response_model=list[schemas.ReportRead])
def list_reports(db: Session = Depends(get_db)): return [service.report_to_read(item) for item in db.query(models.SocReport).order_by(models.SocReport.created_at.desc()).all()]


def report_or_404(db, report_id):
    report = db.query(models.SocReport).filter(models.SocReport.id == report_id).first()
    if not report: raise HTTPException(status_code=404, detail="SOC report not found")
    return report


@router.get("/reports/{report_id}", response_model=schemas.ReportRead)
def get_report(report_id: int, db: Session = Depends(get_db)): return service.report_to_read(report_or_404(db, report_id))


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = report_or_404(db, report_id)
    return Response(content=report.html_content, media_type="text/html", headers={"Content-Disposition": f"attachment; filename=soc-report-{report.id}.html"})

