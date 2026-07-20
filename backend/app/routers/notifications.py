from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db
from typing import List
from app.modules.access_control.role_service import effective_permissions

router = APIRouter()

ENTITY_PERMISSIONS = {
    "scan": "web:read", "report": "web:read", "target": "web:read",
    "api_assessment": "api:read", "api_report": "api:read",
    "soc_alert": "soc:read", "soc_report": "soc:read", "soc_import": "soc:read", "soc_blocklist": "soc:read",
    "document_analysis": "document:read", "document_report": "document:read",
    "phishing_analysis": "phishing:read", "phishing_report": "phishing:read", "phishing_watchlist": "phishing:read",
    "correlation_match": "correlation:read", "incident_case": "cases:read", "incident_report": "cases:read",
    "governance_risk": "governance:read", "governance_mapping": "governance:read", "governance_exception": "governance:read", "governance_review": "governance:read", "governance_report": "governance:read",
    "user": "users:read", "security_audit": "audit:read",
    "operational_backup": "operations:backup", "operational_restore": "operations:restore",
    "operational_export": "operations:export", "operational_release": "operations:release",
    "operational_job": "operations:maintenance", "operational_retention": "operations:retention",
    "operational_demo": "operations:demo_manage", "operational_configuration": "operations:diagnostics",
    "vm_asset": "assets:view", "vm_asset_sync": "assets:view",
    "vm_vulnerability": "vulnerabilities:view", "vm_ingestion": "vulnerabilities:view",
    "vm_remediation_plan": "vulnerabilities:view", "vm_remediation_task": "vulnerabilities:view",
    "vm_sla": "vulnerabilities:view", "vm_risk_acceptance": "vulnerabilities:view",
    "vm_verification": "vulnerabilities:view", "vm_report": "vulnerabilities:export",
    "security_anomaly": "analytics:view", "analytics_detector": "analytics:view",
    "analytics_drift": "analytics:view", "analytics_suppression": "analytics:policy_manage", "analytics_report": "analytics:aggregate",
}

def _visible(db, request, item):
    if getattr(item, "recipient_user_id", None) is not None and item.recipient_user_id != request.state.current_user.id:
        return False
    required = ENTITY_PERMISSIONS.get(item.entity_type)
    return required is None or required in effective_permissions(db, request.state.current_user)

@router.get("/", response_model=List[schemas.Notification])
def get_notifications(request: Request, skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    items = db.query(models.Notification).order_by(models.Notification.created_at.desc()).all()
    return [item for item in items if _visible(db, request, item)][skip:skip + limit]

@router.get("/unread-count")
def get_unread_count(request: Request, db: Session = Depends(get_db)):
    count = sum(1 for item in db.query(models.Notification).filter(models.Notification.is_read == False).all() if _visible(db, request, item))
    return {"unread_count": count}

@router.patch("/{notification_id}/read", response_model=schemas.Notification)
def mark_as_read(notification_id: int, request: Request, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif or not _visible(db, request, notif):
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    db.refresh(notif)
    return notif

@router.patch("/mark-all-read")
def mark_all_read(request: Request, db: Session = Depends(get_db)):
    for item in db.query(models.Notification).filter(models.Notification.is_read == False).all():
        if _visible(db, request, item): item.is_read = True
    db.commit()
    return {"status": "ok"}

@router.delete("/{notification_id}")
def delete_notification(notification_id: int, request: Request, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif or not _visible(db, request, notif):
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(notif)
    db.commit()
    return {"status": "ok"}
