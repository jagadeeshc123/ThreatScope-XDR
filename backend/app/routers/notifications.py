from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, or_
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


def _visibility_filter(db: Session, request: Request):
    permissions = effective_permissions(db, request.state.current_user)
    known_types = tuple(ENTITY_PERMISSIONS)
    allowed_types = tuple(
        entity_type
        for entity_type, permission in ENTITY_PERMISSIONS.items()
        if permission in permissions
    )
    recipient_filter = or_(
        models.Notification.recipient_user_id.is_(None),
        models.Notification.recipient_user_id == request.state.current_user.id,
    )
    entity_filter = or_(
        models.Notification.entity_type.is_(None),
        models.Notification.entity_type.notin_(known_types),
        models.Notification.entity_type.in_(allowed_types),
    )
    return and_(recipient_filter, entity_filter)

@router.get("/", response_model=List[schemas.Notification])
def get_notifications(
    request: Request,
    skip: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return (
        db.query(models.Notification)
        .filter(_visibility_filter(db, request))
        .order_by(models.Notification.created_at.desc(), models.Notification.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

@router.get("/unread-count")
def get_unread_count(request: Request, db: Session = Depends(get_db)):
    count = (
        db.query(models.Notification)
        .filter(models.Notification.is_read.is_(False), _visibility_filter(db, request))
        .count()
    )
    return {"unread_count": count}

@router.patch("/mark-all-read")
def mark_all_read(request: Request, db: Session = Depends(get_db)):
    updated = (
        db.query(models.Notification)
        .filter(models.Notification.is_read.is_(False), _visibility_filter(db, request))
        .update({models.Notification.is_read: True}, synchronize_session=False)
    )
    db.commit()
    return {"status": "ok", "updated": updated}

@router.patch("/{notification_id}/read", response_model=schemas.Notification)
def mark_as_read(notification_id: int, request: Request, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif or not _visible(db, request, notif):
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    db.refresh(notif)
    return notif

@router.delete("/{notification_id}")
def delete_notification(notification_id: int, request: Request, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif or not _visible(db, request, notif):
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(notif)
    db.commit()
    return {"status": "ok"}
