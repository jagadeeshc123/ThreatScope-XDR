from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db
from typing import List

router = APIRouter()

@router.get("/", response_model=List[schemas.Notification])
def get_notifications(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    return db.query(models.Notification).order_by(models.Notification.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/unread-count")
def get_unread_count(db: Session = Depends(get_db)):
    count = db.query(models.Notification).filter(models.Notification.is_read == False).count()
    return {"unread_count": count}

@router.patch("/{notification_id}/read", response_model=schemas.Notification)
def mark_as_read(notification_id: int, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    db.refresh(notif)
    return notif

@router.patch("/mark-all-read")
def mark_all_read(db: Session = Depends(get_db)):
    db.query(models.Notification).filter(models.Notification.is_read == False).update({"is_read": True})
    db.commit()
    return {"status": "ok"}

@router.delete("/{notification_id}")
def delete_notification(notification_id: int, db: Session = Depends(get_db)):
    notif = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(notif)
    db.commit()
    return {"status": "ok"}
