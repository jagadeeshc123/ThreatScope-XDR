from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db

router = APIRouter()

@router.get("/", response_model=schemas.AppSettings)
def get_settings(db: Session = Depends(get_db)):
    settings = db.query(models.AppSettings).first()
    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")
    return settings

@router.patch("/", response_model=schemas.AppSettings)
def update_settings(settings_update: schemas.AppSettingsUpdate, db: Session = Depends(get_db)):
    settings = db.query(models.AppSettings).first()
    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")
    
    update_data = settings_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(settings, key, value)
        
    db.commit()
    db.refresh(settings)
    return settings

@router.post("/reset", response_model=schemas.AppSettings)
def reset_settings(db: Session = Depends(get_db)):
    settings = db.query(models.AppSettings).first()
    if settings:
        db.delete(settings)
        db.commit()
        
    new_settings = models.AppSettings()
    db.add(new_settings)
    db.commit()
    db.refresh(new_settings)
    return new_settings
