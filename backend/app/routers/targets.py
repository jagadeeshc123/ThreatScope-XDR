from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from app import schemas, models
from app.database import get_db

router = APIRouter()

@router.get("/", response_model=list[schemas.Target])
def read_targets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    targets = db.query(models.Target).offset(skip).limit(limit).all()
    return targets

@router.post("/", response_model=schemas.Target)
def create_target(target: schemas.TargetCreate, db: Session = Depends(get_db)):
    if not target.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Must confirm authorization")

    parsed = urlparse(target.base_url)
    domain = parsed.netloc or target.base_url
    
    db_target = models.Target(
        name=target.name,
        base_url=target.base_url,
        domain=domain,
        environment=target.environment,
        authorization_confirmed=target.authorization_confirmed
    )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@router.get("/{target_id}", response_model=schemas.Target)
def read_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return {"ok": True}
