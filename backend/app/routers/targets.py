from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
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

@router.patch("/{target_id}", response_model=schemas.Target)
def update_target(target_id: int, target_update: schemas.TargetUpdate, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    update_data = target_update.model_dump(exclude_unset=True)
    if "base_url" in update_data:
        parsed = urlparse(update_data["base_url"])
        update_data["domain"] = parsed.netloc or update_data["base_url"]
    for key, value in update_data.items():
        setattr(target, key, value)
    db.commit()
    db.refresh(target)
    return target

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    scan_ids = [row.id for row in db.query(models.Scan.id).filter(models.Scan.target_id == target_id).all()]
    report_ids = [row.id for row in db.query(models.Report.id).filter(models.Report.target_id == target_id).all()]
    if scan_ids or report_ids:
        db.query(models.Notification).filter(or_(
            and_(models.Notification.entity_type == "scan", models.Notification.entity_id.in_(scan_ids)),
            and_(models.Notification.entity_type == "report", models.Notification.entity_id.in_(report_ids)),
        )).delete(synchronize_session=False)
    db.query(models.PostureDiff).filter(models.PostureDiff.target_id == target_id).delete(synchronize_session=False)
    db.query(models.EvidenceArtifact).filter(models.EvidenceArtifact.target_id == target_id).delete(synchronize_session=False)
    db.query(models.CrawlNode).filter(models.CrawlNode.target_id == target_id).delete(synchronize_session=False)
    db.query(models.Finding).filter(models.Finding.target_id == target_id).delete(synchronize_session=False)
    db.query(models.Report).filter(models.Report.target_id == target_id).delete(synchronize_session=False)
    db.query(models.Scan).filter(models.Scan.target_id == target_id).delete(synchronize_session=False)
    db.delete(target)
    db.commit()
    return {"ok": True}
