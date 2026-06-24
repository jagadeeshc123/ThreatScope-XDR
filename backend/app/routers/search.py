from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app import schemas, models
from app.database import get_db

router = APIRouter()

@router.get("/", response_model=schemas.SearchResults)
def search(q: str = "", db: Session = Depends(get_db)):
    if not q or len(q) < 2:
        return schemas.SearchResults(targets=[], scans=[], findings=[], reports=[])
        
    query = f"%{q}%"
    
    targets = db.query(models.Target).filter(
        or_(
            models.Target.name.ilike(query),
            models.Target.domain.ilike(query),
            models.Target.base_url.ilike(query)
        )
    ).limit(10).all()
    
    scans = db.query(models.Scan).join(models.Target).filter(
        or_(
            models.Scan.profile.ilike(query),
            models.Scan.status.ilike(query),
            models.Target.name.ilike(query)
        )
    ).limit(10).all()
    
    findings = db.query(models.Finding).filter(
        or_(
            models.Finding.title.ilike(query),
            models.Finding.category.ilike(query),
            models.Finding.severity.ilike(query),
            models.Finding.affected_url.ilike(query)
        )
    ).limit(15).all()
    
    reports = db.query(models.Report).join(models.Target).filter(
        or_(
            models.Report.title.ilike(query),
            models.Target.name.ilike(query)
        )
    ).limit(10).all()
    
    return schemas.SearchResults(
        targets=targets,
        scans=scans,
        findings=findings,
        reports=reports
    )
