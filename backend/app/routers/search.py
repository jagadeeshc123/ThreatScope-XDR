from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app import schemas, models
from app.database import get_db
from app.modules.api_security.service import endpoint_to_schema

router = APIRouter()

@router.get("/", response_model=schemas.SearchResults)
def search(q: str = "", db: Session = Depends(get_db)):
    if not q or len(q) < 2:
        return schemas.SearchResults(targets=[], scans=[], findings=[], reports=[], api_assessments=[], api_endpoints=[])
        
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

    api_assessments = db.query(models.ApiAssessment).filter(
        or_(
            models.ApiAssessment.name.ilike(query),
            models.ApiAssessment.description.ilike(query),
            models.ApiAssessment.source_filename.ilike(query),
            models.ApiAssessment.base_url.ilike(query),
        )
    ).limit(10).all()

    api_endpoints = db.query(models.ApiEndpoint).filter(
        or_(
            models.ApiEndpoint.path.ilike(query),
            models.ApiEndpoint.method.ilike(query),
            models.ApiEndpoint.summary.ilike(query),
            models.ApiEndpoint.operation_id.ilike(query),
            models.ApiEndpoint.tags_json.ilike(query),
        )
    ).limit(15).all()
    
    return schemas.SearchResults(
        targets=targets,
        scans=scans,
        findings=findings,
        reports=reports,
        api_assessments=[{
            "id": item.id,
            "name": item.name,
            "status": item.status,
            "source_type": item.source_type,
            "endpoint_count": item.endpoint_count,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in api_assessments],
        api_endpoints=[endpoint_to_schema(item) for item in api_endpoints],
    )
