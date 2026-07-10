from typing import List, Optional

from fastapi import APIRouter, Depends, File, Query, UploadFile
from sqlalchemy.orm import Session

from app.modules.api_security import schemas, service
from app.modules.api_security.validators import OPENAPI_EXTENSIONS, POSTMAN_EXTENSIONS, read_validated_upload
from app.database import get_db
from app import models


router = APIRouter()


@router.get("/overview", response_model=schemas.ApiSecurityOverview)
def get_api_security_overview(db: Session = Depends(get_db)):
    return service.overview(db)


@router.get("/assessments", response_model=List[schemas.ApiAssessmentRead])
def list_assessments(db: Session = Depends(get_db)):
    return db.query(models.ApiAssessment).order_by(models.ApiAssessment.created_at.desc()).all()


@router.post("/assessments", response_model=schemas.ApiAssessmentRead)
def create_assessment(payload: schemas.ApiAssessmentCreate, db: Session = Depends(get_db)):
    return service.create_assessment(db, payload)


@router.get("/assessments/{assessment_id}", response_model=schemas.ApiAssessmentDetail)
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    return service.assessment_detail(service.get_assessment_or_404(db, assessment_id))


@router.delete("/assessments/{assessment_id}")
def delete_assessment(assessment_id: int, db: Session = Depends(get_db)):
    service.delete_assessment(db, assessment_id)
    return {"ok": True}


@router.post("/assessments/{assessment_id}/import/openapi", response_model=schemas.ApiImportResult)
async def import_openapi(assessment_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename, content = await read_validated_upload(file, OPENAPI_EXTENSIONS, "OpenAPI")
    return service.import_definition(db, assessment_id, "openapi", filename, content)


@router.post("/assessments/{assessment_id}/import/postman", response_model=schemas.ApiImportResult)
async def import_postman(assessment_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename, content = await read_validated_upload(file, POSTMAN_EXTENSIONS, "Postman")
    return service.import_definition(db, assessment_id, "postman", filename, content)


@router.get("/assessments/{assessment_id}/endpoints", response_model=List[schemas.ApiEndpointRead])
def list_endpoints(
    assessment_id: int,
    method: Optional[str] = None,
    auth: Optional[str] = Query(default=None, pattern="^(authenticated|unauthenticated)$"),
    deprecated: Optional[bool] = None,
    risk: Optional[str] = Query(default=None, pattern="^(info|low|medium|high)$"),
    tag: Optional[str] = None,
    q: Optional[str] = None,
    sort: str = Query(default="path", pattern="^(method|path|authentication|risk)$"),
    db: Session = Depends(get_db),
):
    return service.list_endpoints(db, assessment_id, method, auth, deprecated, risk, tag, q, sort)


@router.get("/assessments/{assessment_id}/summary", response_model=schemas.ApiSecuritySummary)
def get_summary(assessment_id: int, db: Session = Depends(get_db)):
    return service.summary(db, assessment_id)

