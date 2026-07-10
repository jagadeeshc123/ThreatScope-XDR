from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.api_security.authorization import schemas, service


router = APIRouter()


@router.get("/assessments/{assessment_id}/roles", response_model=List[schemas.RoleRead])
def list_roles(assessment_id: int, db: Session = Depends(get_db)):
    return service.list_roles(db, assessment_id)


@router.post("/assessments/{assessment_id}/roles", response_model=schemas.RoleRead)
def create_role(assessment_id: int, payload: schemas.RoleCreate, db: Session = Depends(get_db)):
    return service.create_role(db, assessment_id, payload)


@router.patch("/roles/{role_id}", response_model=schemas.RoleRead)
def update_role(role_id: int, payload: schemas.RoleUpdate, db: Session = Depends(get_db)):
    return service.update_role(db, role_id, payload)


@router.delete("/roles/{role_id}")
def delete_role(role_id: int, db: Session = Depends(get_db)):
    service.delete_role(db, role_id)
    return {"ok": True}


@router.get("/assessments/{assessment_id}/identities", response_model=List[schemas.IdentityRead])
def list_identities(assessment_id: int, db: Session = Depends(get_db)):
    return service.list_identities(db, assessment_id)


@router.post("/assessments/{assessment_id}/identities", response_model=schemas.IdentityRead)
def create_identity(assessment_id: int, payload: schemas.IdentityCreate, db: Session = Depends(get_db)):
    return service.create_identity(db, assessment_id, payload)


@router.patch("/identities/{identity_id}", response_model=schemas.IdentityRead)
def update_identity(identity_id: int, payload: schemas.IdentityUpdate, db: Session = Depends(get_db)):
    return service.update_identity(db, identity_id, payload)


@router.delete("/identities/{identity_id}")
def delete_identity(identity_id: int, db: Session = Depends(get_db)):
    service.delete_identity(db, identity_id)
    return {"ok": True}


@router.get("/assessments/{assessment_id}/authorization-matrix", response_model=List[schemas.MatrixEntryRead])
def list_matrix(assessment_id: int, db: Session = Depends(get_db)):
    return service.list_matrix(db, assessment_id)


@router.post("/assessments/{assessment_id}/authorization-matrix", response_model=schemas.MatrixEntryRead)
def create_matrix(assessment_id: int, payload: schemas.MatrixEntryCreate, db: Session = Depends(get_db)):
    return service.create_matrix_entry(db, assessment_id, payload)


@router.patch("/authorization-matrix/{entry_id}", response_model=schemas.MatrixEntryRead)
def update_matrix(entry_id: int, payload: schemas.MatrixEntryUpdate, db: Session = Depends(get_db)):
    return service.update_matrix_entry(db, entry_id, payload)


@router.delete("/authorization-matrix/{entry_id}")
def delete_matrix(entry_id: int, db: Session = Depends(get_db)):
    service.delete_matrix_entry(db, entry_id)
    return {"ok": True}


@router.post("/assessments/{assessment_id}/authorization-review/generate", response_model=schemas.AuthorizationGenerationResult)
def generate_authorization_review(assessment_id: int, db: Session = Depends(get_db)):
    return service.generate_reviews(db, assessment_id)


@router.get("/assessments/{assessment_id}/authorization-reviews", response_model=List[schemas.AuthorizationReviewRead])
def list_authorization_reviews(assessment_id: int, db: Session = Depends(get_db)):
    return service.list_reviews(db, assessment_id)


@router.patch("/authorization-reviews/{review_id}", response_model=schemas.AuthorizationReviewRead)
def update_authorization_review(review_id: int, payload: schemas.AuthorizationReviewUpdate, db: Session = Depends(get_db)):
    return service.update_review(db, review_id, payload)
