import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.modules.api_security.authorization import schemas
from app.modules.api_security.authorization.matrix_engine import suggest_cell
from app.modules.api_security.authorization.review_rules import authorization_review_candidates
from app.modules.api_security.findings_engine import fingerprint
from app.modules.api_security.parsers.redaction import redact_data, redact_text


DISCLAIMER = "Suggestions are inferred from imported metadata. Analyst confirmation is required; runtime validation was not performed."


def _notify(db: Session, title: str, message: str, kind: str, assessment_id: int) -> None:
    db.add(models.Notification(title=title, message=message, type=kind, entity_type="api_assessment", entity_id=assessment_id))


def _assessment(db: Session, assessment_id: int):
    item = db.query(models.ApiAssessment).filter(models.ApiAssessment.id == assessment_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="API assessment not found.")
    return item


def _owned(db: Session, model, item_id: int, label: str):
    item = db.query(model).filter(model.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail=f"{label} not found.")
    return item


def _clean(value: str | None) -> str | None:
    return redact_text(value.strip()) if value and value.strip() else None


def list_roles(db: Session, assessment_id: int):
    _assessment(db, assessment_id)
    return db.query(models.ApiRole).filter(models.ApiRole.assessment_id == assessment_id).order_by(models.ApiRole.id).all()


def create_role(db: Session, assessment_id: int, payload: schemas.RoleCreate):
    _assessment(db, assessment_id)
    role = models.ApiRole(assessment_id=assessment_id, name=_clean(payload.name) or "Role", description=_clean(payload.description), privilege_level=payload.privilege_level)
    db.add(role)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A role with this name already exists in the assessment.") from exc
    db.refresh(role)
    return role


def update_role(db: Session, role_id: int, payload: schemas.RoleUpdate):
    role = _owned(db, models.ApiRole, role_id, "API role")
    values = payload.model_dump(exclude_unset=True)
    if "name" in values:
        role.name = _clean(values["name"]) or role.name
    if "description" in values:
        role.description = _clean(values["description"])
    if "privilege_level" in values:
        role.privilege_level = values["privilege_level"]
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A role with this name already exists in the assessment.") from exc
    db.refresh(role)
    return role


def delete_role(db: Session, role_id: int):
    role = _owned(db, models.ApiRole, role_id, "API role")
    db.delete(role)
    db.commit()


def _validate_role(db: Session, assessment_id: int, role_id: int | None):
    if role_id is None:
        return
    role = _owned(db, models.ApiRole, role_id, "API role")
    if role.assessment_id != assessment_id:
        raise HTTPException(status_code=400, detail="Role does not belong to this assessment.")


def list_identities(db: Session, assessment_id: int):
    _assessment(db, assessment_id)
    return db.query(models.ApiIdentity).filter(models.ApiIdentity.assessment_id == assessment_id).order_by(models.ApiIdentity.id).all()


def create_identity(db: Session, assessment_id: int, payload: schemas.IdentityCreate):
    _assessment(db, assessment_id)
    _validate_role(db, assessment_id, payload.role_id)
    item = models.ApiIdentity(assessment_id=assessment_id, label=_clean(payload.label) or "Identity", role_id=payload.role_id, identity_type=payload.identity_type, notes=_clean(payload.notes))
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def update_identity(db: Session, identity_id: int, payload: schemas.IdentityUpdate):
    item = _owned(db, models.ApiIdentity, identity_id, "API identity")
    values = payload.model_dump(exclude_unset=True)
    if "role_id" in values:
        _validate_role(db, item.assessment_id, values["role_id"])
    for field, value in values.items():
        if field == "label" and value:
            value = _clean(value) or item.label
        if field == "notes":
            value = _clean(value)
        setattr(item, field, value)
    db.commit()
    db.refresh(item)
    return item


def delete_identity(db: Session, identity_id: int):
    db.delete(_owned(db, models.ApiIdentity, identity_id, "API identity"))
    db.commit()


def _validate_matrix_refs(db: Session, assessment_id: int, endpoint_id: int, role_id: int):
    endpoint = _owned(db, models.ApiEndpoint, endpoint_id, "API endpoint")
    role = _owned(db, models.ApiRole, role_id, "API role")
    if endpoint.assessment_id != assessment_id or role.assessment_id != assessment_id:
        raise HTTPException(status_code=400, detail="Endpoint and role must belong to the requested assessment.")


def matrix_to_schema(item) -> dict[str, Any]:
    return {
        "id": item.id, "assessment_id": item.assessment_id, "endpoint_id": item.endpoint_id, "role_id": item.role_id,
        "expected_access": item.expected_access, "object_scope": item.object_scope,
        "expected_conditions": json.loads(item.expected_conditions_json) if item.expected_conditions_json else None,
        "analyst_notes": item.analyst_notes, "review_status": item.review_status,
        "created_at": item.created_at, "updated_at": item.updated_at,
    }


def list_matrix(db: Session, assessment_id: int):
    _assessment(db, assessment_id)
    rows = db.query(models.AuthorizationMatrixEntry).filter(models.AuthorizationMatrixEntry.assessment_id == assessment_id).order_by(models.AuthorizationMatrixEntry.endpoint_id, models.AuthorizationMatrixEntry.role_id).all()
    return [matrix_to_schema(item) for item in rows]


def create_matrix_entry(db: Session, assessment_id: int, payload: schemas.MatrixEntryCreate):
    _assessment(db, assessment_id)
    _validate_matrix_refs(db, assessment_id, payload.endpoint_id, payload.role_id)
    item = models.AuthorizationMatrixEntry(
        assessment_id=assessment_id, endpoint_id=payload.endpoint_id, role_id=payload.role_id,
        expected_access=payload.expected_access, object_scope=payload.object_scope,
        expected_conditions_json=json.dumps(redact_data(payload.expected_conditions), sort_keys=True) if payload.expected_conditions is not None else None,
        analyst_notes=_clean(payload.analyst_notes), review_status=payload.review_status,
    )
    db.add(item)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="This endpoint and role already have a matrix entry.") from exc
    db.refresh(item)
    return matrix_to_schema(item)


def update_matrix_entry(db: Session, entry_id: int, payload: schemas.MatrixEntryUpdate):
    item = _owned(db, models.AuthorizationMatrixEntry, entry_id, "Authorization matrix entry")
    values = payload.model_dump(exclude_unset=True)
    if "expected_conditions" in values:
        item.expected_conditions_json = json.dumps(redact_data(values.pop("expected_conditions")), sort_keys=True) if values["expected_conditions"] is not None else None
    if "analyst_notes" in values:
        values["analyst_notes"] = _clean(values["analyst_notes"])
    for field, value in values.items():
        setattr(item, field, value)
    db.commit()
    db.refresh(item)
    return matrix_to_schema(item)


def delete_matrix_entry(db: Session, entry_id: int):
    db.delete(_owned(db, models.AuthorizationMatrixEntry, entry_id, "Authorization matrix entry"))
    db.commit()


def review_to_schema(item) -> dict[str, Any]:
    return {
        "id": item.id, "assessment_id": item.assessment_id, "endpoint_id": item.endpoint_id,
        "matrix_entry_id": item.matrix_entry_id, "review_type": item.review_type,
        "expected_behavior": item.expected_behavior, "observed_metadata": item.observed_metadata,
        "risk_indicator": item.risk_indicator, "severity": item.severity, "confidence": item.confidence,
        "manual_validation_required": item.manual_validation_required, "analyst_decision": item.analyst_decision,
        "notes": item.notes, "validation_checklist": json.loads(item.validation_checklist_json or "[]"),
        "created_at": item.created_at, "updated_at": item.updated_at,
    }


def _upsert_review_finding(db: Session, review, confirmed: bool = False) -> None:
    source = f"{review.review_type}_review"
    title_prefix = "Analyst-confirmed" if confirmed else "Potential"
    title = f"{title_prefix} {review.review_type.replace('_', ' ').title()} Authorization Weakness"
    fp = fingerprint("authorization-review", review.id)
    existing = db.query(models.ApiFinding).filter(models.ApiFinding.assessment_id == review.assessment_id, models.ApiFinding.fingerprint == fp).first()
    values = {
        "assessment_id": review.assessment_id, "endpoint_id": review.endpoint_id, "title": title,
        "owasp_category": {"object_level": "API1:2023", "property_level": "API3:2023", "function_level": "API5:2023"}[review.review_type],
        "severity": "high" if review.severity == "high" else "medium", "confidence": "high" if confirmed else "medium",
        "description": review.risk_indicator,
        "evidence": ("Analyst accepted this review based on recorded evidence." if confirmed else "Strong metadata indicator; manual validation remains required. ") + " " + review.observed_metadata,
        "impact": "Insufficient authorization could expose objects, privileged functions, or sensitive properties beyond the intended role.",
        "remediation": review.expected_behavior + " Enforce authorization server-side and validate in an authorized environment.",
        "source": source, "fingerprint": fp,
    }
    if existing:
        for field, value in values.items():
            setattr(existing, field, value)
    else:
        db.add(models.ApiFinding(**values))


def generate_reviews(db: Session, assessment_id: int):
    assessment = _assessment(db, assessment_id)
    roles = list(assessment.api_roles)
    created_entries = 0
    for endpoint in assessment.endpoints:
        for role in roles:
            existing = db.query(models.AuthorizationMatrixEntry).filter_by(assessment_id=assessment_id, endpoint_id=endpoint.id, role_id=role.id).first()
            if existing:
                continue
            suggestion = suggest_cell(endpoint, role)
            db.add(models.AuthorizationMatrixEntry(
                assessment_id=assessment_id, endpoint_id=endpoint.id, role_id=role.id,
                expected_access=suggestion["expected_access"], object_scope=suggestion["object_scope"],
                expected_conditions_json=json.dumps(suggestion["expected_conditions"], sort_keys=True),
                review_status=suggestion["review_status"],
            ))
            created_entries += 1
    db.flush()

    created_reviews = 0
    high_risk_created = 0
    for candidate in authorization_review_candidates(assessment):
        existing = db.query(models.AuthorizationReview).filter_by(
            assessment_id=assessment_id, endpoint_id=candidate["endpoint_id"], review_type=candidate["review_type"]
        ).first()
        if existing:
            continue
        matrix_entry = db.query(models.AuthorizationMatrixEntry).filter_by(assessment_id=assessment_id, endpoint_id=candidate["endpoint_id"]).first()
        checklist = candidate.pop("validation_checklist")
        review = models.AuthorizationReview(
            **candidate, matrix_entry_id=matrix_entry.id if matrix_entry else None,
            validation_checklist_json=json.dumps(checklist, ensure_ascii=True),
        )
        db.add(review)
        db.flush()
        created_reviews += 1
        if review.severity == "high":
            high_risk_created += 1
            _upsert_review_finding(db, review, confirmed=False)

    _notify(db, "Authorization suggestions generated", f"Created {created_entries} suggested matrix entries and {created_reviews} passive review items. {DISCLAIMER}", "warning" if high_risk_created else "info", assessment_id)
    if high_risk_created:
        _notify(db, "High-risk authorization reviews require validation", f"{high_risk_created} high-risk metadata indicator(s) require analyst validation.", "warning", assessment_id)
    db.commit()
    return {"matrix_entries_created": created_entries, "reviews_created": created_reviews, "unresolved_high_risk_reviews": high_risk_created, "disclaimer": DISCLAIMER}


def list_reviews(db: Session, assessment_id: int):
    _assessment(db, assessment_id)
    rows = db.query(models.AuthorizationReview).filter(models.AuthorizationReview.assessment_id == assessment_id).order_by(models.AuthorizationReview.severity.desc(), models.AuthorizationReview.id).all()
    return [review_to_schema(item) for item in rows]


def update_review(db: Session, review_id: int, payload: schemas.AuthorizationReviewUpdate):
    item = _owned(db, models.AuthorizationReview, review_id, "Authorization review")
    old_decision = item.analyst_decision
    values = payload.model_dump(exclude_unset=True)
    if "notes" in values:
        values["notes"] = _clean(values["notes"])
    for field, value in values.items():
        setattr(item, field, value)
    if item.analyst_decision == "accepted":
        _upsert_review_finding(db, item, confirmed=True)
    if old_decision in {"open", "needs_testing"} and item.analyst_decision in {"accepted", "rejected"}:
        _notify(db, "Authorization review resolved", f"Review #{item.id} was marked {item.analyst_decision} by the analyst.", "success", item.assessment_id)
    db.commit()
    db.refresh(item)
    return review_to_schema(item)
