import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.modules.api_security.business_flows import schemas
from app.modules.api_security.business_flows.risk_engine import analyze_flow_metadata, risk_score
from app.modules.api_security.findings_engine import fingerprint
from app.modules.api_security.parsers.redaction import redact_text


DISCLAIMER = "Passive design review only. Possible business-flow weaknesses require manual validation; runtime behavior was not tested."


def _clean(value: str | None) -> str | None:
    return redact_text(value.strip()) if value and value.strip() else None


def _notify(db: Session, title: str, message: str, kind: str, assessment_id: int) -> None:
    db.add(models.Notification(title=title, message=message, type=kind, entity_type="api_assessment", entity_id=assessment_id))


def _assessment(db: Session, assessment_id: int):
    item = db.query(models.ApiAssessment).filter(models.ApiAssessment.id == assessment_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="API assessment not found.")
    return item


def _flow(db: Session, flow_id: int):
    item = db.query(models.ApiBusinessFlow).filter(models.ApiBusinessFlow.id == flow_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="API business flow not found.")
    return item


def _step(db: Session, step_id: int):
    item = db.query(models.ApiBusinessFlowStep).filter(models.ApiBusinessFlowStep.id == step_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Business-flow step not found.")
    return item


def _risk(db: Session, risk_id: int):
    item = db.query(models.ApiBusinessFlowRisk).filter(models.ApiBusinessFlowRisk.id == risk_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Business-flow risk not found.")
    return item


def risk_to_schema(item) -> dict[str, Any]:
    return {field: getattr(item, field) for field in (
        "id", "flow_id", "step_id", "risk_type", "title", "severity", "confidence", "description",
        "evidence_summary", "remediation", "manual_validation_required", "status", "owasp_category", "created_at", "updated_at",
    )}


def step_to_schema(item) -> dict[str, Any]:
    return {field: getattr(item, field) for field in (
        "id", "flow_id", "step_order", "endpoint_id", "action_name", "expected_actor_role",
        "prerequisite_description", "expected_state_before", "expected_state_after", "sensitive_operation", "created_at", "updated_at",
    )}


def flow_to_schema(item, include_details: bool = True) -> dict[str, Any]:
    data = {
        "id": item.id, "assessment_id": item.assessment_id, "name": item.name, "description": item.description,
        "business_goal": item.business_goal, "actor_roles": json.loads(item.actor_roles_json or "[]"),
        "status": item.status, "risk_score": item.risk_score, "created_at": item.created_at, "updated_at": item.updated_at,
        "steps": [], "risks": [],
    }
    if include_details:
        data["steps"] = [step_to_schema(step) for step in sorted(item.steps, key=lambda row: row.step_order)]
        data["risks"] = [risk_to_schema(risk) for risk in item.risks]
    return data


def list_flows(db: Session, assessment_id: int):
    _assessment(db, assessment_id)
    return [flow_to_schema(item) for item in db.query(models.ApiBusinessFlow).filter(models.ApiBusinessFlow.assessment_id == assessment_id).order_by(models.ApiBusinessFlow.updated_at.desc()).all()]


def create_flow(db: Session, assessment_id: int, payload: schemas.FlowCreate):
    _assessment(db, assessment_id)
    item = models.ApiBusinessFlow(
        assessment_id=assessment_id, name=_clean(payload.name) or "Business flow", description=_clean(payload.description) or "",
        business_goal=_clean(payload.business_goal), actor_roles_json=json.dumps([redact_text(role.strip()) for role in payload.actor_roles if role.strip()]),
        status=payload.status,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return flow_to_schema(item)


def get_flow(db: Session, flow_id: int):
    return flow_to_schema(_flow(db, flow_id))


def update_flow(db: Session, flow_id: int, payload: schemas.FlowUpdate):
    item = _flow(db, flow_id)
    values = payload.model_dump(exclude_unset=True)
    if "actor_roles" in values:
        item.actor_roles_json = json.dumps([redact_text(role.strip()) for role in values.pop("actor_roles") if role.strip()])
    for field, value in values.items():
        if field in {"name", "description", "business_goal"}:
            value = _clean(value)
        setattr(item, field, value)
    db.commit()
    db.refresh(item)
    return flow_to_schema(item)


def delete_flow(db: Session, flow_id: int):
    db.delete(_flow(db, flow_id))
    db.commit()


def _validate_endpoint(db: Session, assessment_id: int, endpoint_id: int | None):
    if endpoint_id is None:
        return
    endpoint = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="API endpoint not found.")
    if endpoint.assessment_id != assessment_id:
        raise HTTPException(status_code=400, detail="Endpoint does not belong to the flow assessment.")


def create_step(db: Session, flow_id: int, payload: schemas.StepCreate):
    flow = _flow(db, flow_id)
    _validate_endpoint(db, flow.assessment_id, payload.endpoint_id)
    values = payload.model_dump()
    for field in ("action_name", "expected_actor_role", "prerequisite_description", "expected_state_before", "expected_state_after"):
        values[field] = _clean(values[field])
    item = models.ApiBusinessFlowStep(flow_id=flow_id, **values)
    db.add(item)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A step with this order already exists in the flow.") from exc
    db.refresh(item)
    return step_to_schema(item)


def update_step(db: Session, step_id: int, payload: schemas.StepUpdate):
    item = _step(db, step_id)
    values = payload.model_dump(exclude_unset=True)
    if "endpoint_id" in values:
        _validate_endpoint(db, item.flow.assessment_id, values["endpoint_id"])
    for field, value in values.items():
        if field in {"action_name", "expected_actor_role", "prerequisite_description", "expected_state_before", "expected_state_after"}:
            value = _clean(value)
        setattr(item, field, value)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A step with this order already exists in the flow.") from exc
    db.refresh(item)
    return step_to_schema(item)


def delete_step(db: Session, step_id: int):
    db.delete(_step(db, step_id))
    db.commit()


def _upsert_flow_finding(db: Session, flow, risk, confirmed: bool = False):
    fp = fingerprint("business-flow-risk", risk.id)
    existing = db.query(models.ApiFinding).filter(models.ApiFinding.assessment_id == flow.assessment_id, models.ApiFinding.fingerprint == fp).first()
    values = {
        "assessment_id": flow.assessment_id,
        "endpoint_id": risk.step.endpoint_id if risk.step else None,
        "title": ("Analyst-accepted" if confirmed else "Potential") + f" Business Flow Risk: {risk.title}",
        "owasp_category": risk.owasp_category,
        "severity": "high" if risk.severity == "high" else "medium",
        "confidence": "high" if confirmed else risk.confidence,
        "description": risk.description,
        "evidence": ("Analyst accepted this indicator. " if confirmed else "Metadata-derived indicator; manual validation is pending. ") + risk.evidence_summary,
        "impact": "A workflow control gap could allow actions or data access outside the intended sequence, role, or object scope.",
        "remediation": risk.remediation,
        "source": "business_flow",
        "fingerprint": fp,
    }
    if existing:
        for field, value in values.items():
            setattr(existing, field, value)
    else:
        db.add(models.ApiFinding(**values))


def analyze_flow(db: Session, flow_id: int):
    flow = _flow(db, flow_id)
    candidates = analyze_flow_metadata(flow)
    created = 0
    for candidate in candidates:
        existing = db.query(models.ApiBusinessFlowRisk).filter_by(flow_id=flow.id, fingerprint=candidate["fingerprint"]).first()
        if existing:
            continue
        risk = models.ApiBusinessFlowRisk(**candidate)
        db.add(risk)
        db.flush()
        created += 1
        if risk.severity == "high":
            _upsert_flow_finding(db, flow, risk, confirmed=False)
    all_risks = db.query(models.ApiBusinessFlowRisk).filter(models.ApiBusinessFlowRisk.flow_id == flow.id).all()
    flow.risk_score = risk_score([{"severity": item.severity} for item in all_risks if item.status != "resolved"])
    high = sum(1 for item in all_risks if item.severity == "high" and item.status == "open")
    _notify(db, "Business flow analysis completed", f"Passive review of '{flow.name}' produced {len(all_risks)} indicator(s). {DISCLAIMER}", "warning" if high else "info", flow.assessment_id)
    db.commit()
    return {"flow_id": flow.id, "risks_created": created, "risks_total": len(all_risks), "high_risk_indicators": high, "risk_score": flow.risk_score, "disclaimer": DISCLAIMER}


def list_risks(db: Session, flow_id: int):
    _flow(db, flow_id)
    return [risk_to_schema(item) for item in db.query(models.ApiBusinessFlowRisk).filter(models.ApiBusinessFlowRisk.flow_id == flow_id).order_by(models.ApiBusinessFlowRisk.severity.desc(), models.ApiBusinessFlowRisk.id).all()]


def update_risk(db: Session, risk_id: int, payload: schemas.RiskUpdate):
    item = _risk(db, risk_id)
    previous = item.status
    item.status = payload.status
    if payload.status == "accepted":
        _upsert_flow_finding(db, item.flow, item, confirmed=True)
    active_risks = [risk for risk in item.flow.risks if risk.status != "resolved"]
    item.flow.risk_score = risk_score([{"severity": risk.severity} for risk in active_risks])
    if previous == "open" and payload.status == "resolved":
        _notify(db, "Business flow risk resolved", f"Flow risk #{item.id} was marked resolved.", "success", item.flow.assessment_id)
    db.commit()
    db.refresh(item)
    return risk_to_schema(item)
