from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.api_security.business_flows import schemas, service


router = APIRouter()


@router.get("/assessments/{assessment_id}/business-flows", response_model=List[schemas.FlowRead])
def list_flows(assessment_id: int, db: Session = Depends(get_db)):
    return service.list_flows(db, assessment_id)


@router.post("/assessments/{assessment_id}/business-flows", response_model=schemas.FlowRead)
def create_flow(assessment_id: int, payload: schemas.FlowCreate, db: Session = Depends(get_db)):
    return service.create_flow(db, assessment_id, payload)


@router.get("/business-flows/{flow_id}", response_model=schemas.FlowRead)
def get_flow(flow_id: int, db: Session = Depends(get_db)):
    return service.get_flow(db, flow_id)


@router.patch("/business-flows/{flow_id}", response_model=schemas.FlowRead)
def update_flow(flow_id: int, payload: schemas.FlowUpdate, db: Session = Depends(get_db)):
    return service.update_flow(db, flow_id, payload)


@router.delete("/business-flows/{flow_id}")
def delete_flow(flow_id: int, db: Session = Depends(get_db)):
    service.delete_flow(db, flow_id)
    return {"ok": True}


@router.post("/business-flows/{flow_id}/steps", response_model=schemas.StepRead)
def create_step(flow_id: int, payload: schemas.StepCreate, db: Session = Depends(get_db)):
    return service.create_step(db, flow_id, payload)


@router.patch("/business-flow-steps/{step_id}", response_model=schemas.StepRead)
def update_step(step_id: int, payload: schemas.StepUpdate, db: Session = Depends(get_db)):
    return service.update_step(db, step_id, payload)


@router.delete("/business-flow-steps/{step_id}")
def delete_step(step_id: int, db: Session = Depends(get_db)):
    service.delete_step(db, step_id)
    return {"ok": True}


@router.post("/business-flows/{flow_id}/analyze", response_model=schemas.FlowAnalysisResult)
def analyze_flow(flow_id: int, db: Session = Depends(get_db)):
    return service.analyze_flow(db, flow_id)


@router.get("/business-flows/{flow_id}/risks", response_model=List[schemas.RiskRead])
def list_risks(flow_id: int, db: Session = Depends(get_db)):
    return service.list_risks(db, flow_id)


@router.patch("/business-flow-risks/{risk_id}", response_model=schemas.RiskRead)
def update_risk(risk_id: int, payload: schemas.RiskUpdate, db: Session = Depends(get_db)):
    return service.update_risk(db, risk_id, payload)
