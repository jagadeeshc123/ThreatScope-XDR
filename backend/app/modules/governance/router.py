import hashlib,json
from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app import models
from app.database import get_db
from . import framework_service,risk_service,mapping_engine,coverage_service,evidence_service,report_service,snapshot_service,exception_service,review_service
from .overview_service import overview
from .redaction import redact
from .schemas import ManualRiskCreate
from .scoring import bounded,calculate
from .service import DISCLAIMER,activity,dump,get_or_404,key,notify_once

router=APIRouter()
RISK_STATUSES={"identified","under_review","treatment_planned","treatment_in_progress","accepted","mitigated","monitoring","closed"};RISK_STRATEGIES={"unset","mitigate","accept","avoid","transfer","monitor"};CONFIDENCES={"low","medium","high"};MAPPING_STATUSES={"candidate","confirmed","rejected","not_applicable"};TREATMENT_STRATEGIES={"mitigate","avoid","transfer","monitor"};TREATMENT_STATUSES={"planned","in_progress","completed","cancelled"};PRIORITIES={"low","medium","high","critical"};EXCEPTION_STATUSES={"requested","approved","rejected","expired","revoked"};PACKAGE_STATUSES={"draft","ready_for_review","reviewed","archived"};REVIEW_TYPES={"executive","risk_register","control_coverage","evidence_readiness","periodic"};REVIEW_STATUSES={"planned","in_progress","awaiting_approval","completed","cancelled"};SOURCE_MODULES={"web_exposure","api_security","soc_monitor","document_threat","phishing_defense","unified_correlation","incident_case"};SOURCE_SEVERITIES={"info","low","medium","high","critical"}


def utc(value):return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value
def parse_date(value,label):
    if value is None or value=="":return None
    if isinstance(value,datetime):return value
    try:return datetime.fromisoformat(str(value).replace("Z","+00:00"))
    except ValueError:raise HTTPException(422,f"{label} must be a valid ISO timestamp")
def valid_range(start,end,label):
    if start and end and utc(start)>utc(end):raise HTTPException(422,f"Invalid {label} range")
def risk_or_404(db,risk_id):return get_or_404(db,models.GovernanceRisk,risk_id,"Governance risk")
def choice(value,allowed,label):
    if value not in allowed:raise HTTPException(422,f"Unsupported {label}")
    return value
def strict_bool(value,label):
    if not isinstance(value,bool):raise HTTPException(422,f"{label} must be a boolean")
    return value


@router.get("/overview")
def get_overview(db:Session=Depends(get_db)):return overview(db)|{"disclaimer":DISCLAIMER}


@router.post("/frameworks/seed")
def seed_frameworks(db:Session=Depends(get_db)):return framework_service.seed(db)
@router.get("/frameworks")
def frameworks(enabled:bool|None=None,db:Session=Depends(get_db)):
    query=db.query(models.GovernanceFramework)
    if enabled is not None:query=query.filter_by(enabled=enabled)
    return [dump(x) for x in query.order_by(models.GovernanceFramework.name)]
@router.get("/frameworks/{framework_id}")
def framework(framework_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceFramework,framework_id,"Framework");return dump(x)|{"controls":[dump(c) for c in x.controls],"coverage":coverage_service.framework_coverage(db,x)}
@router.patch("/frameworks/{framework_id}")
def update_framework(framework_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceFramework,framework_id,"Framework")
    if "enabled" in payload:x.enabled=strict_bool(payload["enabled"],"enabled")
    db.commit();return dump(x)
@router.delete("/frameworks/{framework_id}")
def delete_framework(framework_id:int,db:Session=Depends(get_db)):raise HTTPException(422,"System framework catalogs cannot be deleted; disable the framework instead")
@router.get("/frameworks/{framework_id}/controls")
def controls(framework_id:int,control_type:str|None=None,enabled:bool|None=None,db:Session=Depends(get_db)):
    get_or_404(db,models.GovernanceFramework,framework_id,"Framework");query=db.query(models.GovernanceControl).filter_by(framework_id=framework_id)
    if control_type:query=query.filter_by(control_type=control_type)
    if enabled is not None:query=query.filter_by(enabled=enabled)
    return [dump(x) for x in query.order_by(models.GovernanceControl.sort_order)]
@router.get("/controls/{control_id}")
def control(control_id:int,db:Session=Depends(get_db)):return dump(get_or_404(db,models.GovernanceControl,control_id,"Control"))
@router.patch("/controls/{control_id}")
def update_control(control_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceControl,control_id,"Control")
    if "enabled" in payload:x.enabled=strict_bool(payload["enabled"],"enabled")
    db.commit();return dump(x)
@router.get("/controls/{control_id}/coverage")
def control_coverage(control_id:int,db:Session=Depends(get_db)):return coverage_service.control_coverage(db,get_or_404(db,models.GovernanceControl,control_id,"Control"))
@router.get("/frameworks/{framework_id}/coverage")
def framework_coverage(framework_id:int,db:Session=Depends(get_db)):return coverage_service.framework_coverage(db,get_or_404(db,models.GovernanceFramework,framework_id,"Framework"))
@router.get("/coverage/summary")
def coverage_summary(db:Session=Depends(get_db)):return coverage_service.summary(db)


@router.post("/risks/sync")
def sync_risks(source_module:str|None=None,minimum_source_severity:str="info",since:datetime|None=None,maximum_records_per_module:int=Query(500,ge=1,le=1000),include_existing_closed_source_records:bool=False,db:Session=Depends(get_db)):
    if source_module is not None:choice(source_module,SOURCE_MODULES,"source module")
    choice(minimum_source_severity,SOURCE_SEVERITIES,"source severity")
    return risk_service.synchronize(db,source_module,minimum_source_severity,since,maximum_records_per_module,include_existing_closed_source_records)
@router.get("/risks")
def risks(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=200),category:str|None=None,origin:str|None=None,status:str|None=None,strategy:str|None=None,severity:str|None=None,confidence:str|None=None,appetite_status:str|None=None,owner:str|None=None,min_inherent_score:float|None=Query(None,ge=0,le=100),min_residual_score:float|None=Query(None,ge=0,le=100),due_from:datetime|None=None,due_to:datetime|None=None,next_review_from:datetime|None=None,next_review_to:datetime|None=None,source_module:str|None=None,framework:str|None=None,q:str|None=Query(None,max_length=200),db:Session=Depends(get_db)):
    valid_range(due_from,due_to,"due date");valid_range(next_review_from,next_review_to,"next review");query=db.query(models.GovernanceRisk)
    for field,value in [("category",category),("origin",origin),("status",status),("treatment_strategy",strategy),("severity",severity),("confidence",confidence),("appetite_status",appetite_status)]:
        if value:query=query.filter(getattr(models.GovernanceRisk,field)==value)
    if owner:query=query.filter(models.GovernanceRisk.owner_name.ilike(f"%{owner}%"))
    if min_inherent_score is not None:query=query.filter(models.GovernanceRisk.inherent_score>=min_inherent_score)
    if min_residual_score is not None:query=query.filter(models.GovernanceRisk.residual_score>=min_residual_score)
    if due_from:query=query.filter(models.GovernanceRisk.due_at>=due_from)
    if due_to:query=query.filter(models.GovernanceRisk.due_at<=due_to)
    if next_review_from:query=query.filter(models.GovernanceRisk.next_review_at>=next_review_from)
    if next_review_to:query=query.filter(models.GovernanceRisk.next_review_at<=next_review_to)
    if source_module:query=query.filter(models.GovernanceRisk.sources.any(models.GovernanceRiskSource.source_module==source_module))
    if framework:query=query.filter(models.GovernanceRisk.mappings.any(models.GovernanceControlMapping.control.has(models.GovernanceControl.framework.has(models.GovernanceFramework.framework_key==framework))))
    if q:query=query.filter(or_(models.GovernanceRisk.title.ilike(f"%{q}%"),models.GovernanceRisk.description.ilike(f"%{q}%"),models.GovernanceRisk.risk_key.ilike(f"%{q}%")))
    total=query.count();items=query.order_by(models.GovernanceRisk.residual_score.desc(),models.GovernanceRisk.updated_at.desc()).offset((page-1)*page_size).limit(page_size).all();return {"items":[dump(x) for x in items],"total":total,"page":page,"page_size":page_size}
@router.post("/risks")
def create_risk(payload:ManualRiskCreate,db:Session=Depends(get_db)):
    values=calculate(payload.likelihood,payload.impact,payload.residual_likelihood,payload.residual_impact);risk=models.GovernanceRisk(risk_key=key("RISK",datetime.now(timezone.utc).isoformat()+payload.title),title=redact(payload.title,300),description=redact(payload.description,4000),origin="analyst_created",category=payload.category,owner_name=redact(payload.owner_name,200),confidence=payload.confidence,due_at=payload.due_at,next_review_at=payload.next_review_at,**values);db.add(risk);db.flush();activity(db,"governance_risk_created",f"Created manual governance risk {risk.risk_key}.",risk.id);db.commit();db.refresh(risk);return dump(risk)
@router.get("/risks/{risk_id}")
def risk_detail(risk_id:int,db:Session=Depends(get_db)):
    x=risk_or_404(db,risk_id);return dump(x)|{"sources":[dump(y) for y in x.sources],"mappings":[dump(y)|{"control":dump(y.control)} for y in x.mappings],"treatments":[dump(y) for y in x.treatments],"exceptions":[dump(y) for y in x.exceptions],"evidence_packages":[dump(p) for p in db.query(models.GovernanceEvidencePackage).filter(models.GovernanceEvidencePackage.items.any(models.GovernanceEvidenceItem.risk_id==x.id))]}
@router.get("/risks/{risk_id}/sources")
def risk_sources(risk_id:int,db:Session=Depends(get_db)):return [dump(x) for x in risk_or_404(db,risk_id).sources]
@router.patch("/risks/{risk_id}")
def update_risk(risk_id:int,payload:dict,db:Session=Depends(get_db)):
    x=risk_or_404(db,risk_id);old_status=x.status;score_fields={"likelihood","impact","residual_likelihood","residual_impact"}
    if "status" in payload:choice(payload["status"],RISK_STATUSES,"risk status")
    if "treatment_strategy" in payload:choice(payload["treatment_strategy"],RISK_STRATEGIES,"treatment strategy")
    if "confidence" in payload:choice(payload["confidence"],CONFIDENCES,"confidence")
    for field in ("title","description"):
        if field in payload and not (redact(payload[field],4000) or "").strip():raise HTTPException(422,f"Risk {field} is required")
    if score_fields.intersection(payload) and not redact(payload.get("adjustment_rationale"),500):raise HTTPException(422,"A bounded adjustment rationale is required for score changes")
    new_status=payload.get("status",x.status)
    if new_status=="accepted":
        justification=redact(payload.get("acceptance_justification"),2000);supporting=next((e for e in x.exceptions if exception_service.is_active(e)),None)
        if not justification and not supporting:raise HTTPException(422,"Risk acceptance requires justification or an approved unexpired exception")
        x.acceptance_justification=justification or f"Supported by approved exception {supporting.exception_key}."
    if new_status=="closed" and not redact(payload.get("resolution_summary",x.resolution_summary),2000):raise HTTPException(422,"Risk closure requires a resolution summary")
    for field in ("title","description","owner_name","status","treatment_strategy","confidence","due_at","next_review_at","analyst_notes","resolution_summary"):
        if field in payload:setattr(x,field,redact(payload[field],4000) if field in {"title","description","owner_name","analyst_notes","resolution_summary"} else parse_date(payload[field],field) if field in {"due_at","next_review_at"} else payload[field])
    if score_fields.intersection(payload):
        values=calculate(payload.get("likelihood",x.likelihood),payload.get("impact",x.impact),payload.get("residual_likelihood",x.residual_likelihood),payload.get("residual_impact",x.residual_impact));[setattr(x,k,v) for k,v in values.items()];x.analyst_notes=redact(((x.analyst_notes or "")+" Score adjustment: "+payload["adjustment_rationale"]),4000)
    if x.status=="closed":x.closed_at=datetime.now(timezone.utc)
    elif old_status=="closed" and x.status!="closed":x.closed_at=None;notify_once(db,"Governance Risk Reopened",x.risk_key,"warning","governance_risk",x.id)
    activity(db,"governance_risk_accepted" if x.status=="accepted" else "governance_risk_closed" if x.status=="closed" else "governance_risk_updated",f"Updated governance risk {x.risk_key}.",x.id);db.commit();return dump(x)
@router.delete("/risks/{risk_id}")
def delete_risk(risk_id:int,db:Session=Depends(get_db)):
    x=risk_or_404(db,risk_id);risk_key=x.risk_key;db.delete(x);activity(db,"governance_record_deleted",f"Deleted governance-owned risk {risk_key}; source records were preserved.");db.commit();return {"ok":True,"source_records_deleted":0}


@router.post("/mappings/generate")
def generate_mappings(payload:dict|None=None,db:Session=Depends(get_db)):
    payload=payload or {}
    for field in ("risk_ids","source_modules","framework_keys"):
        if field in payload and not isinstance(payload[field],list):raise HTTPException(422,f"{field} must be a list")
    if any(not isinstance(x,int) for x in payload.get("risk_ids",[])):raise HTTPException(422,"risk_ids must contain integers")
    if any(x not in SOURCE_MODULES for x in payload.get("source_modules",[])):raise HTTPException(422,"Unsupported source module")
    choice(payload.get("minimum_confidence","low"),CONFIDENCES,"minimum confidence")
    return mapping_engine.generate(db,payload.get("risk_ids"),payload.get("source_modules"),payload.get("framework_keys"),payload.get("minimum_confidence","low"))
@router.get("/mappings")
def mappings(page:int=Query(1,ge=1),page_size:int=Query(100,ge=1,le=200),status:str|None=None,framework_key:str|None=None,confidence:str|None=None,source_module:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.GovernanceControlMapping)
    if status:query=query.filter_by(mapping_status=status)
    if confidence:query=query.filter_by(confidence=confidence)
    if source_module:query=query.filter_by(source_module=source_module)
    if framework_key:query=query.join(models.GovernanceControl).join(models.GovernanceFramework).filter(models.GovernanceFramework.framework_key==framework_key)
    total=query.count();items=query.order_by(models.GovernanceControlMapping.created_at.desc()).offset((page-1)*page_size).limit(page_size).all();return {"items":[dump(x)|{"control":dump(x.control),"framework":dump(x.control.framework),"risk":dump(x.risk)} for x in items],"total":total,"page":page,"page_size":page_size}
@router.get("/mappings/{mapping_id}")
def mapping(mapping_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceControlMapping,mapping_id,"Mapping");return dump(x)|{"control":dump(x.control),"risk":dump(x.risk)}
@router.patch("/mappings/{mapping_id}")
def update_mapping(mapping_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceControlMapping,mapping_id,"Mapping");status=payload.get("mapping_status",x.mapping_status)
    choice(status,MAPPING_STATUSES,"mapping status")
    if "confidence" in payload:choice(payload["confidence"],CONFIDENCES,"mapping confidence")
    if status=="not_applicable" and not redact(payload.get("analyst_notes"),1000):raise HTTPException(422,"Not-applicable mappings require an analyst reason")
    for field in ("mapping_status","confidence","analyst_notes","rationale"):
        if field in payload:setattr(x,field,redact(payload[field],2000))
    if status in {"confirmed","rejected","not_applicable"}:x.reviewed_at=datetime.now(timezone.utc)
    activity(db,"governance_mapping_reviewed",f"Mapping {x.id} marked {status}.",x.risk_id);db.commit();return dump(x)
@router.delete("/mappings/{mapping_id}")
def delete_mapping(mapping_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceControlMapping,mapping_id,"Mapping")
    if x.mapping_status!="candidate" or x.reviewed_at:raise HTTPException(422,"Reviewed mappings are retained for audit history")
    db.delete(x);db.commit();return {"ok":True}


@router.get("/treatments")
def all_treatments(status:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.RiskTreatmentPlan)
    if status:query=query.filter_by(status=status)
    return [dump(x)|{"risk":dump(x.risk)} for x in query.order_by(models.RiskTreatmentPlan.updated_at.desc())]
@router.get("/risks/{risk_id}/treatments")
def treatments(risk_id:int,db:Session=Depends(get_db)):return [dump(x) for x in risk_or_404(db,risk_id).treatments]
@router.post("/risks/{risk_id}/treatments")
def create_treatment(risk_id:int,payload:dict,db:Session=Depends(get_db)):
    risk=risk_or_404(db,risk_id)
    choice(payload.get("strategy"),TREATMENT_STRATEGIES,"treatment strategy");choice(payload.get("priority","medium"),PRIORITIES,"treatment priority")
    if not (redact(payload.get("title"),300) or "").strip():raise HTTPException(422,"Treatment title is required")
    for field in ("expected_residual_likelihood","expected_residual_impact"):
        if payload.get(field) is not None:payload[field]=bounded(payload[field],field)
    target=payload.get("target_date");item=models.RiskTreatmentPlan(risk_id=risk.id,title=redact(payload.get("title"),300),description=redact(payload.get("description",""),3000),strategy=payload["strategy"],owner_name=redact(payload.get("owner_name"),200),priority=payload.get("priority","medium"),target_date=parse_date(target,"target_date"),expected_residual_likelihood=payload.get("expected_residual_likelihood"),expected_residual_impact=payload.get("expected_residual_impact"));db.add(item);db.flush();activity(db,"governance_treatment_created",f"Created workflow-only treatment {item.id}; no remediation executed.",risk.id);db.commit();return dump(item)
@router.patch("/risks/{risk_id}/treatments/{treatment_id}")
def update_treatment(risk_id:int,treatment_id:int,payload:dict,db:Session=Depends(get_db)):
    risk=risk_or_404(db,risk_id);item=db.query(models.RiskTreatmentPlan).filter_by(id=treatment_id,risk_id=risk.id).first()
    if not item:raise HTTPException(404,"Treatment not found")
    if "status" in payload:choice(payload["status"],TREATMENT_STATUSES,"treatment status")
    if "strategy" in payload:choice(payload["strategy"],TREATMENT_STRATEGIES,"treatment strategy")
    if "priority" in payload:choice(payload["priority"],PRIORITIES,"treatment priority")
    if "title" in payload and not (redact(payload["title"],300) or "").strip():raise HTTPException(422,"Treatment title is required")
    for field in ("expected_residual_likelihood","expected_residual_impact"):
        if payload.get(field) is not None:payload[field]=bounded(payload[field],field)
    if payload.get("status")=="completed" and not redact(payload.get("completion_summary",item.completion_summary),2000):raise HTTPException(422,"Treatment completion requires a completion summary")
    for field in ("title","description","strategy","status","owner_name","priority","target_date","expected_residual_likelihood","expected_residual_impact","completion_summary"):
        if field in payload:setattr(item,field,parse_date(payload[field],"target_date") if field=="target_date" else redact(payload[field],3000) if field in {"title","description","owner_name","completion_summary"} else payload[field])
    item.completed_at=datetime.now(timezone.utc) if item.status=="completed" else None
    activity(db,"governance_treatment_updated",f"Treatment {item.id} updated to {item.status}; no technical action executed.",risk.id);db.commit();return dump(item)
@router.delete("/risks/{risk_id}/treatments/{treatment_id}")
def delete_treatment(risk_id:int,treatment_id:int,db:Session=Depends(get_db)):
    risk_or_404(db,risk_id);item=db.query(models.RiskTreatmentPlan).filter_by(id=treatment_id,risk_id=risk_id).first()
    if not item:raise HTTPException(404,"Treatment not found")
    db.delete(item);db.commit();return {"ok":True}


@router.get("/exceptions")
def exceptions(status:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.RiskException)
    if status:query=query.filter_by(status=status)
    return [dump(x)|{"risk":dump(x.risk)} for x in query.order_by(models.RiskException.updated_at.desc())]
@router.post("/risks/{risk_id}/exceptions")
def request_exception(risk_id:int,payload:dict,db:Session=Depends(get_db)):
    risk=risk_or_404(db,risk_id);justification=redact(payload.get("justification"),3000)
    if not justification or not justification.strip():raise HTTPException(422,"Exception justification is required")
    item=models.RiskException(risk_id=risk.id,exception_key=key("EXC",datetime.now(timezone.utc).isoformat()+risk.risk_key),justification=justification,review_notes=redact(payload.get("review_notes"),2000));db.add(item);db.flush();activity(db,"governance_exception_requested",f"Requested {item.exception_key}.",risk.id);db.commit();return dump(item)
@router.get("/exceptions/{exception_id}")
def exception(exception_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.RiskException,exception_id,"Exception");return dump(x)|{"risk":dump(x.risk)}
@router.patch("/exceptions/{exception_id}")
def update_exception(exception_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.RiskException,exception_id,"Exception");status=payload.get("status",x.status);expires=payload.get("expires_at")
    choice(status,EXCEPTION_STATUSES,"exception status")
    if status=="approved":
        approver=redact(payload.get("approver_name",x.approver_name),200);expiration=parse_date(expires,"expires_at") if expires is not None else x.expires_at
        if not approver:raise HTTPException(422,"Exception approval requires an approver")
        if not x.justification:raise HTTPException(422,"Exception approval requires justification")
        if not expiration or utc(expiration)<=datetime.now(timezone.utc):raise HTTPException(422,"Approved exceptions require a future expiration")
        x.approver_name=approver;x.expires_at=expiration;x.approved_at=datetime.now(timezone.utc);notify_once(db,"Governance Exception Approved",x.exception_key,"info","governance_exception",x.id)
    if status=="revoked":x.revoked_at=datetime.now(timezone.utc)
    for field in ("status","review_notes","approver_name"):
        if field in payload:setattr(x,field,redact(payload[field],2000))
    x.status=status;activity(db,f"governance_exception_{status}",f"Exception {x.exception_key} marked {status}.",x.risk_id);db.commit();return dump(x)
@router.post("/exceptions/check-expired")
def check_expired_exceptions(db:Session=Depends(get_db)):
    checked=datetime.now(timezone.utc);items=db.query(models.RiskException).filter_by(status="approved").all();expired=created=reused=nearing=0;errors=[]
    for item in items:
        try:
            if item.expires_at and checked<utc(item.expires_at)<=checked+timedelta(days=30):
                nearing+=1;made=notify_once(db,"Governance Exception Nearing Expiration",f"{item.exception_key} expires {utc(item.expires_at).date()}; governance review required.","warning","governance_exception",item.id);created+=int(made);reused+=int(not made);continue
            if not item.expires_at or utc(item.expires_at)>checked:continue
            item.status="expired";expired+=1;message=f"{item.exception_key} expired; governance review required for {item.risk.risk_key}.";made=notify_once(db,"Governance Exception Expired",message,"warning","governance_exception",item.id);created+=int(made);reused+=int(not made);activity(db,"governance_exception_expired",message,item.risk_id)
        except Exception as exc:errors.append(redact(exc,200))
    db.commit();return {"exceptions_examined":len(items),"newly_expired":expired,"nearing_expiration":nearing,"notifications_created":created,"notifications_reused":reused,"errors":errors,"checked_at":checked}


@router.post("/checks/overdue")
def check_overdue_governance(db:Session=Depends(get_db)):
    checked=datetime.now(timezone.utc);created=reused=0;errors=[];risk_count=treatment_count=0
    risks=db.query(models.GovernanceRisk).filter(models.GovernanceRisk.status!="closed",models.GovernanceRisk.due_at.is_not(None)).all();treatments=db.query(models.RiskTreatmentPlan).filter(models.RiskTreatmentPlan.status.in_(["planned","in_progress"]),models.RiskTreatmentPlan.target_date.is_not(None)).all()
    for item,title,message,entity_type in [(x,"Governance Risk Overdue",x.risk_key,"governance_risk") for x in risks if utc(x.due_at)<checked]+[(x,"Governance Treatment Overdue",f"Treatment {x.id} for {x.risk.risk_key}","governance_risk") for x in treatments if utc(x.target_date)<checked]:
        try:
            made=notify_once(db,title,message,"warning",entity_type,item.id if isinstance(item,models.GovernanceRisk) else item.risk_id);created+=int(made);reused+=int(not made);risk_count+=int(isinstance(item,models.GovernanceRisk));treatment_count+=int(isinstance(item,models.RiskTreatmentPlan))
        except Exception as exc:errors.append(redact(exc,200))
    db.commit();return {"risks_examined":len(risks),"treatments_examined":len(treatments),"overdue_risks":risk_count,"overdue_treatments":treatment_count,"notifications_created":created,"notifications_reused":reused,"errors":errors,"checked_at":checked}


@router.get("/evidence-packages")
def evidence_packages(status:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.GovernanceEvidencePackage)
    if status:query=query.filter_by(status=status)
    return [dump(x) for x in query.order_by(models.GovernanceEvidencePackage.updated_at.desc())]
@router.post("/evidence-packages")
def create_package(payload:dict,db:Session=Depends(get_db)):
    title=redact(payload.get("title"),300)
    if not title or not title.strip():raise HTTPException(422,"Evidence package title is required")
    if payload.get("framework_id") is not None:get_or_404(db,models.GovernanceFramework,payload["framework_id"],"Framework")
    if payload.get("review_id") is not None:get_or_404(db,models.GovernanceReview,payload["review_id"],"Governance review")
    item=models.GovernanceEvidencePackage(package_key=key("EVID",datetime.now(timezone.utc).isoformat()+title),title=title,description=redact(payload.get("description",""),3000),framework_id=payload.get("framework_id"),review_id=payload.get("review_id"),owner_name=redact(payload.get("owner_name"),200));db.add(item);db.flush();activity(db,"governance_evidence_package_created",f"Created evidence package {item.package_key}.",item.id);db.commit();return dump(item)
@router.get("/evidence-packages/{package_id}")
def package(package_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package");return dump(x)|{"items":[dump(y) for y in x.items]}
@router.patch("/evidence-packages/{package_id}")
def update_package(package_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package")
    if "status" in payload:choice(payload["status"],PACKAGE_STATUSES,"evidence package status")
    if "title" in payload and not (redact(payload["title"],300) or "").strip():raise HTTPException(422,"Evidence package title is required")
    if payload.get("framework_id") is not None:get_or_404(db,models.GovernanceFramework,payload["framework_id"],"Framework")
    if payload.get("review_id") is not None:get_or_404(db,models.GovernanceReview,payload["review_id"],"Governance review")
    for field in ("title","description","status","owner_name","framework_id","review_id"):
        if field in payload:setattr(x,field,redact(payload[field],3000) if field in {"title","description","owner_name"} else payload[field])
    activity(db,"governance_evidence_package_updated",f"Updated {x.package_key}.",x.id);db.commit();return dump(x)
@router.delete("/evidence-packages/{package_id}")
def delete_package(package_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package");db.delete(x);activity(db,"governance_record_deleted",f"Deleted governance evidence package {x.package_key}; source records preserved.");db.commit();return {"ok":True,"source_records_deleted":0}
@router.get("/evidence-packages/{package_id}/items")
def package_items(package_id:int,db:Session=Depends(get_db)):return [dump(x) for x in get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package").items]
@router.post("/evidence-packages/{package_id}/items")
def add_package_item(package_id:int,payload:dict,db:Session=Depends(get_db)):
    package=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package");item,created=evidence_service.add_item(db,package,payload);activity(db,"governance_evidence_item_added",f"{'Added' if created else 'Reused'} safe evidence in {package.package_key}.",package.id);db.commit();return dump(item)|{"created":created}
@router.delete("/evidence-packages/{package_id}/items/{item_id}")
def delete_package_item(package_id:int,item_id:int,db:Session=Depends(get_db)):
    package=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package");item=db.query(models.GovernanceEvidenceItem).filter_by(id=item_id,package_id=package.id).first()
    if not item:raise HTTPException(404,"Evidence item not found")
    db.delete(item);db.flush();package.item_count=db.query(models.GovernanceEvidenceItem).filter_by(package_id=package.id).count();db.commit();return {"ok":True,"source_records_deleted":0}


@router.get("/reviews")
def reviews(status:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.GovernanceReview)
    if status:query=query.filter_by(status=status)
    return [dump(x) for x in query.order_by(models.GovernanceReview.updated_at.desc())]
@router.post("/reviews")
def create_review(payload:dict,db:Session=Depends(get_db)):
    try:start=datetime.fromisoformat(payload["period_start"].replace("Z","+00:00"));end=datetime.fromisoformat(payload["period_end"].replace("Z","+00:00"))
    except Exception:raise HTTPException(422,"Review period start and end are required")
    review_service.validate_period(start,end);title=redact(payload.get("title"),300)
    if not title or not title.strip():raise HTTPException(422,"Review title is required")
    choice(payload.get("review_type","periodic"),REVIEW_TYPES,"review type")
    x=models.GovernanceReview(review_key=key("REVIEW",datetime.now(timezone.utc).isoformat()+title),title=title,review_type=payload.get("review_type","periodic"),period_start=start,period_end=end,owner_name=redact(payload.get("owner_name"),200),scope_summary=redact(payload.get("scope_summary","Local governance evidence review."),3000));db.add(x);db.flush();activity(db,"governance_review_created",f"Created review {x.review_key}.",x.id);db.commit();return dump(x)
@router.get("/reviews/{review_id}")
def review(review_id:int,db:Session=Depends(get_db)):return dump(get_or_404(db,models.GovernanceReview,review_id,"Governance review"))
@router.patch("/reviews/{review_id}")
def update_review(review_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceReview,review_id,"Governance review")
    if x.status=="completed":raise HTTPException(422,"Completed review snapshots are immutable")
    if "review_type" in payload:choice(payload["review_type"],REVIEW_TYPES,"review type")
    if "status" in payload:choice(payload["status"],REVIEW_STATUSES,"review status")
    if "title" in payload and not (redact(payload["title"],300) or "").strip():raise HTTPException(422,"Review title is required")
    for field in ("title","review_type","owner_name","status","scope_summary","conclusions"):
        if field in payload:setattr(x,field,redact(payload[field],4000))
    if x.status=="awaiting_approval":notify_once(db,"Governance Review Awaiting Approval",x.review_key,"warning","governance_review",x.id)
    db.commit();return dump(x)
@router.delete("/reviews/{review_id}")
def delete_review(review_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceReview,review_id,"Governance review")
    if x.status=="completed":raise HTTPException(422,"Completed governance reviews are retained")
    db.delete(x);db.commit();return {"ok":True}
@router.post("/reviews/{review_id}/complete")
def complete_review(review_id:int,payload:dict,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceReview,review_id,"Governance review");conclusions=redact(payload.get("conclusions",x.conclusions),5000)
    if not conclusions:raise HTTPException(422,"Review conclusions are required")
    if x.status=="completed":return dump(x)
    values=snapshot_service.metrics(db);snapshot,created=snapshot_service.capture(db,"review_completion",source_label=x.review_key);x.conclusions=conclusions;x.snapshot_json=json.dumps(values);x.status="completed";x.completed_at=datetime.now(timezone.utc);activity(db,"governance_review_completed",f"Completed review {x.review_key} with immutable aggregate snapshot.",x.id);notify_once(db,"Governance Review Completed",x.review_key,"success","governance_review",x.id);db.commit();return dump(x)|{"snapshot":dump(snapshot),"snapshot_created":created}


@router.post("/snapshots/capture")
def capture_snapshot(payload:dict|None=None,db:Session=Depends(get_db)):
    payload=payload or {};item,created=snapshot_service.capture(db,"manual",source_label=redact(payload.get("label"),100));db.commit();return dump(item)|{"created":created}
@router.get("/snapshots")
def snapshots(date_from:datetime|None=None,date_to:datetime|None=None,db:Session=Depends(get_db)):
    valid_range(date_from,date_to,"snapshot date");query=db.query(models.GovernanceSnapshot)
    if date_from:query=query.filter(models.GovernanceSnapshot.metric_date>=date_from)
    if date_to:query=query.filter(models.GovernanceSnapshot.metric_date<=date_to)
    return [dump(x) for x in query.order_by(models.GovernanceSnapshot.metric_date)]


@router.post("/reports/executive")
def executive_report(db:Session=Depends(get_db)):return dump(report_service.generate(db,"executive_risk"))
@router.post("/reports/risk-register")
def risk_register_report(db:Session=Depends(get_db)):return dump(report_service.generate(db,"risk_register"))
@router.post("/frameworks/{framework_id}/reports")
def framework_report(framework_id:int,db:Session=Depends(get_db)):return dump(report_service.generate(db,"framework_coverage",framework=get_or_404(db,models.GovernanceFramework,framework_id,"Framework")))
@router.post("/evidence-packages/{package_id}/reports")
def evidence_report(package_id:int,db:Session=Depends(get_db)):return dump(report_service.generate(db,"evidence_package",package=get_or_404(db,models.GovernanceEvidencePackage,package_id,"Evidence package")))
@router.post("/reviews/{review_id}/reports")
def review_report(review_id:int,db:Session=Depends(get_db)):return dump(report_service.generate(db,"governance_review",review=get_or_404(db,models.GovernanceReview,review_id,"Governance review")))
@router.get("/reports")
def reports(report_type:str|None=None,db:Session=Depends(get_db)):
    query=db.query(models.GovernanceReport)
    if report_type:query=query.filter_by(report_type=report_type)
    return [dump(x) for x in query.order_by(models.GovernanceReport.created_at.desc())]
@router.get("/reports/{report_id}")
def report(report_id:int,db:Session=Depends(get_db)):return dump(get_or_404(db,models.GovernanceReport,report_id,"Governance report"))
@router.get("/reports/{report_id}/download")
def download_report(report_id:int,db:Session=Depends(get_db)):
    x=get_or_404(db,models.GovernanceReport,report_id,"Governance report");return Response(x.html_content,media_type="text/html",headers={"Content-Disposition":f'attachment; filename="governance-report-{x.id}.html"'})
