import json
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.modules.access_control.dependencies import require_permission
from app.modules.soc_monitor.redaction import redact_text
from app.modules.threat_intelligence.service import post_commit_event
from . import evaluator, execution_service, import_service, report_service, schemas, service
from .models import AttackTechnique, DetectionExecution, DetectionMatch, DetectionReport, DetectionRule, DetectionRulePack, DetectionRulePackEntry, DetectionRuleTechnique, DetectionRuleVersion, DetectionSuppression, DetectionTestCase

router=APIRouter()
_limits=defaultdict(deque)


def rate_limit(user_id,key,limit=20):
    instant=time.monotonic(); bucket=_limits[(user_id,key)]
    while bucket and bucket[0] < instant-60: bucket.popleft()
    if len(bucket)>=limit: raise HTTPException(429,"Rate limit exceeded; retry shortly")
    bucket.append(instant)


def get_or_404(db,model,item_id,label):
    item=db.get(model,item_id)
    if not item: raise HTTPException(404,f"{label} not found")
    return item


def validate_suppression_conditions(conditions):
    normalized={}
    for field,value in conditions.items():
        canonical=evaluator.canonical_field(field)
        if canonical not in evaluator.ALLOWED_FIELDS: raise HTTPException(422,f"Unsupported suppression field: {field}")
        if value is None or isinstance(value,str) and not value.strip(): raise HTTPException(422,"Suppression values must not be empty")
        normalized[canonical]=value
    return normalized


def page(query,page_number,page_size,order):
    total=query.count(); items=query.order_by(order).offset((page_number-1)*page_size).limit(page_size).all()
    return {"items":[service.dump(x) for x in items],"total":total,"page":page_number,"page_size":page_size}


def rule_detail(db,rule):
    data=service.dump(rule)
    data["versions"]=[service.dump(x) for x in rule.versions]
    data["tests"]=[service.dump(x) for x in rule.tests]
    data["techniques"]=[service.dump(x.technique) for x in db.query(DetectionRuleTechnique).filter_by(rule_id=rule.id).all()]
    data["validation"]=evaluator.validate(json.loads(rule.rule_content_json))
    data["match_count"]=db.query(DetectionMatch).filter_by(rule_id=rule.id).count()
    return data


@router.get("/overview")
def overview(db:Session=Depends(get_db)):
    total=db.query(DetectionRule).count(); active=db.query(DetectionRule).filter_by(lifecycle_status="active").count(); matches=db.query(DetectionMatch).count()
    covered=db.query(func.count(func.distinct(DetectionRuleTechnique.technique_id))).join(DetectionRule).filter(DetectionRule.lifecycle_status=="active").scalar() or 0
    technique_total=db.query(AttackTechnique).count()
    return {"total_rules":total,"active_rules":active,"draft_testing_rules":db.query(DetectionRule).filter(DetectionRule.lifecycle_status.in_(["draft","testing"])).count(),
      "disabled_rules":db.query(DetectionRule).filter_by(lifecycle_status="disabled").count(),"recent_executions":[service.dump(x) for x in db.query(DetectionExecution).order_by(DetectionExecution.started_at.desc()).limit(5)],
      "total_matches":matches,"high_risk_matches":db.query(DetectionMatch).filter(DetectionMatch.risk_score>=60,DetectionMatch.status.notin_(["false_positive","suppressed"])).count(),
      "confirmed_matches":db.query(DetectionMatch).filter_by(status="confirmed").count(),"false_positive_rate":round(db.query(DetectionMatch).filter_by(status="false_positive").count()*100/matches,1) if matches else 0,
      "attack_coverage_percentage":round(covered*100/technique_total,1) if technique_total else 0,"average_quality":round(db.query(func.avg(DetectionRule.quality_score)).scalar() or 0,1),
      "recent_escalations":[service.dump(x) for x in db.query(DetectionMatch).filter_by(status="escalated").order_by(DetectionMatch.reviewed_at.desc()).limit(5)]}


@router.get("/rules")
def rules(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),search:str|None=None,status:str|None=None,severity:str|None=None,rule_format:str|None=None,source_module:str|None=None,technique:str|None=None,sort:str="updated",db:Session=Depends(get_db)):
    query=db.query(DetectionRule)
    if search: query=query.filter(or_(DetectionRule.title.ilike(f"%{search[:120]}%"),DetectionRule.description.ilike(f"%{search[:120]}%")))
    if status: query=query.filter_by(lifecycle_status=status)
    if severity: query=query.filter_by(severity=severity)
    if rule_format: query=query.filter_by(rule_format=rule_format)
    if source_module: query=query.filter_by(source_module=source_module)
    if technique: query=query.join(DetectionRuleTechnique).join(AttackTechnique).filter(AttackTechnique.external_id==technique.upper())
    order={"title":DetectionRule.title.asc(),"quality":DetectionRule.quality_score.desc(),"created":DetectionRule.created_at.desc()}.get(sort,DetectionRule.updated_at.desc())
    return page(query,page_number,page_size,order)


@router.post("/rules")
def create_rule(payload:schemas.RuleCreate,request:Request,db:Session=Depends(get_db)):
    user=request.state.current_user; rate_limit(user.id,"rule_create")
    if payload.rule_uuid and db.query(DetectionRule).filter_by(rule_uuid=payload.rule_uuid).first(): raise HTTPException(409,"Rule UUID already exists")
    item=service.create_rule(db,payload.model_dump(),user.id)
    try: db.commit()
    except IntegrityError as exc: db.rollback(); raise HTTPException(409,"Rule UUID already exists") from exc
    db.refresh(item);post_commit_event(db,request,user,"detection_rule_created","detection_rule",item.id,f"Detection rule {item.id} created.");return rule_detail(db,item)


@router.get("/rules/{rule_id}")
def get_rule(rule_id:int,db:Session=Depends(get_db)): return rule_detail(db,get_or_404(db,DetectionRule,rule_id,"Rule"))


@router.patch("/rules/{rule_id}")
def update_rule(rule_id:int,payload:schemas.RuleUpdate,request:Request,db:Session=Depends(get_db)):
    rule=get_or_404(db,DetectionRule,rule_id,"Rule")
    if rule.system_owned and not request.state.current_user.is_system_admin: raise HTTPException(403,"System rules require Administrator access; clone to edit")
    changes=payload.model_dump(exclude_unset=True); summary=changes.pop("change_summary","Rule updated")
    content=json.loads(rule.rule_content_json)
    for key in ["title","description"]:
        if key in changes: setattr(rule,key,changes[key]);content[key]=changes[key]
    if "selections" in changes: content["selections"]=changes.pop("selections")
    if "condition" in changes: content["condition"]=changes.pop("condition")
    techniques=changes.pop("technique_ids",None);tags=changes.pop("tags",None)
    for key,value in changes.items(): setattr(rule,key,value)
    result=evaluator.validate(content)
    if not result["valid"]: raise HTTPException(422,result["errors"])
    new_hash=service.content_hash(content);current=db.query(DetectionRuleVersion).filter_by(rule_id=rule.id,version_number=rule.current_version).first()
    if current and current.content_sha256==new_hash and techniques is None and tags is None: raise HTTPException(409,"No meaningful rule change detected")
    rule.current_version+=1;rule.rule_content_json=json.dumps(content,sort_keys=True);rule.normalized_condition_json=json.dumps(result["normalized"],sort_keys=True);rule.lifecycle_status="testing" if rule.lifecycle_status=="active" else rule.lifecycle_status;rule.enabled=False
    if tags is not None: rule.tags_json=json.dumps(sorted({str(x)[:80] for x in tags}))
    if techniques is not None: service.map_techniques(db,rule.id,techniques,request.state.current_user.id)
    service.add_version(db,rule,request.state.current_user.id,summary);rule.quality_score=service.quality_score(rule,db);db.commit();db.refresh(rule)
    post_commit_event(db,request,request.state.current_user,"detection_rule_updated","detection_rule",rule.id,f"Detection rule {rule.id} version {rule.current_version} created.");return rule_detail(db,rule)


@router.post("/rules/{rule_id}/validate")
def validate_rule(rule_id:int,request:Request,db:Session=Depends(get_db)):
    rate_limit(request.state.current_user.id,"validate",30);rule=get_or_404(db,DetectionRule,rule_id,"Rule");result=evaluator.validate(json.loads(rule.rule_content_json));rule.last_validated_at=datetime.now(timezone.utc);rule.quality_score=service.quality_score(rule,db);db.commit()
    if not result["valid"]: post_commit_event(db,request,request.state.current_user,"detection_validation_failed","detection_rule",rule.id,f"Validation failed for detection rule {rule.id}.",notify=("Detection rule validation failed",f"Rule {rule.id} requires correction.","warning"))
    else: post_commit_event(db,request,request.state.current_user,"detection_rule_validated","detection_rule",rule.id,f"Detection rule {rule.id} validated.")
    return result|{"test_summary":execution_service.run_tests(db,rule),"quality_score":rule.quality_score}


@router.post("/rules/{rule_id}/activate")
def activate(rule_id:int,request:Request,db:Session=Depends(get_db)):
    rule=get_or_404(db,DetectionRule,rule_id,"Rule");validation=evaluator.validate(json.loads(rule.rule_content_json));tests=execution_service.run_tests(db,rule)
    if not validation["valid"] or not tests["passed"]: raise HTTPException(422,"Activation requires successful validation and all enabled positive/negative tests to pass")
    rule.lifecycle_status="active";rule.enabled=True;rule.last_validated_at=datetime.now(timezone.utc);rule.quality_score=service.quality_score(rule,db);db.commit();post_commit_event(db,request,request.state.current_user,"detection_rule_activated","detection_rule",rule.id,f"Detection rule {rule.id} activated.");return service.dump(rule)


def _lifecycle(rule_id,status,request,db):
    rule=get_or_404(db,DetectionRule,rule_id,"Rule");rule.lifecycle_status=status;rule.enabled=False;db.commit();post_commit_event(db,request,request.state.current_user,f"detection_rule_{status}","detection_rule",rule.id,f"Detection rule {rule.id} set to {status}.");return service.dump(rule)


@router.post("/rules/{rule_id}/disable")
def disable(rule_id:int,request:Request,db:Session=Depends(get_db)): return _lifecycle(rule_id,"disabled",request,db)
@router.post("/rules/{rule_id}/archive")
def archive(rule_id:int,request:Request,db:Session=Depends(get_db)): return _lifecycle(rule_id,"archived",request,db)


@router.post("/rules/{rule_id}/clone")
def clone(rule_id:int,request:Request,db:Session=Depends(get_db)):
    source=get_or_404(db,DetectionRule,rule_id,"Rule");content=json.loads(source.rule_content_json)
    item=service.create_rule(db,{"title":f"Copy of {source.title}"[:240],"description":source.description,"selections":content["selections"],"condition":content["condition"],"severity":source.severity,"confidence":source.confidence,"source_module":source.source_module,"tags":json.loads(source.tags_json)},request.state.current_user.id);db.commit();db.refresh(item);post_commit_event(db,request,request.state.current_user,"detection_rule_cloned","detection_rule",item.id,f"Detection rule {source.id} cloned as {item.id}.");return rule_detail(db,item)


@router.get("/rules/{rule_id}/versions")
def versions(rule_id:int,db:Session=Depends(get_db)): get_or_404(db,DetectionRule,rule_id,"Rule");return [service.dump(x) for x in db.query(DetectionRuleVersion).filter_by(rule_id=rule_id).order_by(DetectionRuleVersion.version_number.desc())]
@router.get("/rules/{rule_id}/versions/{version}")
def version(rule_id:int,version:int,db:Session=Depends(get_db)): return service.dump(db.query(DetectionRuleVersion).filter_by(rule_id=rule_id,version_number=version).first()) or (_ for _ in ()).throw(HTTPException(404,"Version not found"))
@router.post("/rules/{rule_id}/rollback")
def rollback(rule_id:int,payload:schemas.Rollback,request:Request,db:Session=Depends(get_db)):
    rule=get_or_404(db,DetectionRule,rule_id,"Rule");old=db.query(DetectionRuleVersion).filter_by(rule_id=rule.id,version_number=payload.version_number).first()
    if not old: raise HTTPException(404,"Version not found")
    rule.current_version+=1;rule.rule_content_json=old.rule_content_json;rule.normalized_condition_json=old.normalized_condition_json;rule.lifecycle_status="testing";rule.enabled=False;service.add_version(db,rule,request.state.current_user.id,payload.change_summary);db.commit();post_commit_event(db,request,request.state.current_user,"detection_rule_rollback","detection_rule",rule.id,f"Rule {rule.id} rolled back as new version {rule.current_version}.");return rule_detail(db,rule)


@router.get("/rules/{rule_id}/tests")
def tests(rule_id:int,db:Session=Depends(get_db)): get_or_404(db,DetectionRule,rule_id,"Rule");return [service.dump(x) for x in db.query(DetectionTestCase).filter_by(rule_id=rule_id).order_by(DetectionTestCase.id)]
@router.post("/rules/{rule_id}/tests")
def create_test(rule_id:int,payload:schemas.TestCaseCreate,request:Request,db:Session=Depends(get_db)):
    rule=get_or_404(db,DetectionRule,rule_id,"Rule")
    try:event=execution_service.synthetic_event(payload.event_payload)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    item=DetectionTestCase(rule_id=rule.id,name=payload.name,description=payload.description,event_payload_json=json.dumps(payload.event_payload,sort_keys=True),expected_match=payload.expected_match,expected_severity=payload.expected_severity,enabled=payload.enabled,created_by_user_id=request.state.current_user.id);db.add(item);db.flush();rule.quality_score=service.quality_score(rule,db);db.commit();db.refresh(item);post_commit_event(db,request,request.state.current_user,"detection_test_created","detection_test_case",item.id,f"Test case {item.id} created.");return service.dump(item)
@router.patch("/rules/{rule_id}/tests/{test_id}")
def update_test(rule_id:int,test_id:int,payload:schemas.TestCaseUpdate,request:Request,db:Session=Depends(get_db)):
    item=db.query(DetectionTestCase).filter_by(id=test_id,rule_id=rule_id).first()
    if not item:raise HTTPException(404,"Test case not found")
    changes=payload.model_dump(exclude_unset=True)
    if "event_payload" in changes:execution_service.synthetic_event(changes["event_payload"]);item.event_payload_json=json.dumps(changes.pop("event_payload"),sort_keys=True)
    for key,value in changes.items():setattr(item,key,value)
    db.commit();post_commit_event(db,request,request.state.current_user,"detection_test_updated","detection_test_case",item.id,f"Test case {item.id} updated.");return service.dump(item)
@router.delete("/rules/{rule_id}/tests/{test_id}")
def delete_test(rule_id:int,test_id:int,request:Request,db:Session=Depends(get_db)):
    item=db.query(DetectionTestCase).filter_by(id=test_id,rule_id=rule_id).first()
    if not item:raise HTTPException(404,"Test case not found")
    db.delete(item);db.commit();post_commit_event(db,request,request.state.current_user,"detection_test_deleted","detection_test_case",test_id,f"Test case {test_id} deleted.");return {"ok":True}
@router.post("/rules/{rule_id}/tests/run")
def run_tests(rule_id:int,request:Request,db:Session=Depends(get_db)):
    rate_limit(request.state.current_user.id,"test_run",30);rule=get_or_404(db,DetectionRule,rule_id,"Rule");result=execution_service.run_tests(db,rule);post_commit_event(db,request,request.state.current_user,"detection_tests_executed","detection_rule",rule.id,f"{result['passed_count']} of {result['total']} tests passed for rule {rule.id}.");return result


@router.post("/imports/validate")
def validate_import(payload:schemas.ImportRequest,request:Request):
    rate_limit(request.state.current_user.id,"import_validate",10)
    try:return import_service.parse(payload.content,payload.filename)
    except import_service.ImportError as exc:raise HTTPException(422,str(exc)) from exc
@router.post("/imports")
def import_rules(payload:schemas.ImportRequest,request:Request,db:Session=Depends(get_db)):
    preview=validate_import(payload,request);created=[];skipped=[];versions=[]
    for item in preview["previews"]:
        if not item["valid"]:skipped.append({"title":item.get("title"),"reason":"validation failed"});continue
        existing=db.query(DetectionRule).filter_by(rule_uuid=item["rule_uuid"]).first() if item["rule_uuid"] else None
        content_existing=db.query(DetectionRuleVersion).filter_by(content_sha256=item["content_sha256"]).first()
        if (existing or content_existing) and payload.duplicate_action=="skip":skipped.append({"title":item["title"],"reason":"duplicate UUID or content"});continue
        if existing:
            existing.current_version+=1;existing.rule_content_json=json.dumps(item["content"],sort_keys=True);existing.normalized_condition_json=json.dumps(item["normalized"],sort_keys=True);existing.lifecycle_status="testing";existing.enabled=False;service.add_version(db,existing,request.state.current_user.id,"Imported new version");versions.append(existing.id);continue
        tags=[str(x) for x in item["content"].get("tags",[])]; techniques=[]
        for tag in tags:
            if tag.lower().startswith("attack.t"):
                external=tag.split(".",1)[1].upper()
                if db.query(AttackTechnique).filter_by(external_id=external).first():techniques.append(external)
                else:item["warnings"].append(f"Unknown local ATT&CK tag preserved as warning: {tag}")
        logsource=item["content"].get("logsource") or {}; detection=item["content"].get("detection") or {}; selections={k:v for k,v in detection.items() if k!="condition"} or item["content"].get("selections")
        rule=service.create_rule(db,{"title":item["title"],"description":str(item["content"].get("description") or "")[:8000],"rule_uuid":item["rule_uuid"],"rule_format":item["format"],"severity":item["severity"] if item["severity"] in {"informational","low","medium","high","critical"} else "medium","confidence":50,"source_module":None,"logsource_category":logsource.get("category"),"logsource_product":logsource.get("product"),"logsource_service":logsource.get("service"),"selections":selections,"condition":detection.get("condition") or item["content"].get("condition"),"false_positive_guidance":"; ".join(map(str,item["content"].get("falsepositives",[])))[:8000],"tags":tags,"technique_ids":techniques,"lifecycle_status":"draft"},request.state.current_user.id);created.append(rule.id)
    db.commit();post_commit_event(db,request,request.state.current_user,"detection_rules_imported","detection_import",0,f"Detection import created {len(created)} rules and {len(versions)} versions.");return preview|{"created_rule_ids":created,"versioned_rule_ids":versions,"skipped":skipped}


@router.get("/packs")
def packs(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),db:Session=Depends(get_db)):return page(db.query(DetectionRulePack),page_number,page_size,DetectionRulePack.name.asc())
@router.post("/packs")
def create_pack(payload:schemas.PackCreate,request:Request,db:Session=Depends(get_db)):
    item=DetectionRulePack(**payload.model_dump(),system_owned=False,created_by_user_id=request.state.current_user.id);db.add(item)
    try:db.commit()
    except IntegrityError as exc:db.rollback();raise HTTPException(409,"Pack name already exists") from exc
    db.refresh(item);post_commit_event(db,request,request.state.current_user,"detection_pack_created","detection_rule_pack",item.id,f"Detection pack {item.id} created.");return service.dump(item)
@router.get("/packs/{pack_id}")
def get_pack(pack_id:int,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionRulePack,pack_id,"Pack");return service.dump(item)|{"rules":[service.dump(x.rule) for x in item.entries]}
@router.patch("/packs/{pack_id}")
def update_pack(pack_id:int,payload:schemas.PackUpdate,request:Request,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionRulePack,pack_id,"Pack")
    if item.system_owned:raise HTTPException(403,"System packs are protected")
    for key,value in payload.model_dump(exclude_unset=True).items():setattr(item,key,value)
    db.commit();post_commit_event(db,request,request.state.current_user,"detection_pack_updated","detection_rule_pack",item.id,f"Detection pack {item.id} updated.");return service.dump(item)
@router.post("/packs/{pack_id}/rules")
def add_pack_rule(pack_id:int,payload:schemas.PackRule,request:Request,db:Session=Depends(get_db)):
    get_or_404(db,DetectionRulePack,pack_id,"Pack");get_or_404(db,DetectionRule,payload.rule_id,"Rule");item=DetectionRulePackEntry(pack_id=pack_id,rule_id=payload.rule_id,added_by_user_id=request.state.current_user.id);db.add(item)
    try:db.commit()
    except IntegrityError as exc:db.rollback();raise HTTPException(409,"Rule already belongs to pack") from exc
    return service.dump(item)
@router.delete("/packs/{pack_id}/rules/{rule_id}")
def remove_pack_rule(pack_id:int,rule_id:int,request:Request,db:Session=Depends(get_db)):
    pack=get_or_404(db,DetectionRulePack,pack_id,"Pack")
    if pack.system_owned:raise HTTPException(403,"System packs are protected")
    item=db.query(DetectionRulePackEntry).filter_by(pack_id=pack_id,rule_id=rule_id).first()
    if not item:raise HTTPException(404,"Pack entry not found")
    db.delete(item);db.commit();return {"ok":True}


@router.get("/techniques")
def techniques(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(100,ge=1,le=100),tactic:str|None=None,db:Session=Depends(get_db)):
    query=db.query(AttackTechnique)
    if tactic:query=query.filter_by(tactic=tactic)
    return page(query,page_number,page_size,AttackTechnique.external_id.asc())
@router.get("/coverage")
def coverage(db:Session=Depends(get_db)):
    items=[]
    for technique in db.query(AttackTechnique).order_by(AttackTechnique.external_id):
        mappings=db.query(DetectionRuleTechnique).filter_by(technique_id=technique.id).all();ids=[x.rule_id for x in mappings]
        active=db.query(DetectionRule).filter(DetectionRule.id.in_(ids),DetectionRule.lifecycle_status=="active").all() if ids else []
        match_count=db.query(DetectionMatch).filter(DetectionMatch.rule_id.in_(ids)).count() if ids else 0
        confirmed=db.query(DetectionMatch).filter(DetectionMatch.rule_id.in_(ids),DetectionMatch.status=="confirmed").count() if ids else 0
        false=db.query(DetectionMatch).filter(DetectionMatch.rule_id.in_(ids),DetectionMatch.status=="false_positive").count() if ids else 0
        items.append(service.dump(technique)|{"covered":bool(active),"active_rule_count":len(active),"validated_rule_count":sum(r.last_validated_at is not None for r in active),"average_quality":round(sum(r.quality_score for r in active)/len(active),1) if active else 0,"match_count":match_count,"confirmed_match_count":confirmed,"false_positive_ratio":round(false*100/match_count,1) if match_count else 0})
    return {"catalog_scope":"Bounded local educational subset; not the complete current ATT&CK catalog or complete organizational coverage.","items":items}


@router.post("/executions")
def execute(payload:schemas.ExecutionCreate,request:Request,db:Session=Depends(get_db)):
    rate_limit(request.state.current_user.id,"execution",10);execution=execution_service.execute(db,payload,request.state.current_user.id);post_commit_event(db,request,request.state.current_user,"detection_execution_completed","detection_execution",execution.id,f"Execution {execution.id} scanned {execution.records_scanned} stored records.",notify=("Detection execution completed",f"Execution {execution.id} completed with {execution.errors_count} errors.","warning" if execution.errors_count else "info"));return service.dump(execution)
@router.get("/executions")
def executions(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),status:str|None=None,db:Session=Depends(get_db)):
    query=db.query(DetectionExecution)
    if status:query=query.filter_by(status=status)
    return page(query,page_number,page_size,DetectionExecution.started_at.desc())
@router.get("/executions/{execution_id}")
def get_execution(execution_id:int,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionExecution,execution_id,"Execution");return service.dump(item)|{"matches":[service.dump(x) for x in db.query(DetectionMatch).filter_by(execution_id=item.id).order_by(DetectionMatch.risk_score.desc()).limit(100)]}
@router.post("/executions/{execution_id}/cancel")
def cancel_execution(execution_id:int,request:Request,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionExecution,execution_id,"Execution")
    if item.status not in {"queued","running"}:raise HTTPException(409,"Only queued or running executions can be cancelled")
    item.status="cancelled";item.completed_at=datetime.now(timezone.utc);db.commit();return service.dump(item)


@router.get("/matches")
def matches(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),status:str|None=None,min_risk:float|None=Query(None,ge=0,le=100),rule_id:int|None=None,db:Session=Depends(get_db)):
    query=db.query(DetectionMatch)
    if status:query=query.filter_by(status=status)
    if min_risk is not None:query=query.filter(DetectionMatch.risk_score>=min_risk)
    if rule_id:query=query.filter_by(rule_id=rule_id)
    return page(query,page_number,page_size,DetectionMatch.created_at.desc())
@router.get("/matches/{match_id}")
def get_match(match_id:int,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionMatch,match_id,"Match");return service.dump(item)|{"rule":service.dump(item.rule),"alert":service.dump(db.get(models.SocAlert,item.alert_id)) if item.alert_id else None,"case":service.dump(db.get(models.IncidentCase,item.case_id)) if item.case_id else None}
@router.post("/matches/{match_id}/review")
def review_match(match_id:int,payload:schemas.MatchReview,request:Request,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionMatch,match_id,"Match");item.status=payload.status;item.analyst_note=redact_text(payload.analyst_note or "",4000);item.reviewed_by_user_id=request.state.current_user.id;item.reviewed_at=datetime.now(timezone.utc);db.commit();post_commit_event(db,request,request.state.current_user,"detection_match_reviewed","detection_match",item.id,f"Detection match {item.id} set to {item.status}.",notify=("Detection match confirmed",f"Match {item.id} was confirmed.","danger") if item.status=="confirmed" else None);return service.dump(item)
@router.post("/matches/{match_id}/create-alert",dependencies=[Depends(require_permission("soc:manage_alerts"))])
def create_alert(match_id:int,payload:schemas.Promote,request:Request,db:Session=Depends(get_db)):
    if payload.confirmed is not True:raise HTTPException(422,"Explicit analyst confirmation is required")
    item=get_or_404(db,DetectionMatch,match_id,"Match")
    if item.alert_id:raise HTTPException(409,"Match is already linked to an alert")
    soc_rule=db.query(models.SocDetectionRule).order_by(models.SocDetectionRule.id).first()
    if not soc_rule:raise HTTPException(409,"A local SOC detection rule is required before alert promotion")
    alert=models.SocAlert(rule_id=soc_rule.id,title=f"Detection: {item.rule.title}"[:240],description="Explicit analyst promotion from an offline detection match.",severity=item.severity,confidence="high" if item.confidence>=75 else "medium",status="open",first_seen=item.event_timestamp,last_seen=item.event_timestamp,event_count=1,correlation_key=f"detection:{item.id}",evidence_summary=redact_text(item.evidence_summary,2000),fingerprint=__import__('hashlib').sha256(f"detection-alert:{item.id}".encode()).hexdigest(),analyst_notes=redact_text(payload.analyst_note or "",4000));db.add(alert);db.flush();item.alert_id=alert.id;item.status="confirmed";db.commit();post_commit_event(db,request,request.state.current_user,"detection_alert_promoted","detection_match",item.id,f"Detection match {item.id} promoted to SOC alert {alert.id}.");return {"match":service.dump(item),"alert":service.dump(alert)}
@router.post("/matches/{match_id}/escalate-case",dependencies=[Depends(require_permission("cases:create"))])
def escalate_case(match_id:int,payload:schemas.Escalate,request:Request,db:Session=Depends(get_db)):
    if payload.confirmed is not True:raise HTTPException(422,"Explicit analyst confirmation is required")
    item=get_or_404(db,DetectionMatch,match_id,"Match")
    if item.case_id:raise HTTPException(409,"Match is already linked to a case")
    case=get_or_404(db,models.IncidentCase,payload.case_id,"Incident case") if payload.case_id else models.IncidentCase(case_key=f"DET-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{item.id}",title=payload.case_title or f"Detection match {item.id}",summary="Explicit analyst escalation from offline detection engineering.",case_type="incident",severity=item.severity,priority="P1" if item.risk_score>=80 else "P2" if item.risk_score>=60 else "P3",confidence="high" if item.confidence>=75 else "medium",risk_score=item.risk_score,status="new",source_module_count=1,evidence_count=0,tags_json='["detection-engineering"]')
    if not payload.case_id:db.add(case);db.flush()
    fingerprint=__import__('hashlib').sha256(f"detection-case:{item.id}:{case.id}".encode()).hexdigest()
    if not db.query(models.IncidentEvidence).filter_by(evidence_fingerprint=fingerprint).first():db.add(models.IncidentEvidence(case_id=case.id,source_module="detection_engineering",source_record_type="detection_match",source_record_id=item.id,source_internal_route=f"/detections/matches/{item.id}",title_snapshot=f"Detection match {item.id}",evidence_snapshot=redact_text(item.evidence_summary,2000),severity=item.severity,confidence="high" if item.confidence>=75 else "medium",evidence_fingerprint=fingerprint));case.evidence_count+=1
    item.case_id=case.id;item.status="escalated";item.reviewed_by_user_id=request.state.current_user.id;item.reviewed_at=datetime.now(timezone.utc);db.commit();post_commit_event(db,request,request.state.current_user,"detection_case_escalated","detection_match",item.id,f"Detection match {item.id} escalated to case {case.case_key}.",notify=("Detection match escalated",f"Match {item.id} linked to {case.case_key}.","warning"));return {"match":service.dump(item),"case":service.dump(case)}


@router.get("/suppressions")
def suppressions(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),db:Session=Depends(get_db)):return page(db.query(DetectionSuppression),page_number,page_size,DetectionSuppression.updated_at.desc())
@router.post("/suppressions")
def create_suppression(payload:schemas.SuppressionCreate,request:Request,db:Session=Depends(get_db)):
    if payload.rule_id:get_or_404(db,DetectionRule,payload.rule_id,"Rule")
    conditions=validate_suppression_conditions(payload.field_conditions)
    item=DetectionSuppression(name=payload.name,description=redact_text(payload.description,4000),rule_id=payload.rule_id,field_conditions_json=json.dumps(conditions,sort_keys=True),valid_from=payload.valid_from,valid_until=payload.valid_until,enabled=payload.enabled,created_by_user_id=request.state.current_user.id);db.add(item);db.commit();db.refresh(item);post_commit_event(db,request,request.state.current_user,"detection_suppression_created","detection_suppression",item.id,f"Detection suppression {item.id} created.");return service.dump(item)
@router.patch("/suppressions/{suppression_id}")
def update_suppression(suppression_id:int,payload:schemas.SuppressionUpdate,request:Request,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionSuppression,suppression_id,"Suppression");changes=payload.model_dump(exclude_unset=True)
    if "field_conditions" in changes:item.field_conditions_json=json.dumps(validate_suppression_conditions(changes.pop("field_conditions")),sort_keys=True)
    for key,value in changes.items():setattr(item,key,redact_text(value,4000) if key=="description" else value)
    db.commit();post_commit_event(db,request,request.state.current_user,"detection_suppression_updated","detection_suppression",item.id,f"Detection suppression {item.id} updated.");return service.dump(item)
@router.delete("/suppressions/{suppression_id}")
def delete_suppression(suppression_id:int,request:Request,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionSuppression,suppression_id,"Suppression");db.delete(item);db.commit();post_commit_event(db,request,request.state.current_user,"detection_suppression_deleted","detection_suppression",suppression_id,f"Detection suppression {suppression_id} deleted.");return {"ok":True}


@router.get("/reports")
def reports(page_number:int=Query(1,alias="page",ge=1),page_size:int=Query(25,ge=1,le=100),db:Session=Depends(get_db)):return page(db.query(DetectionReport),page_number,page_size,DetectionReport.created_at.desc())
@router.post("/reports")
def create_report(payload:schemas.ReportCreate,request:Request,db:Session=Depends(get_db)):
    rate_limit(request.state.current_user.id,"report",10);item=report_service.generate(db,payload.title,payload.report_type,payload.filters,request.state.current_user.id);post_commit_event(db,request,request.state.current_user,"detection_report_generated","detection_report",item.id,f"Detection report {item.id} generated.");return service.dump(item)
@router.get("/reports/{report_id}")
def get_report(report_id:int,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionReport,report_id,"Report");return service.dump(item)|{"html_content":item.html_content}
@router.get("/reports/{report_id}/download")
def download_report(report_id:int,db:Session=Depends(get_db)):
    item=get_or_404(db,DetectionReport,report_id,"Report");return Response(item.html_content,media_type="text/html",headers={"Content-Disposition":f"attachment; filename=detection-report-{item.id}.html"})
