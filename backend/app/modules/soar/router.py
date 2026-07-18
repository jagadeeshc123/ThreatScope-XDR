import difflib
import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.access_control.audit_service import append_event
from app.modules.access_control.dependencies import get_current_user, require_authenticated_csrf, require_permission, require_system_admin
from app.modules.access_control.models import UserAccount
from app.modules.access_control.role_service import effective_permissions

from . import report_service, service
from .catalog import ACTION_CATALOG, catalog_response
from .models import SoarActionPolicy, SoarAnalystInput, SoarApproval, SoarApprovalDecision, SoarExecution, SoarExecutionEvent, SoarExecutionEvidence, SoarPlaybook, SoarPlaybookVersion, SoarReport, SoarRollbackRecord, SoarStepExecution, SoarTriggerEvaluationRun, SoarTriggerRule
from .schemas import ActionPolicyUpdate, AnalystInputSubmit, CloneRequest, DecisionRequest, ExecutionCreate, LifecycleRequest, PlaybookCreate, PlaybookUpdate, ProcessDueRequest, ReasonRequest, ReportCreate, RollbackExecute, TriggerCreate, TriggerEvaluateRequest, TriggerUpdate, VersionRollbackRequest
from .validation import validate_definition


router = APIRouter()


def _audit(db:Session,request:Request,actor:UserAccount,action:str,resource_type:str,resource_id=None,metadata=None):
    append_event(db,event_type=f"soar_{action}",action=action,request_id=getattr(request.state,"request_id","unknown"),outcome="success",actor=actor,resource_type=resource_type,resource_id=resource_id,route_template=request.url.path,request_method=request.method,status_code=200,metadata=metadata or {})


def _get(db:Session,model,item_id:int,message:str="Record not found"):
    item=db.get(model,item_id)
    if not item:raise HTTPException(404,message)
    return item


def _bind_current_session(request:Request,actor:UserAccount)->None:
    auth_session=getattr(request.state,"auth_session",None)
    actor._soar_current_session_id=auth_session.id if auth_session else None


def _rate(db:Session,model,actor_id:int,limit:int=100):
    column=getattr(model,"created_at",None)
    actor_column=getattr(model,"requested_by_user_id",None)
    if actor_column is None: actor_column=getattr(model,"created_by_user_id",None)
    if column is not None and actor_column is not None and db.query(model).filter(actor_column==actor_id,column>=service.utcnow()-timedelta(hours=1)).count()>=limit:raise service.error(429,"SOAR_RATE_LIMITED","Bounded SOAR mutation rate exceeded")


@router.get("/overview",dependencies=[Depends(require_permission("soar:view"))])
def overview(db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    permissions=effective_permissions(db,actor)
    if "soar:view" not in permissions:return {}
    statuses={status:db.query(SoarExecution).filter_by(status=status).count() for status in ("proposed","waiting_approval","waiting_input","waiting_delay","running","completed","completed_with_warnings","failed","cancelled","rollback_requested","rollback_failed")}
    return {"active_playbooks":db.query(SoarPlaybook).filter_by(lifecycle_status="active").count(),"testing_playbooks":db.query(SoarPlaybook).filter_by(lifecycle_status="testing").count(),**statuses,"simulated_actions":db.query(SoarStepExecution).filter_by(status="simulated").count(),"local_actions":db.query(SoarStepExecution).filter(SoarStepExecution.status=="succeeded",SoarStepExecution.action_key.is_not(None)).count(),"sensitive_action_requests":db.query(SoarApproval).filter_by(approval_type="sensitive_action").count(),"rollback_failures":db.query(SoarRollbackRecord).filter_by(status="failed").count(),"mean_execution_seconds":None,"mean_approval_seconds":None,"timezone":"UTC","metrics_are_stored_data_only":True}


@router.get("/actions",dependencies=[Depends(require_permission("soar:view"))])
def actions(db:Session=Depends(get_db)):
    policies={item.action_key:service.row(item) for item in db.query(SoarActionPolicy).all()};return [{**item,"policy":policies.get(item["action_key"])} for item in catalog_response()]


@router.get("/action-policies",dependencies=[Depends(require_permission("soar:view"))])
def action_policies(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):return service.page(db.query(SoarActionPolicy).order_by(SoarActionPolicy.action_key),page,page_size)


@router.patch("/action-policies/{action_key}",dependencies=[Depends(require_authenticated_csrf),Depends(require_system_admin),Depends(require_permission("soar:action_policy_manage"))])
def update_policy(action_key:str,payload:ActionPolicyUpdate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    action=ACTION_CATALOG.get(action_key);policy=db.query(SoarActionPolicy).filter_by(action_key=action_key).first()
    if not action or not policy:raise service.error(404,"SOAR_ACTION_UNKNOWN","Unknown server-owned action")
    data=payload.model_dump(exclude_unset=True)
    if action.safety_classification=="sensitive_local" and (data.get("approval_required_override") is False or data.get("requester_approver_separation_required") is False or data.get("automatic_local_allowed") is True):raise service.error(422,"SOAR_ACTION_POLICY_VIOLATION","Sensitive action protections cannot be weakened")
    if (action.simulation_only or not action.automatic_local_eligible) and data.get("automatic_local_allowed") is True:raise service.error(422,"SOAR_ACTION_POLICY_VIOLATION","Action is not automatic-local eligible")
    if data.get("maximum_retries_override") is not None and data["maximum_retries_override"]>action.maximum_retries:raise service.error(422,"SOAR_ACTION_POLICY_VIOLATION","Retry override exceeds the server maximum")
    for key,value in data.items():setattr(policy,key,value)
    policy.updated_by_user_id=actor.id;db.commit();db.refresh(policy);_audit(db,request,actor,"action_policy_updated","soar_action_policy",policy.id,{"action_key":action_key,"safety_classification":action.safety_classification});return service.row(policy)


@router.get("/playbooks",dependencies=[Depends(require_permission("soar:view"))])
def playbooks(status:str|None=None,category:str|None=None,search:str|None=Query(None,max_length=200),page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):
    q=db.query(SoarPlaybook)
    if status:q=q.filter_by(lifecycle_status=status)
    if category:q=q.filter_by(category=category)
    if search:q=q.filter(SoarPlaybook.name.ilike(f"%{search}%"))
    return service.page(q.order_by(SoarPlaybook.updated_at.desc(),SoarPlaybook.id.desc()),page,page_size)


@router.post("/playbooks",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def create_playbook(payload:PlaybookCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    _rate(db,SoarPlaybook,actor.id,30);item,validation=service.create_playbook(db,payload,actor);_audit(db,request,actor,"playbook_created","soar_playbook",item.id,{"version":1,"valid":validation["valid"]});return {**service.row(item),"validation":validation}


@router.get("/playbooks/{playbook_id}",dependencies=[Depends(require_permission("soar:view"))])
def playbook_details(playbook_id:int,db:Session=Depends(get_db)):
    item=_get(db,SoarPlaybook,playbook_id);version=db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id,version_number=item.current_version).one();return {**service.row(item),"definition":service.loads(version.definition_json),"validation":service.loads(item.validation_summary_json)}


@router.patch("/playbooks/{playbook_id}",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def patch_playbook(playbook_id:int,payload:PlaybookUpdate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item,result,versioned=service.update_playbook(db,_get(db,SoarPlaybook,playbook_id),payload,actor);_audit(db,request,actor,"playbook_updated","soar_playbook",item.id,{"version":item.current_version,"version_created":versioned,"valid":result["valid"]});return {**service.row(item),"validation":result,"version_created":versioned}


@router.post("/playbooks/{playbook_id}/validate",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def validate_playbook(playbook_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=service.validate_playbook(db,_get(db,SoarPlaybook,playbook_id));_audit(db,request,actor,"playbook_validated","soar_playbook",playbook_id,{"valid":result["valid"],"content_sha256":result["content_sha256"]});return result


def _move(playbook_id:int,payload:LifecycleRequest,target:str,request:Request,db:Session,actor:UserAccount):
    item=service.lifecycle(db,_get(db,SoarPlaybook,playbook_id),target,actor,payload.optimistic_lock_version);_audit(db,request,actor,f"playbook_{target}","soar_playbook",item.id);return service.row(item)


@router.post("/playbooks/{playbook_id}/move-to-testing",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def move_testing(playbook_id:int,payload:LifecycleRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _move(playbook_id,payload,"testing",request,db,actor)
@router.post("/playbooks/{playbook_id}/activate",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def activate(playbook_id:int,payload:LifecycleRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _move(playbook_id,payload,"active",request,db,actor)
@router.post("/playbooks/{playbook_id}/disable",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def disable(playbook_id:int,payload:LifecycleRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _move(playbook_id,payload,"disabled",request,db,actor)
@router.post("/playbooks/{playbook_id}/archive",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def archive(playbook_id:int,payload:LifecycleRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _move(playbook_id,payload,"archived",request,db,actor)
@router.post("/playbooks/{playbook_id}/clone",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def clone(playbook_id:int,payload:CloneRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.clone_playbook(db,_get(db,SoarPlaybook,playbook_id),payload.name,payload.change_summary,actor);_audit(db,request,actor,"playbook_cloned","soar_playbook",item.id,{"source_playbook_id":playbook_id});return service.row(item)


@router.get("/playbooks/{playbook_id}/versions",dependencies=[Depends(require_permission("soar:view"))])
def versions(playbook_id:int,db:Session=Depends(get_db)):_get(db,SoarPlaybook,playbook_id);return [service.row(x) for x in db.query(SoarPlaybookVersion).filter_by(playbook_id=playbook_id).order_by(SoarPlaybookVersion.version_number.desc()).all()]
@router.get("/playbooks/{playbook_id}/versions/{version_number}",dependencies=[Depends(require_permission("soar:view"))])
def version(playbook_id:int,version_number:int,db:Session=Depends(get_db)):return service.row(db.query(SoarPlaybookVersion).filter_by(playbook_id=playbook_id,version_number=version_number).first() or (_ for _ in ()).throw(HTTPException(404,"Version not found")))
@router.get("/playbooks/{playbook_id}/versions/{from_version}/compare/{to_version}",dependencies=[Depends(require_permission("soar:view"))])
def compare(playbook_id:int,from_version:int,to_version:int,db:Session=Depends(get_db)):
    a=db.query(SoarPlaybookVersion).filter_by(playbook_id=playbook_id,version_number=from_version).first();b=db.query(SoarPlaybookVersion).filter_by(playbook_id=playbook_id,version_number=to_version).first()
    if not a or not b:raise HTTPException(404,"Version not found")
    left=json.dumps(service.loads(a.normalized_definition_json),indent=2,sort_keys=True).splitlines();right=json.dumps(service.loads(b.normalized_definition_json),indent=2,sort_keys=True).splitlines();return {"from_version":from_version,"to_version":to_version,"same_content":a.content_sha256==b.content_sha256,"diff":list(difflib.unified_diff(left,right,fromfile=str(from_version),tofile=str(to_version)))[:5000]}
@router.post("/playbooks/{playbook_id}/rollback-version",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def rollback_version(playbook_id:int,payload:VersionRollbackRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.version_rollback(db,_get(db,SoarPlaybook,playbook_id),payload.version_number,payload.change_summary,actor,payload.optimistic_lock_version);_audit(db,request,actor,"version_rollback","soar_playbook",item.id,{"source_version":payload.version_number,"new_version":item.current_version});return service.row(item)


@router.get("/templates",dependencies=[Depends(require_permission("soar:view"))])
def templates(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):return service.page(db.query(SoarPlaybook).filter_by(system_owned=True).order_by(SoarPlaybook.name),page,page_size)
@router.get("/templates/{template_id}",dependencies=[Depends(require_permission("soar:view"))])
def template_details(template_id:int,db:Session=Depends(get_db)):
    item=_get(db,SoarPlaybook,template_id)
    if not item.system_owned:raise HTTPException(404,"Template not found")
    return playbook_details(item.id,db)
@router.post("/templates/{template_id}/clone",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def clone_template(template_id:int,payload:CloneRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return clone(template_id,payload,request,db,actor)


@router.post("/triggers/evaluate",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def trigger_evaluate(payload:TriggerEvaluateRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    _rate(db,SoarTriggerEvaluationRun,actor.id,50);run=service.evaluate_triggers(db,payload,actor);_audit(db,request,actor,"trigger_evaluated","soar_trigger_evaluation",run.id,{"matched":run.rules_matched,"proposals":run.proposals_created});return service.row(run)
@router.get("/triggers/evaluation-runs",dependencies=[Depends(require_permission("soar:view"))])
def evaluation_runs(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):return service.page(db.query(SoarTriggerEvaluationRun).order_by(SoarTriggerEvaluationRun.started_at.desc()),page,page_size)
@router.get("/triggers/evaluation-runs/{run_id}",dependencies=[Depends(require_permission("soar:view"))])
def evaluation_run(run_id:int,db:Session=Depends(get_db)):return service.row(_get(db,SoarTriggerEvaluationRun,run_id))
@router.get("/triggers",dependencies=[Depends(require_permission("soar:view"))])
def triggers(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):return service.page(db.query(SoarTriggerRule).order_by(SoarTriggerRule.updated_at.desc()),page,page_size)
@router.post("/triggers",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def create_trigger(payload:TriggerCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    playbook=_get(db,SoarPlaybook,payload.playbook_id);validate_definition({"start_step":"end","steps":[{"key":"end","type":"end"}],"variables":{}},trigger_mode="manual")
    if payload.automatic_local and playbook.trigger_mode!="automatic_local":raise service.error(422,"SOAR_ACTION_POLICY_VIOLATION","Playbook is not automatic-local")
    try:service.evaluate(payload.conditions,{"trigger":{}})
    except ValueError as exc:raise service.error(422,"SOAR_PLAYBOOK_INVALID",str(exc))
    item=SoarTriggerRule(playbook_id=payload.playbook_id,name=payload.name,source_type=payload.source_type,conditions_json=service.dumps(payload.conditions),proposal_only=payload.proposal_only,automatic_local=payload.automatic_local,cooldown_minutes=payload.cooldown_minutes,maximum_proposals_per_hour=payload.maximum_proposals_per_hour,enabled=payload.enabled,created_by_user_id=actor.id);db.add(item);db.commit();db.refresh(item);_audit(db,request,actor,"trigger_created","soar_trigger",item.id);return service.row(item)
@router.get("/triggers/{trigger_id}",dependencies=[Depends(require_permission("soar:view"))])
def trigger_details(trigger_id:int,db:Session=Depends(get_db)):return service.row(_get(db,SoarTriggerRule,trigger_id))
@router.patch("/triggers/{trigger_id}",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def patch_trigger(trigger_id:int,payload:TriggerUpdate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarTriggerRule,trigger_id);data=payload.model_dump(exclude_unset=True)
    if "conditions" in data:data["conditions_json"]=service.dumps(data.pop("conditions"))
    for key,value in data.items():setattr(item,key,value)
    if item.automatic_local and item.proposal_only:raise service.error(422,"SOAR_ACTION_POLICY_VIOLATION","Trigger modes conflict")
    db.commit();db.refresh(item);_audit(db,request,actor,"trigger_updated","soar_trigger",item.id);return service.row(item)
@router.delete("/triggers/{trigger_id}",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:manage"))])
def delete_trigger(trigger_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarTriggerRule,trigger_id);item.enabled=False;db.commit();_audit(db,request,actor,"trigger_disabled","soar_trigger",item.id);return {"ok":True,"hard_deleted":False}


@router.post("/executions/process-due",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def due(payload:ProcessDueRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=service.process_due(db,actor,payload.batch_size);_audit(db,request,actor,"process_due","soar_execution",metadata=result);return result
@router.get("/executions",dependencies=[Depends(require_permission("soar:view"))])
def executions(status:str|None=None,mode:str|None=None,playbook_id:int|None=None,page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):
    q=db.query(SoarExecution)
    if status:q=q.filter_by(status=status)
    if mode:q=q.filter_by(mode=mode)
    if playbook_id:q=q.filter_by(playbook_id=playbook_id)
    return service.page(q.order_by(SoarExecution.created_at.desc()),page,page_size)
@router.post("/executions",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def create_execution(payload:ExecutionCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    _bind_current_session(request,actor);_rate(db,SoarExecution,actor.id,100);item=service.create_execution(db,_get(db,SoarPlaybook,payload.playbook_id),payload,actor);_audit(db,request,actor,"execution_requested","soar_execution",item.id,{"mode":item.mode,"status":item.status});return service.row(item)
@router.get("/executions/{execution_id}",dependencies=[Depends(require_permission("soar:view"))])
def execution_details(execution_id:int,db:Session=Depends(get_db)):
    item=_get(db,SoarExecution,execution_id);return {**service.row(item),"events":[service.row(x) for x in db.query(SoarExecutionEvent).filter_by(execution_id=item.id).order_by(SoarExecutionEvent.id).limit(1000)],"steps":[service.row(x) for x in db.query(SoarStepExecution).filter_by(execution_id=item.id).order_by(SoarStepExecution.id).limit(500)],"approvals":[service.row(x) for x in db.query(SoarApproval).filter_by(execution_id=item.id).order_by(SoarApproval.id)],"analyst_inputs":[service.row(x) for x in db.query(SoarAnalystInput).filter_by(execution_id=item.id).order_by(SoarAnalystInput.id)],"evidence":[service.row(x) for x in db.query(SoarExecutionEvidence).filter_by(execution_id=item.id).order_by(SoarExecutionEvidence.id)],"rollbacks":[service.row(x) for x in db.query(SoarRollbackRecord).filter_by(execution_id=item.id).order_by(SoarRollbackRecord.id)]}
@router.get("/executions/{execution_id}/events",dependencies=[Depends(require_permission("soar:view"))])
def events(execution_id:int,db:Session=Depends(get_db)):_get(db,SoarExecution,execution_id);return [service.row(x) for x in db.query(SoarExecutionEvent).filter_by(execution_id=execution_id).order_by(SoarExecutionEvent.id).limit(1000)]
@router.get("/executions/{execution_id}/steps",dependencies=[Depends(require_permission("soar:view"))])
def steps(execution_id:int,db:Session=Depends(get_db)):_get(db,SoarExecution,execution_id);return [service.row(x) for x in db.query(SoarStepExecution).filter_by(execution_id=execution_id).order_by(SoarStepExecution.id).limit(500)]
@router.post("/executions/{execution_id}/resume",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def resume(execution_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    _bind_current_session(request,actor);item=service.run_execution(db,_get(db,SoarExecution,execution_id),actor);_audit(db,request,actor,"execution_resumed","soar_execution",item.id);return service.row(item)
@router.post("/executions/{execution_id}/cancel",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def cancel_execution(execution_id:int,payload:ReasonRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.cancel_execution(db,_get(db,SoarExecution,execution_id),actor,payload.reason);_audit(db,request,actor,"execution_cancelled","soar_execution",item.id);return service.row(item)
@router.post("/executions/{execution_id}/retry",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:execute"))])
def retry_execution(execution_id:int,payload:ReasonRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarExecution,execution_id)
    if item.status!="failed":raise service.error(409,"SOAR_EXECUTION_CONFLICT","Only failed executions can be retried")
    if item.retry_count>=3:raise service.error(409,"SOAR_RETRY_EXHAUSTED","Execution retry limit is exhausted")
    last=db.query(SoarStepExecution).filter_by(execution_id=item.id,status="failed").order_by(SoarStepExecution.id.desc()).first()
    action=ACTION_CATALOG.get(last.action_key) if last and last.action_key else None
    if not last or not action or not action.supports_idempotency or last.error_code not in action.retryable_error_codes:raise service.error(409,"SOAR_RETRY_EXHAUSTED","Failed step or error code is not safely retryable")
    item.retry_count+=1;item.current_step_key=last.step_key;item.status="queued";item.completed_at=None;item.error_code=None;item.error_summary=None;service.event(db,item,"manual_retry_requested",payload.reason,actor_id=actor.id,new="queued",metadata={"retry_count":item.retry_count,"previous_error_code":last.error_code});db.commit();service.run_execution(db,item,actor);_audit(db,request,actor,"execution_retried","soar_execution",item.id);return service.row(item)
@router.post("/executions/{execution_id}/request-rollback",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:rollback"))])
def request_rollback(execution_id:int,payload:ReasonRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    records=service.request_rollbacks(db,_get(db,SoarExecution,execution_id),actor,payload.reason);_audit(db,request,actor,"rollback_requested","soar_execution",execution_id,{"records":len(records)});return [service.row(x) for x in records]


@router.get("/approvals",dependencies=[Depends(require_permission("soar:view"))])
def approvals(status:str|None=None,approval_type:str|None=None,page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):
    q=db.query(SoarApproval)
    if status:q=q.filter_by(status=status)
    if approval_type:q=q.filter_by(approval_type=approval_type)
    return service.page(q.order_by(SoarApproval.created_at.desc()),page,page_size)
@router.get("/approvals/{approval_id}",dependencies=[Depends(require_permission("soar:view"))])
def approval_details(approval_id:int,db:Session=Depends(get_db)):
    item=_get(db,SoarApproval,approval_id);return {**service.row(item),"decisions":[service.row(x) for x in db.query(SoarApprovalDecision).filter_by(approval_id=item.id).order_by(SoarApprovalDecision.id)]}
def _decide(approval_id:int,payload:DecisionRequest,decision:str,request:Request,db:Session,actor:UserAccount):
    _bind_current_session(request,actor);item=service.decide_approval(db,_get(db,SoarApproval,approval_id),actor,decision,payload.note);_audit(db,request,actor,f"approval_{decision}","soar_approval",item.id,{"type":item.approval_type});return service.row(item)
@router.post("/approvals/{approval_id}/approve",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:approve"))])
def approve(approval_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _decide(approval_id,payload,"approve",request,db,actor)
@router.post("/approvals/{approval_id}/reject",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:approve"))])
def reject(approval_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return _decide(approval_id,payload,"reject",request,db,actor)
@router.post("/approvals/{approval_id}/cancel",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:approve"))])
def cancel_approval(approval_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarApproval,approval_id)
    if item.status not in {"pending","partially_approved"}:raise service.error(409,"SOAR_APPROVAL_ALREADY_DECIDED","Approval is not pending")
    item.status="cancelled";db.commit();_audit(db,request,actor,"approval_cancelled","soar_approval",item.id);return service.row(item)


@router.get("/analyst-inputs",dependencies=[Depends(require_permission("soar:view"))])
def analyst_inputs(status:str|None=None,page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):
    q=db.query(SoarAnalystInput)
    if status:q=q.filter_by(status=status)
    return service.page(q.order_by(SoarAnalystInput.requested_at.desc()),page,page_size)
@router.get("/analyst-inputs/{input_id}",dependencies=[Depends(require_permission("soar:view"))])
def analyst_input(input_id:int,db:Session=Depends(get_db)):return service.row(_get(db,SoarAnalystInput,input_id))
@router.post("/analyst-inputs/{input_id}/submit",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:review"))])
def submit_input(input_id:int,payload:AnalystInputSubmit,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.submit_analyst_input(db,_get(db,SoarAnalystInput,input_id),actor,payload.response);_audit(db,request,actor,"analyst_input_submitted","soar_analyst_input",item.id,{"field_names":sorted(payload.response)});return service.row(item)
@router.post("/analyst-inputs/{input_id}/cancel",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:review"))])
def cancel_input(input_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarAnalystInput,input_id)
    if item.status!="pending":raise service.error(409,"SOAR_ANALYST_INPUT_INVALID","Input is no longer pending")
    item.status="cancelled";db.commit();_audit(db,request,actor,"analyst_input_cancelled","soar_analyst_input",item.id);return service.row(item)


@router.get("/rollbacks",dependencies=[Depends(require_permission("soar:view"))])
def rollbacks(status:str|None=None,page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):
    q=db.query(SoarRollbackRecord)
    if status:q=q.filter_by(status=status)
    return service.page(q.order_by(SoarRollbackRecord.created_at.desc()),page,page_size)
@router.get("/rollbacks/{rollback_id}",dependencies=[Depends(require_permission("soar:view"))])
def rollback_details(rollback_id:int,db:Session=Depends(get_db)):return service.row(_get(db,SoarRollbackRecord,rollback_id))
@router.post("/rollbacks/{rollback_id}/approve",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:rollback"))])
def approve_rollback(rollback_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarRollbackRecord,rollback_id)
    if item.status!="waiting_approval":raise service.error(409,"SOAR_ROLLBACK_CONFLICT","Rollback is not awaiting approval")
    if item.requested_by_user_id==actor.id and db.query(UserAccount).filter(UserAccount.status=="active",UserAccount.id!=actor.id,UserAccount.is_system_admin.is_(True)).count():raise service.error(403,"SOAR_APPROVAL_NOT_ELIGIBLE","Rollback requester cannot self-approve while another Administrator is eligible")
    item.status="approved";item.approved_by_user_id=actor.id;db.commit();_audit(db,request,actor,"rollback_approved","soar_rollback",item.id);return service.row(item)
@router.post("/rollbacks/{rollback_id}/execute",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:rollback"))])
def execute_rollback(rollback_id:int,payload:RollbackExecute,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.execute_rollback(db,_get(db,SoarRollbackRecord,rollback_id),actor);_audit(db,request,actor,"rollback_executed","soar_rollback",item.id,{"status":item.status});return service.row(item)
@router.post("/rollbacks/{rollback_id}/cancel",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:rollback"))])
def cancel_rollback(rollback_id:int,payload:DecisionRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,SoarRollbackRecord,rollback_id)
    if item.status not in {"proposed","waiting_approval","approved"}:raise service.error(409,"SOAR_ROLLBACK_CONFLICT","Rollback cannot be cancelled")
    item.status="cancelled";item.completed_at=service.utcnow();db.commit();_audit(db,request,actor,"rollback_cancelled","soar_rollback",item.id);return service.row(item)


@router.get("/reports",dependencies=[Depends(require_permission("soar:export"))])
def reports(page:int=Query(1,ge=1),page_size:int=Query(50,ge=1,le=100),db:Session=Depends(get_db)):return service.page(db.query(SoarReport).order_by(SoarReport.created_at.desc()),page,page_size)
@router.post("/reports",dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("soar:export"))])
def create_report(payload:ReportCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=report_service.generate(db,payload.title,payload.report_type,payload.filters,actor.id);_audit(db,request,actor,"report_generated","soar_report",item.id,{"report_type":item.report_type});return report_service.details(item)
@router.get("/reports/{report_id}",dependencies=[Depends(require_permission("soar:export"))])
def report_details(report_id:int,db:Session=Depends(get_db)):return report_service.details(_get(db,SoarReport,report_id))
@router.get("/reports/{report_id}/download",dependencies=[Depends(require_permission("soar:export"))])
def download_report(report_id:int,db:Session=Depends(get_db)):
    item=_get(db,SoarReport,report_id);return Response(item.html_content,media_type="text/html",headers={"Content-Disposition":f'attachment; filename="soar-report-{item.id}.html"',"Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
