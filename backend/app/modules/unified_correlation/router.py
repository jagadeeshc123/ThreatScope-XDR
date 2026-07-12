import json,hashlib
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from sqlalchemy import func,or_
from sqlalchemy.orm import Session
from app import models
from app.database import get_db
from . import service,report_service
from .redaction import redact
router=APIRouter()
SEVERITIES={"info","low","medium","high","critical"};CONFIDENCES={"low","medium","high"};CASE_STATUSES={"new","triage","investigating","awaiting_review","contained_simulated","resolved","closed"};CASE_PRIORITIES={"P1","P2","P3","P4"};CASE_TYPES={"analyst_created","multi_module_correlation","source_investigation","incident"};ACTION_STATUSES={"open","in_progress","completed","cancelled"};ACTION_PRIORITIES={"low","medium","high","critical"}
def choice(value,allowed,label):
 if value not in allowed:raise HTTPException(422,f"Unsupported {label}")
 return value
def strict_bool(value,label):
 if not isinstance(value,bool):raise HTTPException(422,f"{label} must be a boolean")
 return value
def parsed_date(value,label):
 if value in {None,""}:return None
 try:return datetime.fromisoformat(str(value).replace("Z","+00:00"))
 except ValueError:raise HTTPException(422,f"{label} must be a valid ISO timestamp")
def dump(x):
 d={k:v for k,v in x.__dict__.items() if not k.startswith("_")}
 for k in list(d):
  if k.endswith("_json"):d[k[:-5]]=json.loads(d[k] or "[]")
 return d
@router.get("/overview")
def overview(db:Session=Depends(get_db)):
 open_status=["new","triage","investigating","awaiting_review","contained_simulated"];recent_m=db.query(models.CorrelationMatch).order_by(models.CorrelationMatch.updated_at.desc()).limit(8).all();recent_c=db.query(models.IncidentCase).order_by(models.IncidentCase.updated_at.desc()).limit(8).all();return {"total_entities":db.query(models.UnifiedEntity).count(),"multi_module_entities":db.query(models.UnifiedEntity).filter(models.UnifiedEntity.source_module_count>1).count(),"high_risk_entities":db.query(models.UnifiedEntity).filter_by(severity="high").count(),"critical_risk_entities":db.query(models.UnifiedEntity).filter_by(severity="critical").count(),"active_matches":db.query(models.CorrelationMatch).filter(models.CorrelationMatch.status!="dismissed").count(),"new_matches":db.query(models.CorrelationMatch).filter_by(status="new").count(),"open_cases":db.query(models.IncidentCase).filter(models.IncidentCase.status.in_(open_status)).count(),"p1_cases":db.query(models.IncidentCase).filter_by(priority="P1").count(),"high_critical_cases":db.query(models.IncidentCase).filter(models.IncidentCase.severity.in_(["high","critical"])).count(),"cases_awaiting_review":db.query(models.IncidentCase).filter_by(status="awaiting_review").count(),"resolved_cases":db.query(models.IncidentCase).filter_by(status="resolved").count(),"active_action_items":db.query(models.IncidentActionItem).filter(models.IncidentActionItem.status.in_(["open","in_progress"])).count(),"entities_by_type":dict(db.query(models.UnifiedEntity.entity_type,func.count()).group_by(models.UnifiedEntity.entity_type).all()),"observations_by_module":dict(db.query(models.EntityObservation.source_module,func.count()).group_by(models.EntityObservation.source_module).all()),"matches_by_rule":dict(db.query(models.CorrelationMatch.rule_code,func.count()).group_by(models.CorrelationMatch.rule_code).all()),"cases_by_status":dict(db.query(models.IncidentCase.status,func.count()).group_by(models.IncidentCase.status).all()),"recent_matches":[dump(x) for x in recent_m],"recent_cases":[dump(x) for x in recent_c]}
@router.post("/entities/sync")
def sync(source_module:str|None=None,maximum_records:int=Query(500,ge=1,le=5000),db:Session=Depends(get_db)):return service.sync(db,source_module,maximum_records)
@router.get("/entities")
def entities(page:int=Query(1,ge=1),page_size:int=Query(25,ge=1,le=100),entity_type:str|None=None,severity:str|None=None,confidence:str|None=None,min_risk:float|None=Query(None,ge=0,le=100),source_module:str|None=None,watchlist_match:bool|None=None,first_seen_from:datetime|None=None,first_seen_to:datetime|None=None,last_seen_from:datetime|None=None,last_seen_to:datetime|None=None,q:str|None=Query(None,max_length=200),db:Session=Depends(get_db)):
 query=db.query(models.UnifiedEntity)
 if first_seen_from and first_seen_to and first_seen_from>first_seen_to:raise HTTPException(422,"Invalid first-seen range")
 if last_seen_from and last_seen_to and last_seen_from>last_seen_to:raise HTTPException(422,"Invalid last-seen range")
 if entity_type:query=query.filter_by(entity_type=entity_type)
 if severity:query=query.filter_by(severity=severity)
 if confidence:query=query.filter_by(confidence=confidence)
 if min_risk is not None:query=query.filter(models.UnifiedEntity.risk_score>=min_risk)
 if source_module:query=query.filter(models.UnifiedEntity.observations.any(models.EntityObservation.source_module==source_module))
 if watchlist_match is not None:query=query.filter_by(watchlist_match=watchlist_match)
 if first_seen_from:query=query.filter(models.UnifiedEntity.first_seen_at>=first_seen_from)
 if first_seen_to:query=query.filter(models.UnifiedEntity.first_seen_at<=first_seen_to)
 if last_seen_from:query=query.filter(models.UnifiedEntity.last_seen_at>=last_seen_from)
 if last_seen_to:query=query.filter(models.UnifiedEntity.last_seen_at<=last_seen_to)
 if q:query=query.filter(or_(models.UnifiedEntity.display_value_redacted.ilike(f"%{q}%"),models.UnifiedEntity.value_hash.ilike(f"%{q}%")))
 return {"items":[dump(x) for x in query.order_by(models.UnifiedEntity.last_seen_at.desc()).offset((page-1)*page_size).limit(page_size)],"total":query.count(),"page":page,"page_size":page_size}
@router.get("/entities/{entity_id}")
def entity(entity_id:int,db:Session=Depends(get_db)):
 x=db.query(models.UnifiedEntity).filter_by(id=entity_id).first()
 if not x:raise HTTPException(404,"Entity not found")
 return dump(x)|{"observations":[dump(o) for o in x.observations],"matches":[dump(m) for m in db.query(models.CorrelationMatch).filter_by(primary_entity_id=x.id)],"cases":[dump(c) for c in db.query(models.IncidentCase).filter_by(primary_entity_id=x.id)]}
@router.get("/entities/{entity_id}/observations")
def observations(entity_id:int,db:Session=Depends(get_db)):return [dump(x) for x in db.query(models.EntityObservation).filter_by(entity_id=entity_id)]
@router.get("/entities/{entity_id}/relationships")
def relationships(entity_id:int,db:Session=Depends(get_db)):return entity(entity_id,db)
@router.post("/matches/run")
def run(db:Session=Depends(get_db)):return service.run(db)
@router.get("/rules")
def rules(db:Session=Depends(get_db)):service.seed(db);db.commit();return [dump(x) for x in db.query(models.CorrelationRule).order_by(models.CorrelationRule.code)]
@router.patch("/rules/{rule_id}")
def update_rule(rule_id:int,payload:dict,db:Session=Depends(get_db)):
 x=db.query(models.CorrelationRule).filter_by(id=rule_id).first()
 if not x:raise HTTPException(404,"Correlation rule not found")
 if "enabled" in payload:x.enabled=strict_bool(payload["enabled"],"enabled")
 db.commit();db.refresh(x);return dump(x)
@router.delete("/rules/{rule_id}")
def delete_rule(rule_id:int,db:Session=Depends(get_db)):
 x=db.query(models.CorrelationRule).filter_by(id=rule_id).first()
 if not x:raise HTTPException(404,"Correlation rule not found")
 if x.default_rule:raise HTTPException(409,"Default correlation rules cannot be deleted")
 db.delete(x);db.commit();return {"ok":True}
@router.get("/matches")
def matches(page:int=Query(1,ge=1),page_size:int=Query(100,ge=1,le=200),rule_code:str|None=None,status:str|None=None,severity:str|None=None,confidence:str|None=None,min_score:float|None=Query(None,ge=0,le=100),source_module:str|None=None,date_from:datetime|None=None,date_to:datetime|None=None,db:Session=Depends(get_db)):
 q=db.query(models.CorrelationMatch)
 if date_from and date_to and date_from>date_to:raise HTTPException(422,"Invalid match date range")
 if rule_code:q=q.filter_by(rule_code=rule_code)
 if status:q=q.filter_by(status=status)
 if severity:q=q.filter_by(severity=severity)
 if confidence:q=q.filter_by(confidence=confidence)
 if min_score is not None:q=q.filter(models.CorrelationMatch.match_score>=min_score)
 if source_module:q=q.filter(models.CorrelationMatch.source_modules_json.ilike(f'%"{source_module}"%'))
 if date_from:q=q.filter(models.CorrelationMatch.updated_at>=date_from)
 if date_to:q=q.filter(models.CorrelationMatch.updated_at<=date_to)
 return [dump(x) for x in q.order_by(models.CorrelationMatch.updated_at.desc()).offset((page-1)*page_size).limit(page_size)]
@router.get("/matches/{match_id}")
def match(match_id:int,db:Session=Depends(get_db)):
 x=db.query(models.CorrelationMatch).filter_by(id=match_id).first()
 if not x:raise HTTPException(404,"Match not found")
 return dump(x)
@router.patch("/matches/{match_id}")
def update_match(match_id:int,payload:dict,db:Session=Depends(get_db)):
 x=db.query(models.CorrelationMatch).filter_by(id=match_id).first()
 if not x:raise HTTPException(404,"Match not found")
 if "status" in payload:x.status=choice(payload["status"],{"new","reviewed","linked_to_case","dismissed"},"match status")
 if "analyst_notes" in payload:x.analyst_notes=redact(payload["analyst_notes"],4000)
 service.activity(db,"match_updated",f"Correlation match {x.id} updated.",x.id);db.commit();db.refresh(x);return dump(x)
@router.post("/matches/{match_id}/create-case")
@router.post("/cases/from-match/{match_id}")
def from_match(match_id:int,db:Session=Depends(get_db)):return dump(service.from_match(db,match_id))
@router.post("/cases")
def create_case(payload:dict,db:Session=Depends(get_db)):
 c=build_case(db,payload);db.commit();db.refresh(c);return dump(c)
def build_case(db,payload):
 title=redact(payload.get("title","Analyst-created case"),240)
 if not title or not title.strip():raise HTTPException(422,"Case title is required")
 case_type=choice(payload.get("case_type","analyst_created"),CASE_TYPES,"case type");severity=choice(payload.get("severity","medium"),SEVERITIES,"case severity");priority=choice(payload.get("priority","P3"),CASE_PRIORITIES,"case priority");confidence=choice(payload.get("confidence","medium"),CONFIDENCES,"case confidence")
 try:risk_score=float(payload.get("risk_score",40))
 except (TypeError,ValueError):raise HTTPException(422,"Risk score must be a number from 0 to 100")
 if not 0<=risk_score<=100:raise HTTPException(422,"Risk score must be between 0 and 100")
 tags=payload.get("tags",[])
 if not isinstance(tags,list):raise HTTPException(422,"Tags must be a list")
 key="CASE-"+hashlib.sha256(f"{datetime.now(timezone.utc).isoformat()}:{title}".encode()).hexdigest()[:12];c=models.IncidentCase(case_key=key,title=title,summary=redact(payload.get("summary",""),2000),case_type=case_type,severity=severity,priority=priority,confidence=confidence,risk_score=risk_score,status="new",assignee_name=redact(payload.get("assignee_name"),200),tags_json=json.dumps(tags));db.add(c);db.flush();service.timeline(db,c,"case_created","Analyst-created incident case.");service.activity(db,"case_created",f"Incident case {key} created.",c.id);service.notify(db,"Incident Case Created",c.title,"info","incident_case",c.id);return c
def add_observation_evidence(db,c,payload):
 allowed={"web_exposure","api_security","soc_monitor","document_threat","phishing_defense"};module=payload.get("source_module")
 if module not in allowed:raise HTTPException(422,"Unsupported source module")
 o=db.query(models.EntityObservation).filter_by(source_module=module,source_record_type=payload.get("source_record_type"),source_record_id=payload.get("source_record_id")).first()
 if not o:raise HTTPException(404,"Allowlisted source observation not found; synchronize entities first")
 fp=hashlib.sha256(f"{c.id}:{o.observation_fingerprint}".encode()).hexdigest();existing=db.query(models.IncidentEvidence).filter_by(evidence_fingerprint=fp).first()
 if existing:return existing
 x=models.IncidentEvidence(case_id=c.id,source_module=o.source_module,source_record_type=o.source_record_type,source_record_id=o.source_record_id,source_internal_route=o.source_internal_route,title_snapshot=o.title_snapshot,evidence_snapshot=o.evidence_snapshot,severity=o.severity,confidence=o.confidence,entity_id=o.entity_id,evidence_fingerprint=fp);db.add(x);db.flush();c.evidence_count+=1;c.source_module_count=len({e.source_module for e in c.evidence}|{o.source_module});service.timeline(db,c,"evidence_added",f"Safe snapshot added from {o.source_module}.");service.activity(db,"evidence_added",f"Evidence added to {c.case_key}.",c.id);return x
@router.post("/cases/from-source")
def from_source(payload:dict,db:Session=Depends(get_db)):
 c_payload={"title":payload.get("title","Source investigation"),"summary":payload.get("summary","Created from an allowlisted local source observation."),"case_type":payload.get("case_type","source_investigation")};c=build_case(db,c_payload)
 try:add_observation_evidence(db,c,payload)
 except Exception:db.rollback();raise
 db.commit();db.refresh(c);return dump(c)
@router.get("/cases")
def cases(page:int=Query(1,ge=1),page_size:int=Query(100,ge=1,le=200),status:str|None=None,severity:str|None=None,priority:str|None=None,confidence:str|None=None,case_type:str|None=None,assignee:str|None=None,entity_id:int|None=None,source_module:str|None=None,date_from:datetime|None=None,date_to:datetime|None=None,q:str|None=Query(None,max_length=200),db:Session=Depends(get_db)):
 query=db.query(models.IncidentCase)
 if date_from and date_to and date_from>date_to:raise HTTPException(422,"Invalid case date range")
 if status:query=query.filter_by(status=status)
 if severity:query=query.filter_by(severity=severity)
 if priority:query=query.filter_by(priority=priority)
 if confidence:query=query.filter_by(confidence=confidence)
 if case_type:query=query.filter_by(case_type=case_type)
 if assignee:query=query.filter(models.IncidentCase.assignee_name.ilike(f"%{assignee}%"))
 if entity_id is not None:query=query.filter(or_(models.IncidentCase.primary_entity_id==entity_id,models.IncidentCase.evidence.any(models.IncidentEvidence.entity_id==entity_id)))
 if source_module:query=query.filter(models.IncidentCase.evidence.any(models.IncidentEvidence.source_module==source_module))
 if date_from:query=query.filter(models.IncidentCase.updated_at>=date_from)
 if date_to:query=query.filter(models.IncidentCase.updated_at<=date_to)
 if q:query=query.filter(or_(models.IncidentCase.title.ilike(f"%{q}%"),models.IncidentCase.case_key.ilike(f"%{q}%")))
 return [dump(x) for x in query.order_by(models.IncidentCase.updated_at.desc()).offset((page-1)*page_size).limit(page_size)]
@router.get("/cases/{case_id}")
def get_case(case_id:int,db:Session=Depends(get_db)):
 c=service.case(db,case_id);return dump(c)|{"evidence":[dump(x) for x in c.evidence],"timeline":[dump(x) for x in c.timeline],"notes":[dump(x) for x in c.notes],"actions":[dump(x) for x in c.actions],"reports":[dump(x) for x in c.reports]}
@router.patch("/cases/{case_id}")
def update_case(case_id:int,payload:dict,db:Session=Depends(get_db)):
 c=service.case(db,case_id)
 for field,allowed,label in (("status",CASE_STATUSES,"case status"),("severity",SEVERITIES,"case severity"),("priority",CASE_PRIORITIES,"case priority"),("confidence",CONFIDENCES,"case confidence")):
  if field in payload:choice(payload[field],allowed,label)
 if "title" in payload and not (redact(payload["title"],240) or "").strip():raise HTTPException(422,"Case title is required")
 if payload.get("status") in {"resolved","closed"} and not payload.get("resolution_summary",c.resolution_summary):raise HTTPException(422,"Resolution summary is required")
 for k in ("title","summary","status","severity","priority","confidence","assignee_name","resolution_summary"):
  if k in payload:
   old=getattr(c,k);setattr(c,k,redact(payload[k],2000));
   if old!=getattr(c,k):service.timeline(db,c,"status_changed" if k=="status" else f"{k.replace('_name','')}_changed",f"Case {k} changed.",old,getattr(c,k))
   if k=="assignee_name" and old!=getattr(c,k):service.notify(db,"Incident Case Assigned",f"{c.case_key} assigned to {c.assignee_name}.","info","incident_case",c.id)
   if k=="priority" and c.priority=="P1" and old!="P1":service.notify(db,"Incident Case Priority P1",f"{c.case_key} moved to P1.","warning","incident_case",c.id)
   if k=="status" and c.status=="awaiting_review" and old!="awaiting_review":service.notify(db,"Incident Case Awaiting Review",f"{c.case_key} awaits analyst review.","warning","incident_case",c.id)
 if c.status in {"resolved","closed"}:c.closed_at=datetime.now(timezone.utc);service.notify(db,"Incident Case Resolved",c.title,"success","incident_case",c.id)
 elif c.closed_at:c.closed_at=None;service.timeline(db,c,"case_reopened","Case reopened.")
 service.activity(db,"case_updated",f"Incident case {c.case_key} updated.",c.id);db.commit();db.refresh(c);return dump(c)
@router.delete("/cases/{case_id}")
def delete_case(case_id:int,db:Session=Depends(get_db)):c=service.case(db,case_id);key=c.case_key;db.delete(c);service.activity(db,"case_deleted",f"Incident case {key} deleted; source records preserved.",case_id);db.commit();return {"ok":True}
@router.get("/cases/{case_id}/evidence")
def evidence(case_id:int,db:Session=Depends(get_db)):return [dump(x) for x in service.case(db,case_id).evidence]
@router.post("/cases/{case_id}/evidence")
def add_evidence(case_id:int,payload:dict,db:Session=Depends(get_db)):c=service.case(db,case_id);x=add_observation_evidence(db,c,payload);db.commit();db.refresh(x);return dump(x)
@router.delete("/cases/{case_id}/evidence/{evidence_id}")
def delete_evidence(case_id:int,evidence_id:int,db:Session=Depends(get_db)):
 c=service.case(db,case_id);x=db.query(models.IncidentEvidence).filter_by(id=evidence_id,case_id=case_id).first()
 if not x:raise HTTPException(404,"Case evidence not found")
 db.delete(x);c.evidence_count=max(0,c.evidence_count-1);service.timeline(db,c,"evidence_removed","Case evidence snapshot removed; source record preserved.");service.activity(db,"evidence_removed",f"Evidence removed from {c.case_key}; source preserved.",c.id);db.commit();return {"ok":True}
@router.get("/cases/{case_id}/notes")
def notes(case_id:int,db:Session=Depends(get_db)):return [dump(x) for x in service.case(db,case_id).notes]
@router.post("/cases/{case_id}/notes")
def add_note(case_id:int,payload:dict,db:Session=Depends(get_db)):c=service.case(db,case_id);x=models.IncidentNote(case_id=c.id,note_text=redact(payload.get("note_text"),5000),author_label=redact(payload.get("author_label","Local analyst"),100));db.add(x);db.flush();service.timeline(db,c,"note_added","Redacted analyst note added.");db.commit();db.refresh(x);return dump(x)
@router.patch("/cases/{case_id}/notes/{note_id}")
def edit_note(case_id:int,note_id:int,payload:dict,db:Session=Depends(get_db)):
 service.case(db,case_id);x=db.query(models.IncidentNote).filter_by(id=note_id,case_id=case_id).first()
 if not x:raise HTTPException(404,"Case note not found")
 x.note_text=redact(payload.get("note_text"),5000);db.commit();return dump(x)
@router.delete("/cases/{case_id}/notes/{note_id}")
def delete_note(case_id:int,note_id:int,db:Session=Depends(get_db)):
 service.case(db,case_id);x=db.query(models.IncidentNote).filter_by(id=note_id,case_id=case_id).first()
 if not x:raise HTTPException(404,"Case note not found")
 db.delete(x);db.commit();return {"ok":True}
@router.get("/cases/{case_id}/actions")
def actions(case_id:int,db:Session=Depends(get_db)):return [dump(x) for x in service.case(db,case_id).actions]
@router.post("/actions/check-overdue")
def check_overdue(db:Session=Depends(get_db)):
 checked=datetime.now(timezone.utc);items=db.query(models.IncidentActionItem).filter(models.IncidentActionItem.status.in_(["open","in_progress"]),models.IncidentActionItem.due_at.is_not(None)).all();found=created=reused=0;errors=[]
 for action in items:
  try:
   due=action.due_at.replace(tzinfo=timezone.utc) if action.due_at.tzinfo is None else action.due_at.astimezone(timezone.utc)
   if due>=checked:continue
   found+=1;case=service.case(db,action.case_id);lifecycle=hashlib.sha256(f"{action.id}:{due.isoformat()}".encode()).hexdigest()[:16];title=f"Overdue Incident Action #{action.id}";message=redact(f"{case.case_key}: {action.title} is overdue. lifecycle={lifecycle}",500)
   existing=db.query(models.Notification).filter_by(title=title,message=message,entity_type="incident_case",entity_id=case.id).first()
   if existing:reused+=1
   else:service.notify(db,title,message,"warning","incident_case",case.id);created+=1
  except Exception as exc:errors.append(redact(exc,200))
 db.commit();return {"actions_examined":len(items),"overdue_actions_found":found,"notifications_created":created,"notifications_reused":reused,"errors":errors,"checked_at":checked}
@router.post("/cases/{case_id}/actions")
def add_action(case_id:int,payload:dict,db:Session=Depends(get_db)):
 c=service.case(db,case_id);title=redact(payload.get("title"),240)
 if not title or not title.strip():raise HTTPException(422,"Action title is required")
 x=models.IncidentActionItem(case_id=c.id,title=title,description=redact(payload.get("description"),2000),priority=choice(payload.get("priority","medium"),ACTION_PRIORITIES,"action priority"),assignee_name=redact(payload.get("assignee_name"),200),due_at=parsed_date(payload.get("due_at"),"due_at"));db.add(x);db.flush();service.timeline(db,c,"action_item_added","Analyst workflow action item added; no execution occurs.");db.commit();db.refresh(x);return dump(x)
@router.patch("/cases/{case_id}/actions/{action_id}")
def update_action(case_id:int,action_id:int,payload:dict,db:Session=Depends(get_db)):
 c=service.case(db,case_id);x=db.query(models.IncidentActionItem).filter_by(id=action_id,case_id=case_id).first()
 if not x:raise HTTPException(404,"Case action item not found")
 if "status" in payload:choice(payload["status"],ACTION_STATUSES,"action status")
 if "priority" in payload:choice(payload["priority"],ACTION_PRIORITIES,"action priority")
 if "title" in payload and not (redact(payload["title"],240) or "").strip():raise HTTPException(422,"Action title is required")
 for k,v in payload.items():
  if k in {"title","description","assignee_name"}:setattr(x,k,redact(v,2000))
  elif k=="due_at":x.due_at=parsed_date(v,"due_at")
  elif k in {"status","priority"}:setattr(x,k,v)
 x.completed_at=datetime.now(timezone.utc) if x.status=="completed" else None;service.timeline(db,c,"action_item_updated",f"Action item {x.id} updated; no automated execution occurred.");service.activity(db,"action_item_updated",f"Workflow task {x.id} updated.",c.id);db.commit();return dump(x)
@router.delete("/cases/{case_id}/actions/{action_id}")
def delete_action(case_id:int,action_id:int,db:Session=Depends(get_db)):
 service.case(db,case_id);x=db.query(models.IncidentActionItem).filter_by(id=action_id,case_id=case_id).first()
 if not x:raise HTTPException(404,"Case action item not found")
 db.delete(x);db.commit();return {"ok":True}
@router.get("/cases/{case_id}/timeline")
def timeline(case_id:int,db:Session=Depends(get_db)):return [dump(x) for x in service.case(db,case_id).timeline]
@router.post("/cases/{case_id}/reports")
def create_report(case_id:int,db:Session=Depends(get_db)):return dump(report_service.generate(db,service.case(db,case_id)))
@router.get("/reports")
def reports(db:Session=Depends(get_db)):return [dump(x) for x in db.query(models.IncidentReport).order_by(models.IncidentReport.created_at.desc())]
@router.get("/reports/{report_id}")
def report(report_id:int,db:Session=Depends(get_db)):
 x=db.query(models.IncidentReport).filter_by(id=report_id).first()
 if not x:raise HTTPException(404,"Report not found")
 return dump(x)
@router.get("/reports/{report_id}/download")
def download(report_id:int,db:Session=Depends(get_db)):
 x=db.query(models.IncidentReport).filter_by(id=report_id).first()
 if not x:raise HTTPException(404,"Report not found")
 return Response(x.html_content,media_type="text/html",headers={"Content-Disposition":f"attachment; filename=incident-report-{x.id}.html"})
