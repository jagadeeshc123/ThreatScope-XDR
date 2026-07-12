import hashlib,json,time
from datetime import datetime,timezone,timedelta
from sqlalchemy import func
from fastapi import HTTPException
from app import models
from .normalization import normalize,value_hash
from .observation_service import rows
from .redaction import redact
from .risk_engine import entity_risk,match_risk
RULES=[("CORR-001","Domain observed in multiple security modules","domain",2,12),("CORR-002","IP address observed in SOC and another module","ip_address",2,15),("CORR-003","File or attachment hash observed across modules","hash",2,16),("CORR-004","URL hash observed across modules","url_hash",2,14),("CORR-005","Phishing watchlist entity appears in SOC or Document evidence","watch",2,18),("CORR-006","High-severity observations across multiple modules","high",2,18),("CORR-007","Web or API exposure associated with SOC activity","exposure_soc",2,16),("CORR-008","Phishing sender or domain associated with SOC evidence","phish_soc",2,16),("CORR-009","Document indicator associated with Phishing analysis","doc_phish",2,16),("CORR-010","Repeated multi-module entity within time window","repeat",2,12),("CORR-011","Multiple high-confidence findings for one entity","confidence",1,14),("CORR-012","Active local watchlist entity with new observation","watch_new",1,14)]
def now():return datetime.now(timezone.utc)
def activity(db,a,m,e=None):db.add(models.SocActivity(action=a,message=redact(m,500),entity_type="correlation",entity_id=e))
def notify(db,t,m,k,et,e):db.add(models.Notification(title=t,message=redact(m,500),type=k,entity_type=et,entity_id=e))
def seed(db):
 for code,title,_,minimum,_ in RULES:
  existing=db.query(models.CorrelationRule).filter_by(code=code).first()
  if not existing:db.add(models.CorrelationRule(code=code,title=title,description=title+". Analyst validation required; no external enrichment performed.",severity="medium",confidence="medium",minimum_sources=minimum,time_window_hours=24 if code=="CORR-010" else None,configuration_json=json.dumps({"limitations":"Local observations do not prove a real-world attack."})))
  elif code=="CORR-010" and existing.time_window_hours is None:existing.time_window_hours=24
 db.flush()
def sync(db,module=None,maximum=500):
 started=time.perf_counter();seed(db);stats={"source_records_examined":0,"entities_created":0,"entities_updated":0,"observations_created":0,"observations_reused":0,"invalid_values_skipped":0,"redacted_values_skipped":0,"per_module_counts":{},"per_record_type_counts":{},"errors":[]}
 for row in rows(db,module,maximum):
  stats["source_records_examined"]+=1;stats["per_module_counts"][row["source_module"]]=stats["per_module_counts"].get(row["source_module"],0)+1
  stats["per_record_type_counts"][row["source_record_type"]]=stats["per_record_type_counts"].get(row["source_record_type"],0)+1
  kind=row["entity_type"]
  if kind=="url":kind="url_hash"
  try:norm,display=normalize("url" if row["entity_type"]=="url" else kind,row["value"])
  except Exception:stats["invalid_values_skipped"]+=1;continue
  entity=db.query(models.UnifiedEntity).filter_by(entity_type=kind,normalized_value=norm).first()
  if not entity:entity=models.UnifiedEntity(entity_type=kind,normalized_value=norm,value_hash=value_hash(norm),display_value_redacted=redact(display,500),watchlist_match=row["watch"]);db.add(entity);db.flush();stats["entities_created"]+=1
  else:entity.last_seen_at=now();entity.watchlist_match=entity.watchlist_match or row["watch"];stats["entities_updated"]+=1
  fp=hashlib.sha256(f"{row['source_module']}:{row['source_record_type']}:{row['source_record_id']}:{entity.value_hash}".encode()).hexdigest();obs=db.query(models.EntityObservation).filter_by(observation_fingerprint=fp).first()
  if obs:stats["observations_reused"]+=1
  else:db.add(models.EntityObservation(entity_id=entity.id,source_module=row["source_module"],source_record_type=row["source_record_type"],source_record_id=row["source_record_id"],source_internal_route=row["route"] if str(row["route"] or "").startswith("/") else None,title_snapshot=redact(row["title"],500),evidence_snapshot=redact(row["evidence"],1000),severity=row["severity"],confidence=row["confidence"],observation_fingerprint=fp));stats["observations_created"]+=1
 db.flush()
 for e in db.query(models.UnifiedEntity):
  obs=e.observations;e.observation_count=len(obs);e.source_module_count=len({x.source_module for x in obs});e.first_seen_at=min((x.observed_at for x in obs),default=e.created_at);e.last_seen_at=max((x.observed_at for x in obs),default=e.created_at);e.risk_score,e.severity,e.confidence=entity_risk(obs,e.watchlist_match)
 activity(db,"entity_synchronization",f"Local entity sync completed: {stats['observations_created']} new observations.");db.commit();stats["duration_ms"]=round((time.perf_counter()-started)*1000,2);return stats
def applies(rule,e,mods,obs):
 key=rule[2]
 return len(mods)>=rule[3] and ((key=="domain" and e.entity_type in {"domain","hostname","sender_domain"})or(key=="ip_address" and e.entity_type=="ip_address" and "soc_monitor" in mods)or(key=="hash" and e.entity_type in {"file_hash","attachment_hash"})or(key=="url_hash" and e.entity_type=="url_hash")or(key in {"watch","watch_new"} and e.watchlist_match)or(key=="high" and sum(x.severity in {"high","critical"} for x in obs)>=2)or(key=="exposure_soc" and "soc_monitor" in mods and bool(mods&{"web_exposure","api_security"}))or(key=="phish_soc" and {"phishing_defense","soc_monitor"}.issubset(mods))or(key=="doc_phish" and {"document_threat","phishing_defense"}.issubset(mods))or(key=="repeat" and len(obs)>=2)or(key=="confidence" and sum(x.confidence=="high" for x in obs)>=2))
def utc(value):
 if value is None:return now()
 return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
def qualifying_window(obs,hours,minimum_sources):
 unique={x.observation_fingerprint:x for x in obs};ordered=sorted(unique.values(),key=lambda x:utc(x.observed_at));best=[];span=timedelta(hours=hours)
 for index,start in enumerate(ordered):
  window=[x for x in ordered[index:] if utc(x.observed_at)-utc(start.observed_at)<=span]
  if len({x.source_module for x in window})>=minimum_sources and len(window)>len(best):best=window
 return best
def run(db):
 seed(db);enabled={x.code:x for x in db.query(models.CorrelationRule).filter_by(enabled=True)};created=updated=unchanged=0;qualifying_corr10=set()
 for e in db.query(models.UnifiedEntity).filter_by(active=True).limit(2000):
  obs=e.observations;mods={x.source_module for x in obs}
  for rule in RULES:
   if rule[0] not in enabled:continue
   used=obs
   if rule[0]=="CORR-010":
    configured=enabled[rule[0]];used=qualifying_window(obs,configured.time_window_hours or 24,configured.minimum_sources)
    if not used:continue
    qualifying_corr10.add(e.id);used_modules={x.source_module for x in used};earliest=min(utc(x.observed_at) for x in used);latest=max(utc(x.observed_at) for x in used);explain=f"{rule[1]}: configured rolling window {configured.time_window_hours or 24} hours; {len(used)} unique qualifying observations from {len(used_modules)} distinct source modules; earliest {earliest.isoformat()}; latest {latest.isoformat()}. Possible relationship; analyst validation required."
   else:
    if not applies(rule,e,mods,obs):continue
    explain=f"{rule[1]} because {len(obs)} redacted observations from {len(mods)} local modules share entity {e.value_hash[:16]}. Possible relationship; analyst validation required."
   fp=hashlib.sha256(f"{rule[0]}:{e.value_hash}".encode()).hexdigest();score,sev,conf=match_risk(used,e.watchlist_match,rule[4])
   m=db.query(models.CorrelationMatch).filter_by(fingerprint=fp).first()
   if m:m.last_detected_at=now();m.match_score=score;m.explanation=explain;m.source_modules_json=json.dumps(sorted({x.source_module for x in used}));m.observation_ids_json=json.dumps([x.id for x in used]);updated+=1
   else:m=models.CorrelationMatch(rule_code=rule[0],primary_entity_id=e.id,match_key=e.value_hash,title=rule[1],explanation=explain,source_modules_json=json.dumps(sorted({x.source_module for x in used})),observation_ids_json=json.dumps([x.id for x in used]),match_score=score,severity=sev,confidence=conf,fingerprint=fp);db.add(m);db.flush();created+=1
   if not db.query(models.Notification).filter_by(entity_type="correlation_match",entity_id=m.id).first() and sev in {"high","critical"}:notify(db,"High-Risk Correlation Match",m.title,"warning","correlation_match",m.id)
 if "CORR-010" in enabled:
  for stale in db.query(models.CorrelationMatch).filter_by(rule_code="CORR-010",status="new"):
   if stale.primary_entity_id not in qualifying_corr10:stale.status="reviewed";stale.analyst_notes="Historical CORR-010 no longer satisfies the configured rolling window; evidence preserved."
 activity(db,"correlation_run",f"Local correlation completed: {created} new, {updated} refreshed.");db.commit();return {"entities_evaluated":db.query(models.UnifiedEntity).count(),"rules_evaluated":len(enabled),"matches_created":created,"matches_updated":updated,"matches_unchanged":unchanged,"matches_skipped":0,"errors":[],"duration_ms":0}
def case(db,id):
 x=db.query(models.IncidentCase).filter_by(id=id).first()
 if not x:raise HTTPException(404,"Incident case not found")
 return x
def timeline(db,c,t,s,old=None,new=None):db.add(models.IncidentTimelineEvent(case_id=c.id,event_type=t,summary=redact(s,1000),old_value=redact(old,500),new_value=redact(new,500)))
def from_match(db,match_id):
 m=db.query(models.CorrelationMatch).filter_by(id=match_id).first()
 if not m:raise HTTPException(404,"Correlation match not found")
 key="AUTO-"+m.fingerprint[:16];c=db.query(models.IncidentCase).filter_by(case_key=key).first()
 if c:return c
 c=models.IncidentCase(case_key=key,title=m.title,summary=m.explanation,case_type="multi_module_correlation",severity=m.severity,priority="P1" if m.severity in {"critical","high"} else "P2",confidence=m.confidence,risk_score=m.match_score,status="new",source_module_count=len(json.loads(m.source_modules_json)),primary_entity_id=m.primary_entity_id);db.add(c);db.flush()
 for oid in json.loads(m.observation_ids_json):
  o=db.query(models.EntityObservation).filter_by(id=oid).first()
  if o:db.add(models.IncidentEvidence(case_id=c.id,source_module=o.source_module,source_record_type=o.source_record_type,source_record_id=o.source_record_id,source_internal_route=o.source_internal_route,title_snapshot=o.title_snapshot,evidence_snapshot=o.evidence_snapshot,severity=o.severity,confidence=o.confidence,entity_id=o.entity_id,correlation_match_id=m.id,evidence_fingerprint=hashlib.sha256(f"{c.id}:{o.observation_fingerprint}".encode()).hexdigest()))
 db.flush();c.evidence_count=len(json.loads(m.observation_ids_json));timeline(db,c,"case_created","Incident case created from local correlation.");timeline(db,c,"correlation_linked",f"Correlation match {m.id} linked.");m.status="linked_to_case";notify(db,"Incident Case Created",c.title,"warning","incident_case",c.id);activity(db,"case_created",f"Incident case {c.case_key} created.",c.id);db.commit();db.refresh(c);return c
