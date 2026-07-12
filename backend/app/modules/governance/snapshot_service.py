import hashlib,json
from datetime import datetime,timezone,timedelta
from app import models
from .coverage_service import summary as coverage_summary
from .service import activity,dump


def utc(value):return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def metrics(db):
    now=datetime.now(timezone.utc);open_status=["identified","under_review","treatment_planned","treatment_in_progress","accepted","monitoring"]
    risks=db.query(models.GovernanceRisk).all();treatments=db.query(models.RiskTreatmentPlan).all();exceptions=db.query(models.RiskException).all();coverage=coverage_summary(db)
    return {"total_open_risks":sum(x.status in open_status for x in risks),"high_and_critical_risks":sum(x.severity in {"high","critical"} and x.status!="closed" for x in risks),"residual_risk_total":sum(x.residual_score for x in risks if x.status!="closed"),"risks_exceeding_appetite":sum(x.appetite_status=="exceeds_appetite" and x.status!="closed" for x in risks),"overdue_treatments":sum(x.status in {"planned","in_progress"} and x.target_date and utc(x.target_date)<now for x in treatments),"active_exceptions":sum(x.status=="approved" and (not x.expires_at or utc(x.expires_at)>now) for x in exceptions),"supported_controls":sum(x["supported_controls"] for x in coverage),"control_gaps":sum(x["gap_controls"] for x in coverage),"open_incident_cases":db.query(models.IncidentCase).filter(models.IncidentCase.status.notin_(["resolved","closed"])).count(),"p1_cases":db.query(models.IncidentCase).filter(models.IncidentCase.priority=="P1",models.IncidentCase.status.notin_(["resolved","closed"])).count(),"active_correlation_matches":db.query(models.CorrelationMatch).filter(models.CorrelationMatch.status.notin_(["dismissed","reviewed"])).count()}


def capture(db,snapshot_type="manual",metric_date=None,source_label=None):
    metric_date=metric_date or datetime.now(timezone.utc);values=metrics(db);raw=json.dumps(values,sort_keys=True);fingerprint=hashlib.sha256(f"{snapshot_type}:{metric_date.date()}:{source_label or ''}:{raw}".encode()).hexdigest();existing=db.query(models.GovernanceSnapshot).filter_by(source_fingerprint=fingerprint).first()
    if existing:return existing,False
    item=models.GovernanceSnapshot(snapshot_key="SNAP-"+fingerprint[:16],snapshot_type=snapshot_type,metric_date=metric_date,metrics_json=raw,source_fingerprint=fingerprint);db.add(item);db.flush();activity(db,"governance_snapshot_captured",f"Captured aggregate {snapshot_type} governance snapshot.",item.id);return item,True
