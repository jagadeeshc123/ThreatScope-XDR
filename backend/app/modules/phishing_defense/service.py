import hashlib, json
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import Parser
from email.utils import getaddresses
from sqlalchemy import func
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app import models
from .email_parser import build_features, message_fields, parse_eml
from .findings_engine import build as build_findings
from .model_service import predict
from .redaction import bounded, redact_email, redact_recursive, redact_text, sanitize_url
from .risk_engine import METHODOLOGY, score
from .url_analyzer import analyze_url

OFFLINE="Offline phishing risk analysis — no links, domains, attachments, or external services were contacted."
def utcnow():return datetime.now(timezone.utc)
def activity(db,action,message,entity_id=None):db.add(models.SocActivity(action=action,message=redact_text(message,500),entity_type="phishing_analysis",entity_id=entity_id))
def notify(db,title,message,kind,entity_type,entity_id):db.add(models.Notification(title=title,message=redact_text(message,500),type=kind,entity_type=entity_type,entity_id=entity_id))
def get_analysis(db,id):
    item=db.query(models.PhishingAnalysis).filter_by(id=id).first()
    if not item:raise HTTPException(404,"Phishing analysis not found")
    return item
def analysis_read(item,duplicate=False):
    keys=("id","source_type","source_hash","filename_sanitized","subject_redacted","sender_display_redacted","sender_address_redacted","reply_to_redacted","return_path_redacted","recipient_count","url_count","attachment_count","html_present","authentication_results_present","bounded_text_character_count","model_probability","model_label","heuristic_score","final_risk_score","classification","confidence","analyst_disposition","analyst_notes","analysis_status","methodology","error_summary","created_at","completed_at")
    return {k:getattr(item,k) for k in keys}|{"header_summary_json":json.loads(item.header_summary_json or "{}"),"feature_summary_json":json.loads(item.feature_summary_json or "{}"),"duplicate_existing":duplicate}
def report_read(item):return {"id":item.id,"analysis_id":item.analysis_id,"title":item.title,"html_content":item.html_content,"summary_json":json.loads(item.summary_json),"created_at":item.created_at}
def record_failure(db,source_type,source_hash,error,filename=None):
    existing=db.query(models.PhishingAnalysis).filter_by(source_hash=source_hash).first()
    if existing:return existing
    item=models.PhishingAnalysis(source_type=source_type,source_hash=source_hash,filename_sanitized=filename,analysis_status="failed",classification="unknown",confidence="low",methodology=METHODOLOGY+" "+OFFLINE,error_summary=redact_text(error,500),completed_at=utcnow());db.add(item);db.flush();activity(db,"phishing_analysis_failed",f"Offline phishing analysis {item.id} failed safely.",item.id);notify(db,"Phishing Analysis Failed",f"Offline analysis {item.id} could not be completed safely.","danger","phishing_analysis",item.id);db.commit();db.refresh(item);return item

def _complete(db,source_type,source_hash,features,identity,filename=None):
    existing=db.query(models.PhishingAnalysis).filter_by(source_hash=source_hash).first()
    if existing:activity(db,"duplicate_phishing_input",f"Duplicate offline submission matched analysis {existing.id}.",existing.id);db.commit();return analysis_read(existing,True)
    model=predict(features["bounded_text"]); normalized_values={u["normalized"] for u in features["urls"]}|{u["host"] for u in features["urls"] if u["host"]}|{u["raw_hash"] for u in features["urls"]}|{a["sha256"] for a in features["attachments"] if a.get("sha256")}
    parsed_sender=(getaddresses([identity.get("sender","")]) or [("","")])[0];sender_addr=identity.get("sender_address") or parsed_sender[1];sender_name=identity.get("sender_name") or parsed_sender[0]
    if sender_addr:normalized_values.add(sender_addr.lower())
    watch=db.query(models.PhishingWatchlistEntry).filter(models.PhishingWatchlistEntry.status=="active",models.PhishingWatchlistEntry.normalized_value.in_(normalized_values)).count() if normalized_values else 0
    result=score(features,model["probability"],watch); item=models.PhishingAnalysis(source_type=source_type,source_hash=source_hash,filename_sanitized=filename,subject_redacted=redact_text(identity.get("subject"),500),sender_display_redacted=redact_text(sender_name,300),sender_address_redacted=redact_email(sender_addr),reply_to_redacted=redact_email(identity.get("reply_to")),return_path_redacted=redact_email(identity.get("return_path")),recipient_count=identity.get("recipient_count",0),url_count=len(features["urls"]),attachment_count=len(features["attachments"]),html_present=bool(features["html"].get("visible_text") or features["html"].get("links")),authentication_results_present=features["headers"].get("authentication_results_present",False),header_summary_json=json.dumps(redact_recursive(features["headers"]),sort_keys=True),feature_summary_json=json.dumps(redact_recursive({"text":features["text"],"html":{k:v for k,v in features["html"].items() if k not in {"visible_text","links"}},"top_contributing_features":result["top_contributing_features"]}),sort_keys=True),bounded_text_character_count=len(features["bounded_text"]),model_probability=model["probability"],model_label=model["label"],heuristic_score=result["heuristic_score"],final_risk_score=result["final_risk_score"],classification=result["classification"],confidence=result["confidence"],analysis_status="completed",methodology=METHODOLOGY+" "+OFFLINE,completed_at=utcnow())
    db.add(item);db.flush();findings=build_findings(source_hash,features,model["probability"],watch)
    seen=set()
    for u in features["urls"][:200]:
        kind="ip" if u["flags"]["ip_literal"] else "url";key=(kind,u["normalized"])
        if key not in seen:db.add(models.PhishingIndicator(analysis_id=item.id,indicator_type=kind,normalized_value=u["normalized"],display_value_redacted=u["display"],context="Sanitized inert URL text; destination was not contacted.",severity="medium" if u["score"]>=12 else "info",confidence="high" if u["flags"]["ip_literal"] else "medium",source_location=u["source"]));seen.add(key)
        key=("domain",u["host"])
        if u["host"] and key not in seen:db.add(models.PhishingIndicator(analysis_id=item.id,indicator_type="domain",normalized_value=u["host"],display_value_redacted=u["host"],context="Hostname parsed locally without DNS resolution.",severity="medium" if u["flags"]["lookalike"] else "info",confidence="medium",source_location=u["source"]));seen.add(key)
    if sender_addr:db.add(models.PhishingIndicator(analysis_id=item.id,indicator_type="sender_email",normalized_value=sender_addr.lower(),display_value_redacted=redact_email(sender_addr),context="Sender address supplied in message metadata.",severity="info",confidence="medium",source_location="From header"))
    for attachment in features["attachments"][:50]:db.add(models.PhishingAttachmentMetadata(analysis_id=item.id,**{k:v for k,v in attachment.items() if k not in {"mime_mismatch"}}))
    for finding in findings:
        db.add(models.PhishingFinding(analysis_id=item.id,**{k:v for k,v in finding.items() if k!="score"}))
        if finding["severity"] in {"high","critical"}:notify(db,"High-Risk Phishing Finding",f"{finding['rule_code']}: {finding['title']}","warning","phishing_analysis",item.id)
    activity(db,"phishing_analysis_completed",f"Offline phishing analysis {item.id} completed.",item.id);notify(db,"Phishing Analysis Completed",f"Offline analysis {item.id} completed.","success","phishing_analysis",item.id)
    if item.classification=="high_risk":notify(db,"High-Risk Phishing Indicators",f"Analysis {item.id} requires analyst review.","danger","phishing_analysis",item.id)
    db.commit();db.refresh(item);return analysis_read(item)

def analyze_text(db,payload):
    if not any([payload.subject.strip(),payload.sender.strip(),payload.body_text.strip(),(payload.body_html or "").strip(),(payload.headers or "").strip()]):raise HTTPException(422,"Email input is empty")
    header_obj=Parser(policy=policy.default).parsestr((payload.headers or "")+"\n\n");features=build_features(payload.subject,payload.sender,payload.reply_to,payload.body_text,payload.body_html or "",header_obj,[])
    raw=json.dumps(payload.model_dump(),sort_keys=True).encode();identity={"subject":payload.subject,"sender":payload.sender,"reply_to":payload.reply_to,"return_path":header_obj.get("Return-Path"),"recipient_count":len(getaddresses([str(header_obj.get("To","")),str(header_obj.get("Cc",""))]))}
    return _complete(db,"pasted_email",hashlib.sha256(raw).hexdigest(),features,identity)
def analyze_eml(db,data,filename):
    message,plain,html,attachments=parse_eml(data);identity=message_fields(message);features=build_features(identity["subject"],identity["sender"],identity["reply_to"],plain,html,message,attachments)
    return _complete(db,"eml_file",hashlib.sha256(data).hexdigest(),features,identity,filename)
def analyze_standalone_url(db,raw):
    u=analyze_url(raw,"standalone_url");features={"headers":{"authentication_results_present":False},"html":{},"urls":[u],"attachments":[],"text":{"character_count":0},"bounded_text":u["display"]}
    return _complete(db,"standalone_url",hashlib.sha256(raw.strip().encode()).hexdigest(),features,{"subject":"Standalone URL lexical analysis"})
def overview(db):
    since=utcnow()-timedelta(hours=24); classes=dict(db.query(models.PhishingAnalysis.classification,func.count()).group_by(models.PhishingAnalysis.classification).all());sevs=dict(db.query(models.PhishingFinding.severity,func.count()).group_by(models.PhishingFinding.severity).all());cats=[{"category":k,"count":v} for k,v in db.query(models.PhishingFinding.category,func.count()).group_by(models.PhishingFinding.category).order_by(func.count().desc()).limit(8).all()];recent=db.query(models.PhishingAnalysis).order_by(models.PhishingAnalysis.created_at.desc()).limit(8).all();acts=db.query(models.SocActivity).filter_by(entity_type="phishing_analysis").order_by(models.SocActivity.created_at.desc()).limit(10).all()
    count_analyses=lambda codes:db.query(func.count(func.distinct(models.PhishingFinding.analysis_id))).filter(models.PhishingFinding.rule_code.in_(codes)).scalar() or 0
    return {"total_analyses":db.query(models.PhishingAnalysis).count(),"analyses_last_24_hours":db.query(models.PhishingAnalysis).filter(models.PhishingAnalysis.created_at>=since).count(),"completed_analyses":db.query(models.PhishingAnalysis).filter_by(analysis_status="completed").count(),"failed_analyses":db.query(models.PhishingAnalysis).filter_by(analysis_status="failed").count(),"suspicious_analyses":db.query(models.PhishingAnalysis).filter_by(classification="suspicious").count(),"high_risk_analyses":db.query(models.PhishingAnalysis).filter_by(classification="high_risk").count(),"total_findings":db.query(models.PhishingFinding).count(),"high_critical_findings":db.query(models.PhishingFinding).filter(models.PhishingFinding.severity.in_(["high","critical"])).count(),"analyses_with_sender_mismatch":count_analyses(["PHISH-001","PHISH-002"]),"analyses_with_suspicious_urls":count_analyses(["PHISH-007","PHISH-008","PHISH-009","PHISH-010","PHISH-011"]),"analyses_with_risky_attachments":count_analyses(["PHISH-018","PHISH-019","PHISH-020"]),"active_watchlist_entries":db.query(models.PhishingWatchlistEntry).filter_by(status="active").count(),"analyses_by_classification":classes,"findings_by_severity":sevs,"top_finding_categories":cats,"recent_analyses":[analysis_read(x) for x in recent],"recent_activities":[{"id":x.id,"action":x.action,"message":x.message,"created_at":x.created_at} for x in acts]}
