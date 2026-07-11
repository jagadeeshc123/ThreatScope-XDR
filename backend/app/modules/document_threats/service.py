import hashlib, json
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import HTTPException, UploadFile
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app import models
from app.modules.document_threats.findings_engine import build_findings
from app.modules.document_threats.parser import DocumentParseError, inspect_pdf
from app.modules.document_threats.redaction import redact_text, sanitize_filename
from app.modules.document_threats.risk_engine import METHODOLOGY, score

MAX_BYTES=15*1024*1024
def utcnow(): return datetime.now(timezone.utc)
def activity(db,action,message,entity_id=None): db.add(models.SocActivity(action=action,message=redact_text(message,500),entity_type="document_analysis",entity_id=entity_id))
def notify(db,title,message,kind,entity_type,entity_id): db.add(models.Notification(title=title,message=redact_text(message,500),type=kind,entity_type=entity_type,entity_id=entity_id))

def analysis_read(item,duplicate=False):
    values={key:getattr(item,key) for key in ("id","filename_sanitized","file_hash","file_size","mime_type","pdf_version","page_count","analysis_status","is_encrypted","encryption_limited_analysis","has_javascript","has_open_action","has_additional_actions","has_launch_action","has_acroform","has_xfa","has_embedded_files","has_external_uris","external_uri_count","embedded_file_count","annotation_count","extracted_text_character_count","risk_score","classification","confidence","methodology","error_summary","created_at","completed_at")}
    return values|{"metadata_json_redacted":json.loads(item.metadata_json_redacted or "{}"),"feature_summary_json":json.loads(item.feature_summary_json or "{}"),"duplicate_existing":duplicate}
def report_read(item): return {"id":item.id,"analysis_id":item.analysis_id,"title":item.title,"html_content":item.html_content,"summary_json":json.loads(item.summary_json),"created_at":item.created_at}
def get_analysis(db,id):
    item=db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.id==id).first()
    if not item: raise HTTPException(404,"Document analysis not found")
    return item

async def analyze_upload(db:Session,file:UploadFile):
    try: filename=sanitize_filename(file.filename or "")
    except ValueError as exc: await file.close(); raise HTTPException(422,str(exc))
    if not filename.lower().endswith(".pdf"): await file.close(); raise HTTPException(422,"Only .pdf files are supported")
    data=await file.read(MAX_BYTES+1); await file.close()
    if not data: raise HTTPException(422,"PDF file is empty")
    if len(data)>MAX_BYTES: raise HTTPException(413,"PDF exceeds the 15 MB limit")
    if not data.startswith(b"%PDF-"): raise HTTPException(422,"File does not have a valid PDF signature")
    digest=hashlib.sha256(data).hexdigest()
    existing=db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.file_hash==digest).first()
    if existing:
        activity(db,"duplicate_pdf_detected",f"Duplicate PDF detected for {filename}.",existing.id); db.commit()
        return analysis_read(existing,True)
    item=models.DocumentAnalysis(filename_sanitized=filename,file_hash=digest,file_size=len(data),mime_type="application/pdf",analysis_status="processing",methodology=METHODOLOGY)
    db.add(item); db.flush()
    try: features=inspect_pdf(data)
    except DocumentParseError as exc:
        item.analysis_status="failed"; item.error_summary=redact_text(exc,500); item.completed_at=utcnow(); activity(db,"pdf_analysis_failed",f"PDF analysis failed for {filename}.",item.id); notify(db,"Document Analysis Failed",f"Static analysis failed for {filename}.","danger","document_analysis",item.id); db.commit(); raise HTTPException(422,item.error_summary)
    findings=build_findings(item.id,digest,features); risk=score(findings)
    summary={k:v for k,v in features.items() if k not in {"attachments","indicators","metadata"}}
    summary.update(risk)
    for key in ("pdf_version","page_count","is_encrypted","encryption_limited_analysis","has_javascript","has_open_action","has_additional_actions","has_launch_action","has_acroform","has_xfa","has_embedded_files","has_external_uris","external_uri_count","embedded_file_count","annotation_count","extracted_text_character_count"): setattr(item,key,features[key])
    item.metadata_json_redacted=json.dumps(features["metadata"],ensure_ascii=True,sort_keys=True); item.feature_summary_json=json.dumps(summary,ensure_ascii=True,sort_keys=True,default=str)
    item.risk_score=risk["risk_score"]; item.classification=risk["classification"]; item.confidence=risk["confidence"]; item.analysis_status="limited" if features["encryption_limited_analysis"] else "completed"; item.completed_at=utcnow()
    db.add(models.DocumentIndicator(analysis_id=item.id,indicator_type="file_hash",normalized_value=digest,display_value_redacted=digest,context="SHA-256 calculated locally from in-memory upload bytes.",severity="info",confidence="high",source_object="Uploaded PDF"))
    db.add(models.DocumentIndicator(analysis_id=item.id,indicator_type="filename",normalized_value=filename.lower(),display_value_redacted=filename,context="Sanitized uploaded filename.",severity="info",confidence="high",source_object="Upload metadata"))
    for indicator in features["indicators"][:500]: db.add(models.DocumentIndicator(analysis_id=item.id,**indicator))
    for artifact in features["attachments"][:100]: db.add(models.DocumentEmbeddedArtifact(analysis_id=item.id,**{k:v for k,v in artifact.items() if k!="double_extension"}))
    for finding in findings:
        db.add(models.DocumentFinding(**{k:v for k,v in finding.items() if k!="score"}))
        if finding["severity"] in {"high","critical"}: notify(db,"High-Risk Document Finding",f"{finding['rule_code']}: {finding['title']}","warning","document_analysis",item.id)
    activity(db,"pdf_analysis_completed",f"Static PDF analysis completed for {filename}.",item.id); notify(db,"Document Analysis Completed",f"Static analysis completed for {filename}.","success","document_analysis",item.id)
    if item.classification=="high_risk": activity(db,"high_risk_document_identified",f"High-risk static indicators identified in {filename}.",item.id); notify(db,"High-Risk Document Indicators",f"{filename} requires manual review.","danger","document_analysis",item.id)
    db.commit(); db.refresh(item); return analysis_read(item)

def overview(db):
    since=utcnow()-timedelta(hours=24)
    sev={k:v for k,v in db.query(models.DocumentFinding.severity,func.count(models.DocumentFinding.id)).group_by(models.DocumentFinding.severity).all()}
    classes={k:v for k,v in db.query(models.DocumentAnalysis.classification,func.count(models.DocumentAnalysis.id)).group_by(models.DocumentAnalysis.classification).all()}
    cats=[{"category":k,"count":v} for k,v in db.query(models.DocumentFinding.category,func.count(models.DocumentFinding.id)).group_by(models.DocumentFinding.category).order_by(func.count(models.DocumentFinding.id).desc()).limit(8).all()]
    recent=db.query(models.DocumentAnalysis).order_by(models.DocumentAnalysis.created_at.desc()).limit(8).all()
    acts=db.query(models.SocActivity).filter(models.SocActivity.entity_type=="document_analysis").order_by(models.SocActivity.created_at.desc()).limit(10).all()
    return {"total_analyses":db.query(models.DocumentAnalysis).count(),"analyses_last_24_hours":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.created_at>=since).count(),"completed_analyses":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.analysis_status=="completed").count(),"failed_or_limited_analyses":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.analysis_status.in_(["failed","limited"])).count(),"suspicious_analyses":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.classification=="suspicious").count(),"high_risk_analyses":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.classification=="high_risk").count(),"total_findings":db.query(models.DocumentFinding).count(),"high_critical_findings":db.query(models.DocumentFinding).filter(models.DocumentFinding.severity.in_(["high","critical"])).count(),"documents_with_javascript":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.has_javascript==True).count(),"documents_with_automatic_actions":db.query(models.DocumentAnalysis).filter(or_(models.DocumentAnalysis.has_open_action==True,models.DocumentAnalysis.has_launch_action==True,models.DocumentAnalysis.has_additional_actions==True)).count(),"documents_with_embedded_artifacts":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.has_embedded_files==True).count(),"documents_with_external_links":db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.has_external_uris==True).count(),"findings_by_severity":sev,"analyses_by_classification":classes,"recent_analyses":[analysis_read(i) for i in recent],"top_finding_categories":cats,"recent_activity":[{"id":a.id,"action":a.action,"message":a.message,"created_at":a.created_at} for a in acts]}
