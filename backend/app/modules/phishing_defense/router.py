import hashlib,json
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter,Depends,File,HTTPException,Query,Response,UploadFile
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app import models
from app.database import get_db
from . import report_service,schemas,service
from .model_service import info
from .redaction import redact_text,sanitize_filename
from .watchlist import DISCLAIMER,normalize

router=APIRouter()
@router.get("/overview",response_model=schemas.Overview)
def overview(db:Session=Depends(get_db)):return service.overview(db)
@router.get("/model-info")
def model_info():return info()
@router.post("/analyses/email-text",response_model=schemas.AnalysisRead)
def email_text(payload:schemas.EmailTextInput,db:Session=Depends(get_db)):
    try:return service.analyze_text(db,payload)
    except HTTPException:raise
    except Exception as exc:
        digest=hashlib.sha256(json.dumps(payload.model_dump(),sort_keys=True).encode()).hexdigest();service.record_failure(db,"pasted_email",digest,exc);raise HTTPException(422,"Email text could not be analyzed safely")
@router.post("/analyses/url",response_model=schemas.AnalysisRead)
def url(payload:schemas.UrlInput,db:Session=Depends(get_db)):
    try:return service.analyze_standalone_url(db,payload.url)
    except (TypeError,ValueError) as exc:raise HTTPException(422,f"URL text could not be parsed safely: {redact_text(exc,200)}")
    except Exception as exc:
        digest=hashlib.sha256(payload.url.strip().encode()).hexdigest();service.record_failure(db,"standalone_url",digest,exc);raise HTTPException(422,"URL text could not be analyzed safely")
@router.post("/analyses/eml",response_model=schemas.AnalysisRead)
async def eml(file:UploadFile=File(...),db:Session=Depends(get_db)):
    try:filename=sanitize_filename(file.filename or "")
    except ValueError as exc:await file.close();raise HTTPException(422,str(exc))
    if not filename.lower().endswith(".eml"):await file.close();raise HTTPException(422,"Only .eml files are supported")
    data=await file.read(5*1024*1024+1);await file.close()
    if not data:raise HTTPException(422,"EML file is empty")
    if len(data)>5*1024*1024:raise HTTPException(413,"EML exceeds the 5 MB limit")
    try:return service.analyze_eml(db,data,filename)
    except Exception as exc:
        if isinstance(exc,HTTPException):raise
        service.record_failure(db,"eml_file",hashlib.sha256(data).hexdigest(),exc,filename);raise HTTPException(422,f"Malformed EML could not be processed safely: {redact_text(exc,200)}")
@router.get("/analyses",response_model=schemas.AnalysisPage)
def analyses(page:int=Query(1,ge=1),page_size:int=Query(25,ge=1,le=100),classification:Optional[str]=None,disposition:Optional[str]=None,source_type:Optional[str]=None,status:Optional[str]=None,min_score:Optional[float]=Query(None,ge=0,le=100),max_score:Optional[float]=Query(None,ge=0,le=100),q:Optional[str]=Query(None,max_length=200),created_after:Optional[datetime]=None,db:Session=Depends(get_db)):
    query=db.query(models.PhishingAnalysis)
    for field,value in {"classification":classification,"analyst_disposition":disposition,"source_type":source_type,"analysis_status":status}.items():
        if value:query=query.filter(getattr(models.PhishingAnalysis,field)==value)
    if min_score is not None:query=query.filter(models.PhishingAnalysis.final_risk_score>=min_score)
    if max_score is not None:query=query.filter(models.PhishingAnalysis.final_risk_score<=max_score)
    if created_after:query=query.filter(models.PhishingAnalysis.created_at>=created_after)
    if q:term=f"%{q}%";query=query.filter(or_(models.PhishingAnalysis.subject_redacted.ilike(term),models.PhishingAnalysis.sender_address_redacted.ilike(term),models.PhishingAnalysis.source_hash.ilike(term)))
    total=query.count();items=query.order_by(models.PhishingAnalysis.created_at.desc()).offset((page-1)*page_size).limit(page_size).all();return {"items":[service.analysis_read(x) for x in items],"total":total,"page":page,"page_size":page_size}
@router.get("/analyses/{analysis_id}",response_model=schemas.AnalysisDetail)
def analysis(analysis_id:int,db:Session=Depends(get_db)):
    x=service.get_analysis(db,analysis_id);return service.analysis_read(x)|{"findings":x.findings,"indicators":x.indicators,"attachments":x.attachments,"reports":[service.report_read(r) for r in x.reports]}
@router.patch("/analyses/{analysis_id}",response_model=schemas.AnalysisRead)
def update_analysis(analysis_id:int,payload:schemas.AnalysisUpdate,db:Session=Depends(get_db)):
    x=service.get_analysis(db,analysis_id);changes=payload.model_dump(exclude_unset=True)
    if "analyst_disposition" in changes and changes["analyst_disposition"] not in {"unreviewed","legitimate","suspicious","phishing","false_positive"}:raise HTTPException(422,"Invalid analyst disposition")
    old=x.analyst_disposition
    for k,v in changes.items():setattr(x,k,redact_text(v,5000) if k=="analyst_notes" else v)
    if x.analyst_disposition!=old:
        service.activity(db,"phishing_disposition_changed",f"Analysis {x.id} disposition changed to {x.analyst_disposition}.",x.id)
        if x.analyst_disposition=="phishing":service.notify(db,"Analysis Marked as Phishing",f"Analyst disposition updated for analysis {x.id}.","warning","phishing_analysis",x.id)
    db.commit();db.refresh(x);return service.analysis_read(x)
@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id:int,db:Session=Depends(get_db)):
    x=service.get_analysis(db,analysis_id);db.delete(x);service.activity(db,"phishing_analysis_deleted",f"Derived records for phishing analysis {analysis_id} deleted.",analysis_id);db.commit();return {"ok":True}
@router.get("/analyses/{analysis_id}/findings",response_model=list[schemas.FindingRead])
def findings(analysis_id:int,severity:Optional[str]=None,confidence:Optional[str]=None,category:Optional[str]=None,db:Session=Depends(get_db)):
    service.get_analysis(db,analysis_id);q=db.query(models.PhishingFinding).filter_by(analysis_id=analysis_id)
    for k,v in {"severity":severity,"confidence":confidence,"category":category}.items():
        if v:q=q.filter(getattr(models.PhishingFinding,k)==v)
    return q.order_by(models.PhishingFinding.id).all()
@router.get("/findings/{finding_id}",response_model=schemas.FindingRead)
def finding(finding_id:int,db:Session=Depends(get_db)):
    x=db.query(models.PhishingFinding).filter_by(id=finding_id).first()
    if not x:raise HTTPException(404,"Phishing finding not found")
    return x
@router.get("/analyses/{analysis_id}/indicators",response_model=list[schemas.IndicatorRead])
def indicators(analysis_id:int,indicator_type:Optional[str]=None,db:Session=Depends(get_db)):
    service.get_analysis(db,analysis_id);q=db.query(models.PhishingIndicator).filter_by(analysis_id=analysis_id)
    if indicator_type:q=q.filter_by(indicator_type=indicator_type)
    return q.order_by(models.PhishingIndicator.id).all()
@router.get("/analyses/{analysis_id}/attachments",response_model=list[schemas.AttachmentRead])
def attachments(analysis_id:int,db:Session=Depends(get_db)):service.get_analysis(db,analysis_id);return db.query(models.PhishingAttachmentMetadata).filter_by(analysis_id=analysis_id).all()
@router.get("/watchlist",response_model=list[schemas.WatchlistRead])
def watchlist(db:Session=Depends(get_db)):return db.query(models.PhishingWatchlistEntry).order_by(models.PhishingWatchlistEntry.created_at.desc()).all()
@router.post("/watchlist",response_model=schemas.WatchlistRead)
def create_watchlist(payload:schemas.WatchlistCreate,db:Session=Depends(get_db)):
    try:norm,display=normalize(payload.indicator_type,payload.normalized_value)
    except ValueError as exc:raise HTTPException(422,str(exc))
    existing=db.query(models.PhishingWatchlistEntry).filter_by(indicator_type=payload.indicator_type,normalized_value=norm).first()
    if existing:
        if existing.status!="active":existing.status="active";existing.reason=redact_text(payload.reason,1000);db.commit();db.refresh(existing);return existing
        raise HTTPException(409,"Watchlist indicator already exists")
    x=models.PhishingWatchlistEntry(indicator_type=payload.indicator_type,normalized_value=norm,display_value_redacted=display,reason=redact_text(payload.reason,1000),source_analysis_id=payload.source_analysis_id,expires_at=payload.expires_at);db.add(x);db.flush();service.activity(db,"phishing_watchlist_updated",f"Local watchlist entry {x.id} created. {DISCLAIMER}",payload.source_analysis_id);service.notify(db,"Phishing Watchlist Updated",f"Local-only entry {x.id} created.","info","phishing_watchlist",x.id);db.commit();db.refresh(x);return x
@router.patch("/watchlist/{entry_id}",response_model=schemas.WatchlistRead)
def update_watchlist(entry_id:int,payload:schemas.WatchlistUpdate,db:Session=Depends(get_db)):
    x=db.query(models.PhishingWatchlistEntry).filter_by(id=entry_id).first()
    if not x:raise HTTPException(404,"Watchlist entry not found")
    for k,v in payload.model_dump(exclude_unset=True).items():setattr(x,k,redact_text(v,1000) if k=="reason" else v)
    service.activity(db,"phishing_watchlist_updated",f"Local watchlist entry {x.id} updated.",x.source_analysis_id);db.commit();db.refresh(x);return x
@router.delete("/watchlist/{entry_id}")
def delete_watchlist(entry_id:int,db:Session=Depends(get_db)):
    x=db.query(models.PhishingWatchlistEntry).filter_by(id=entry_id).first()
    if not x:raise HTTPException(404,"Watchlist entry not found")
    x.status="removed";service.activity(db,"phishing_watchlist_updated",f"Local watchlist entry {x.id} marked removed.",x.source_analysis_id);db.commit();return {"ok":True,"disclaimer":DISCLAIMER}
@router.post("/analyses/{analysis_id}/reports",response_model=schemas.ReportRead)
def create_report(analysis_id:int,db:Session=Depends(get_db)):return service.report_read(report_service.generate(db,service.get_analysis(db,analysis_id)))
@router.get("/reports",response_model=list[schemas.ReportRead])
def reports(db:Session=Depends(get_db)):return [service.report_read(x) for x in db.query(models.PhishingReport).order_by(models.PhishingReport.created_at.desc()).all()]
def _report(db,id):
    x=db.query(models.PhishingReport).filter_by(id=id).first()
    if not x:raise HTTPException(404,"Phishing report not found")
    return x
@router.get("/reports/{report_id}",response_model=schemas.ReportRead)
def report(report_id:int,db:Session=Depends(get_db)):return service.report_read(_report(db,report_id))
@router.get("/reports/{report_id}/download")
def download(report_id:int,db:Session=Depends(get_db)):
    x=_report(db,report_id);return Response(x.html_content,media_type="text/html",headers={"Content-Disposition":f"attachment; filename=phishing-risk-report-{x.id}.html"})
