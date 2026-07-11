import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter,Depends,File,HTTPException,Query,Response,UploadFile
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app import models
from app.database import get_db
from app.modules.document_threats import report_service,schemas,service

router=APIRouter()
@router.get("/overview",response_model=schemas.Overview)
def overview(db:Session=Depends(get_db)): return service.overview(db)

@router.post("/analyses",response_model=schemas.AnalysisRead)
async def analyze(file:UploadFile=File(...),db:Session=Depends(get_db)): return await service.analyze_upload(db,file)

@router.get("/analyses",response_model=schemas.AnalysisPage)
def analyses(page:int=Query(1,ge=1),page_size:int=Query(25,ge=1,le=100),classification:Optional[str]=None,status:Optional[str]=None,min_risk:Optional[float]=Query(None,ge=0,le=100),max_risk:Optional[float]=Query(None,ge=0,le=100),q:Optional[str]=Query(None,max_length=200),created_after:Optional[datetime]=None,db:Session=Depends(get_db)):
    query=db.query(models.DocumentAnalysis)
    if classification:query=query.filter(models.DocumentAnalysis.classification==classification)
    if status:query=query.filter(models.DocumentAnalysis.analysis_status==status)
    if min_risk is not None:query=query.filter(models.DocumentAnalysis.risk_score>=min_risk)
    if max_risk is not None:query=query.filter(models.DocumentAnalysis.risk_score<=max_risk)
    if created_after:query=query.filter(models.DocumentAnalysis.created_at>=created_after)
    if q: term=f"%{q}%";query=query.filter(or_(models.DocumentAnalysis.filename_sanitized.ilike(term),models.DocumentAnalysis.file_hash.ilike(term)))
    total=query.count();items=query.order_by(models.DocumentAnalysis.created_at.desc()).offset((page-1)*page_size).limit(page_size).all()
    return {"items":[service.analysis_read(i) for i in items],"total":total,"page":page,"page_size":page_size}

@router.get("/analyses/{analysis_id}",response_model=schemas.AnalysisDetail)
def analysis_detail(analysis_id:int,db:Session=Depends(get_db)):
    item=service.get_analysis(db,analysis_id)
    return service.analysis_read(item)|{"findings":item.findings,"indicators":item.indicators,"embedded_artifacts":item.embedded_artifacts}

@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id:int,db:Session=Depends(get_db)):
    item=service.get_analysis(db,analysis_id);name=item.filename_sanitized;db.delete(item);service.activity(db,"document_analysis_deleted",f"Derived analysis records deleted for {name}.",analysis_id);db.commit();return {"ok":True}

@router.get("/analyses/{analysis_id}/findings",response_model=list[schemas.FindingRead])
def findings(analysis_id:int,severity:Optional[str]=None,category:Optional[str]=None,confidence:Optional[str]=None,db:Session=Depends(get_db)):
    service.get_analysis(db,analysis_id);query=db.query(models.DocumentFinding).filter(models.DocumentFinding.analysis_id==analysis_id)
    for field,value in {"severity":severity,"category":category,"confidence":confidence}.items():
        if value:query=query.filter(getattr(models.DocumentFinding,field)==value)
    return query.order_by(models.DocumentFinding.severity.desc(),models.DocumentFinding.id).all()

@router.get("/findings/{finding_id}",response_model=schemas.FindingRead)
def finding(finding_id:int,db:Session=Depends(get_db)):
    item=db.query(models.DocumentFinding).filter(models.DocumentFinding.id==finding_id).first()
    if not item:raise HTTPException(404,"Document finding not found")
    return item

@router.get("/analyses/{analysis_id}/indicators",response_model=list[schemas.IndicatorRead])
def indicators(analysis_id:int,indicator_type:Optional[str]=None,db:Session=Depends(get_db)):
    service.get_analysis(db,analysis_id);query=db.query(models.DocumentIndicator).filter(models.DocumentIndicator.analysis_id==analysis_id)
    if indicator_type:query=query.filter(models.DocumentIndicator.indicator_type==indicator_type)
    return query.order_by(models.DocumentIndicator.id).all()

@router.get("/analyses/{analysis_id}/embedded-artifacts",response_model=list[schemas.EmbeddedRead])
def artifacts(analysis_id:int,db:Session=Depends(get_db)):service.get_analysis(db,analysis_id);return db.query(models.DocumentEmbeddedArtifact).filter(models.DocumentEmbeddedArtifact.analysis_id==analysis_id).all()

@router.post("/analyses/{analysis_id}/reports",response_model=schemas.ReportRead)
def create_report(analysis_id:int,db:Session=Depends(get_db)):return service.report_read(report_service.generate(db,service.get_analysis(db,analysis_id)))
@router.get("/reports",response_model=list[schemas.ReportRead])
def reports(db:Session=Depends(get_db)):return [service.report_read(i) for i in db.query(models.DocumentReport).order_by(models.DocumentReport.created_at.desc()).all()]
def get_report(db,id):
    item=db.query(models.DocumentReport).filter(models.DocumentReport.id==id).first()
    if not item:raise HTTPException(404,"Document report not found")
    return item
@router.get("/reports/{report_id}",response_model=schemas.ReportRead)
def report(report_id:int,db:Session=Depends(get_db)):return service.report_read(get_report(db,report_id))
@router.get("/reports/{report_id}/download")
def download(report_id:int,db:Session=Depends(get_db)):
    item=get_report(db,report_id);return Response(content=item.html_content,media_type="text/html",headers={"Content-Disposition":f"attachment; filename=document-threat-report-{item.id}.html"})
