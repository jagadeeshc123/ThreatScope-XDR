from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db
from app.scanner.reports.report_generator import generate_report

router = APIRouter()

@router.post("/generate/{scan_id}", response_model=schemas.Report)
def generate_report_endpoint(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # check if report already exists
    existing_report = db.query(models.Report).filter(models.Report.scan_id == scan_id).first()
    if existing_report:
        return existing_report

    html_content = generate_report(db, scan)
    
    db_report = models.Report(
        scan_id=scan.id,
        target_id=scan.target_id,
        title=f"Security Assessment Report - {scan.target.name}",
        executive_summary=f"Automated assessment resulted in {scan.total_findings} findings.",
        html_content=html_content
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)

    return db_report

@router.get("/", response_model=list[schemas.Report])
def list_reports(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Report).order_by(models.Report.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/{report_id}", response_model=schemas.Report)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Download as HTML
    return Response(content=report.html_content, media_type="text/html", headers={
        "Content-Disposition": f"attachment; filename=report_{report_id}.html"
    })
