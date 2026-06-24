from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db

from app.scanner.orchestrator import run_scan

router = APIRouter()

@router.post("/start", response_model=schemas.Scan)
def start_scan(scan_req: schemas.ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(models.Target).filter(models.Target.id == scan_req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    if not target.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Target authorization not confirmed")

    db_scan = models.Scan(
        target_id=target.id,
        profile=scan_req.profile,
        status="queued"
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    background_tasks.add_task(run_scan, db_scan.id)
    
    return db_scan

@router.get("/", response_model=list[schemas.Scan])
def read_scans(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.started_at.desc()).offset(skip).limit(limit).all()
    return scans

@router.get("/{scan_id}", response_model=schemas.Scan)
def read_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/findings", response_model=list[schemas.Finding])
def read_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    return findings
