from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app import schemas, models
from app.database import get_db
from app.scanner.orchestrator import run_scan
from app.routers.policies import load_policies

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

@router.get("/{scan_id}/crawl-map", response_model=list[schemas.CrawlNode])
def read_scan_crawl_map(scan_id: int, db: Session = Depends(get_db)):
    nodes = db.query(models.CrawlNode).filter(models.CrawlNode.scan_id == scan_id).all()
    return nodes

@router.get("/{scan_id}/diff", response_model=schemas.PostureDiff)
def read_scan_diff(scan_id: int, db: Session = Depends(get_db)):
    diff = db.query(models.PostureDiff).filter(models.PostureDiff.current_scan_id == scan_id).first()
    if not diff:
        raise HTTPException(status_code=404, detail="Diff not found for this scan (may be the first scan)")
    return diff

@router.get("/{scan_id}/evidence", response_model=list[schemas.EvidenceArtifact])
def read_scan_evidence(scan_id: int, db: Session = Depends(get_db)):
    evidence = db.query(models.EvidenceArtifact).filter(models.EvidenceArtifact.scan_id == scan_id).all()
    return evidence

@router.get("/{scan_id}/policy-results")
def get_scan_policy_results(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    
    policies = load_policies()
    results = []
    
    for policy in policies:
        policy_result = {
            "policy_id": policy["policy_id"],
            "title": policy["title"],
            "checks": []
        }
        
        for check in policy.get("checks", []):
            related_titles = [t.lower() for t in check.get("related_finding_titles", [])]
            
            violating_findings = [
                f for f in findings
                if any(t in f.title.lower() for t in related_titles)
            ]
            
            status = "failed" if violating_findings else "passed"
                
            policy_result["checks"].append({
                "check_id": check["id"],
                "title": check["title"],
                "status": status,
                "violating_findings": [f.title for f in violating_findings]
            })
            
        results.append(policy_result)
        
    return results
