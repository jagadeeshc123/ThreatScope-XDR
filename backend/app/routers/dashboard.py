from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import schemas, models
from app.database import get_db

router = APIRouter()

@router.get("/summary", response_model=schemas.DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_targets = db.query(models.Target).count()
    total_scans = db.query(models.Scan).count()
    total_findings = db.query(models.Finding).count()
    
    # Calculate overall risk score
    # simple average of all scan risk scores for now
    avg_risk = db.query(func.avg(models.Scan.risk_score)).scalar() or 0.0

    # severity distribution
    severities = ["critical", "high", "medium", "low", "info"]
    distribution = {}
    for sev in severities:
        count = db.query(models.Finding).filter(models.Finding.severity == sev).count()
        distribution[sev] = count

    recent_scans = db.query(models.Scan).order_by(models.Scan.started_at.desc()).limit(5).all()
    
    # Target with highest risk
    # Simplified approach: fetch all and sort
    targets = db.query(models.Target).all()
    highest_risk_targets = [] # Ideally we aggregate max risk score per target.
    
    return schemas.DashboardSummary(
        total_targets=total_targets,
        total_scans=total_scans,
        total_findings=total_findings,
        overall_risk_score=round(avg_risk, 2),
        severity_distribution=distribution,
        recent_scans=recent_scans,
        highest_risk_targets=highest_risk_targets
    )
