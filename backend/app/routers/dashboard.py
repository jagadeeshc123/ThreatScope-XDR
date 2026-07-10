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
    active_scans = db.query(models.Scan).filter(models.Scan.status.in_(["queued", "running"])).count()
    total_findings = db.query(models.Finding).count()
    api_assessment_count = db.query(models.ApiAssessment).count()
    api_endpoint_count = db.query(models.ApiEndpoint).count()
    api_unauthenticated_endpoint_count = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.auth_required == False).count()
    api_high_risk_endpoint_count = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.preliminary_risk_level == "high").count()
    
    # Failed and in-progress scans do not contain assessment scores.
    avg_risk = db.query(func.avg(models.Scan.risk_score)).filter(models.Scan.status == "completed").scalar() or 0.0
    avg_posture = db.query(func.avg(models.Scan.overall_posture_score)).filter(models.Scan.status == "completed").scalar() or 0.0

    # severity distribution
    severities = ["critical", "high", "medium", "low", "info"]
    distribution = {}
    for sev in severities:
        count = db.query(models.Finding).filter(models.Finding.severity == sev).count()
        distribution[sev] = count

    recent_scans = db.query(models.Scan).order_by(models.Scan.started_at.desc()).limit(5).all()
    
    target_risk_rows = (
        db.query(models.Target.id, func.avg(models.Scan.risk_score).label("avg_risk"))
        .join(models.Scan, models.Scan.target_id == models.Target.id)
        .filter(models.Scan.status == "completed")
        .group_by(models.Target.id)
        .order_by(func.avg(models.Scan.risk_score).desc())
        .limit(3)
        .all()
    )
    highest_risk_targets = []
    for row in target_risk_rows:
        target = db.query(models.Target).filter(models.Target.id == row.id).first()
        if target:
            highest_risk_targets.append(target)
    
    return schemas.DashboardSummary(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        critical_findings=distribution["critical"],
        high_findings=distribution["high"],
        overall_risk_score=round(avg_risk, 2),
        overall_posture_score=int(avg_posture),
        api_assessment_count=api_assessment_count,
        api_endpoint_count=api_endpoint_count,
        api_unauthenticated_endpoint_count=api_unauthenticated_endpoint_count,
        api_high_risk_endpoint_count=api_high_risk_endpoint_count,
        severity_distribution=distribution,
        recent_scans=recent_scans,
        highest_risk_targets=highest_risk_targets
    )
