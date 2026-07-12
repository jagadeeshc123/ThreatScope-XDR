from datetime import datetime, timezone, timedelta

from app import models
from .coverage_service import summary as coverage_summary
from .service import dump
from .snapshot_service import utc


def overview(db):
    now = datetime.now(timezone.utc)
    risks = db.query(models.GovernanceRisk).all()
    treatments = db.query(models.RiskTreatmentPlan).all()
    exceptions = db.query(models.RiskException).all()
    coverage = coverage_summary(db)
    open_status = {"identified", "under_review", "treatment_planned", "treatment_in_progress", "accepted", "monitoring"}
    snapshots = db.query(models.GovernanceSnapshot).order_by(models.GovernanceSnapshot.metric_date).limit(90).all()
    return {
        "total_risks": len(risks),
        "open_risks": sum(x.status in open_status for x in risks),
        "high_risks": sum(x.severity == "high" and x.status != "closed" for x in risks),
        "critical_risks": sum(x.severity == "critical" and x.status != "closed" for x in risks),
        "risks_exceeding_appetite": sum(x.appetite_status == "exceeds_appetite" and x.status != "closed" for x in risks),
        "risks_near_appetite": sum(x.appetite_status == "near_appetite" and x.status != "closed" for x in risks),
        "overdue_risks": sum(bool(x.due_at) and utc(x.due_at) < now and x.status != "closed" for x in risks),
        "treatments_planned": sum(x.status == "planned" for x in treatments),
        "treatments_overdue": sum(bool(x.target_date) and utc(x.target_date) < now and x.status in {"planned", "in_progress"} for x in treatments),
        "active_exceptions": sum(x.status == "approved" and bool(x.expires_at) and utc(x.expires_at) > now for x in exceptions),
        "exceptions_expiring_within_30_days": sum(x.status == "approved" and bool(x.expires_at) and now < utc(x.expires_at) <= now + timedelta(days=30) for x in exceptions),
        "enabled_frameworks": db.query(models.GovernanceFramework).filter_by(enabled=True).count(),
        "total_controls": db.query(models.GovernanceControl).filter_by(enabled=True).count(),
        "confirmed_mappings": db.query(models.GovernanceControlMapping).filter_by(mapping_status="confirmed").count(),
        "candidate_mappings_awaiting_review": db.query(models.GovernanceControlMapping).filter_by(mapping_status="candidate").count(),
        "control_gaps": sum(x["gap_controls"] for x in coverage),
        "supported_controls": sum(x["supported_controls"] for x in coverage),
        "evidence_packages": db.query(models.GovernanceEvidencePackage).count(),
        "reviews_awaiting_approval": db.query(models.GovernanceReview).filter_by(status="awaiting_approval").count(),
        "open_incident_cases": db.query(models.IncidentCase).filter(models.IncidentCase.status.notin_(["resolved", "closed"])).count(),
        "p1_cases": db.query(models.IncidentCase).filter(models.IncidentCase.priority == "P1", models.IncidentCase.status.notin_(["resolved", "closed"])).count(),
        "active_high_risk_correlation_matches": db.query(models.CorrelationMatch).filter(models.CorrelationMatch.severity.in_(["high", "critical"]), models.CorrelationMatch.status.notin_(["dismissed", "reviewed"])).count(),
        "risks_by_severity": {value: sum(r.severity == value for r in risks) for value in ["low", "medium", "high", "critical"]},
        "risks_by_status": {value: sum(r.status == value for r in risks) for value in sorted({r.status for r in risks})},
        "risks_by_category": {value: sum(r.category == value for r in risks) for value in sorted({r.category for r in risks})},
        "residual_risk_distribution": [{"risk_key": x.risk_key, "score": x.residual_score} for x in risks[:50]],
        "control_coverage_by_framework": coverage,
        "risk_trend": [dump(x) for x in snapshots],
        "recent_risks": [dump(x) for x in sorted(risks, key=lambda x: x.created_at, reverse=True)[:10]],
        "upcoming_reviews": [dump(x) for x in db.query(models.GovernanceReview).filter(models.GovernanceReview.status.in_(["planned", "in_progress", "awaiting_approval"])).limit(10)],
        "recent_governance_activities": [dump(x) for x in db.query(models.SocActivity).filter_by(entity_type="governance").order_by(models.SocActivity.created_at.desc()).limit(10)],
    }
