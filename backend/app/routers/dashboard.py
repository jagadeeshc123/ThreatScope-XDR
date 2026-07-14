from fastapi import APIRouter, Depends, Request
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from app import schemas, models
from app.database import get_db
from app.modules.access_control.role_service import effective_permissions

router = APIRouter()

@router.get("/summary", response_model=schemas.DashboardSummary)
def get_dashboard_summary(request: Request, db: Session = Depends(get_db)):
    permissions = effective_permissions(db, request.state.current_user)
    operations = None
    if "operations:view" in permissions:
        from app.modules.platform_operations.health_service import public_readiness
        from app.modules.platform_operations.models import BackupRecord, OperationalJob, RestoreRecord
        readiness, _ = public_readiness(db)
        latest_backup = db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None), BackupRecord.verification_status == "valid").order_by(BackupRecord.created_at.desc()).first()
        operations = {"readiness_status": readiness["status"], "degraded_check_count": readiness["failed_check_count"], "latest_backup_at": latest_backup.created_at if latest_backup and "operations:backup" in permissions else None, "failed_job_count": db.query(OperationalJob).filter_by(status="failed").count() if "operations:maintenance" in permissions else 0, "pending_restore_count": db.query(RestoreRecord).filter_by(status="pending_restart").count() if "operations:restore" in permissions else 0, "demo_mode": __import__("os").getenv("THREATSCOPE_DEMO_MODE","false").lower() in {"1","true","yes","on"}, "release_version": "1.0.0-rc1"}
    total_targets = db.query(models.Target).count()
    total_scans = db.query(models.Scan).count()
    active_scans = db.query(models.Scan).filter(models.Scan.status.in_(["queued", "running"])).count()
    total_findings = db.query(models.Finding).count()
    api_assessment_count = db.query(models.ApiAssessment).count()
    api_endpoint_count = db.query(models.ApiEndpoint).count()
    api_unauthenticated_endpoint_count = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.auth_required == False).count()
    api_high_risk_endpoint_count = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.preliminary_risk_level == "high").count()
    api_finding_count = db.query(models.ApiFinding).count()
    api_high_risk_finding_count = db.query(models.ApiFinding).filter(models.ApiFinding.severity.in_(["high", "critical"])).count()
    api_owasp_observed_category_count = db.query(models.ApiOwaspCoverage).filter(models.ApiOwaspCoverage.finding_count > 0).count()
    api_matrix_total = sum(assessment.endpoint_count * len(assessment.api_roles) for assessment in db.query(models.ApiAssessment).all())
    api_matrix_reviewed = db.query(models.AuthorizationMatrixEntry).filter(models.AuthorizationMatrixEntry.review_status == "reviewed").count()
    api_authorization_matrix_coverage = round((api_matrix_reviewed / api_matrix_total) * 100, 1) if api_matrix_total else 0
    api_unresolved_authorization_review_count = db.query(models.AuthorizationReview).filter(models.AuthorizationReview.analyst_decision.in_(["open", "needs_testing"])).count()
    api_business_flow_count = db.query(models.ApiBusinessFlow).count()
    api_high_risk_flow_indicator_count = db.query(models.ApiBusinessFlowRisk).filter(models.ApiBusinessFlowRisk.severity == "high", models.ApiBusinessFlowRisk.status == "open").count()
    now = datetime.now(timezone.utc)
    soc_total_events = db.query(models.SocEvent).count()
    soc_open_alerts = db.query(models.SocAlert).filter(models.SocAlert.status.in_(["open", "investigating"])).count()
    soc_high_critical_alerts = db.query(models.SocAlert).filter(models.SocAlert.severity.in_(["high", "critical"])).count()
    soc_active_rules = db.query(models.SocDetectionRule).filter(models.SocDetectionRule.enabled == True).count()
    soc_active_blocklist_entries = db.query(models.SocBlocklistEntry).filter(models.SocBlocklistEntry.status == "active", or_(models.SocBlocklistEntry.expires_at.is_(None), models.SocBlocklistEntry.expires_at > now)).count()
    document_total_analyses = db.query(models.DocumentAnalysis).count()
    document_suspicious_high_risk = db.query(models.DocumentAnalysis).filter(models.DocumentAnalysis.classification.in_(["suspicious", "high_risk"])).count()
    document_high_critical_findings = db.query(models.DocumentFinding).filter(models.DocumentFinding.severity.in_(["high", "critical"])).count()
    document_active_content = db.query(models.DocumentAnalysis).filter(or_(models.DocumentAnalysis.has_javascript == True, models.DocumentAnalysis.has_open_action == True, models.DocumentAnalysis.has_additional_actions == True, models.DocumentAnalysis.has_launch_action == True, models.DocumentAnalysis.has_xfa == True)).count()
    phishing_total_analyses = db.query(models.PhishingAnalysis).count()
    phishing_suspicious_high_risk = db.query(models.PhishingAnalysis).filter(models.PhishingAnalysis.classification.in_(["suspicious", "high_risk"])).count()
    phishing_high_critical_findings = db.query(models.PhishingFinding).filter(models.PhishingFinding.severity.in_(["high", "critical"])).count()
    phishing_active_watchlist_entries = db.query(models.PhishingWatchlistEntry).filter(models.PhishingWatchlistEntry.status == "active").count()
    active_correlation_matches = db.query(models.CorrelationMatch).filter(models.CorrelationMatch.status != "dismissed").count()
    open_incident_cases = db.query(models.IncidentCase).filter(models.IncidentCase.status.in_(["new","triage","investigating","awaiting_review","contained_simulated"])).count()
    p1_incident_cases = db.query(models.IncidentCase).filter(models.IncidentCase.priority == "P1").count()
    high_critical_incident_cases = db.query(models.IncidentCase).filter(models.IncidentCase.severity.in_(["high","critical"])).count()
    multi_module_entities = db.query(models.UnifiedEntity).filter(models.UnifiedEntity.source_module_count > 1).count()
    governance_open_risks=db.query(models.GovernanceRisk).filter(models.GovernanceRisk.status!="closed").count()
    governance_high_critical_risks=db.query(models.GovernanceRisk).filter(models.GovernanceRisk.status!="closed",models.GovernanceRisk.severity.in_(["high","critical"])).count()
    governance_risks_exceeding_appetite=db.query(models.GovernanceRisk).filter(models.GovernanceRisk.status!="closed",models.GovernanceRisk.appetite_status=="exceeds_appetite").count()
    governance_control_gaps=db.query(models.GovernanceControlMapping).filter_by(mapping_status="candidate").count()
    governance_mappings_awaiting_review=db.query(models.GovernanceControlMapping).filter_by(mapping_status="candidate").count()
    governance_active_exceptions=db.query(models.RiskException).filter_by(status="approved").count()
    
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
    
    if "web:read" not in permissions:
        total_targets = total_scans = active_scans = total_findings = 0
        avg_risk = avg_posture = 0; distribution = {key: 0 for key in distribution}; recent_scans = []; highest_risk_targets = []
    if "api:read" not in permissions:
        api_assessment_count = api_endpoint_count = api_unauthenticated_endpoint_count = api_high_risk_endpoint_count = api_finding_count = api_high_risk_finding_count = api_owasp_observed_category_count = api_matrix_total = api_matrix_reviewed = api_unresolved_authorization_review_count = api_business_flow_count = api_high_risk_flow_indicator_count = 0; api_authorization_matrix_coverage = 0
    if "soc:read" not in permissions:
        soc_total_events = soc_open_alerts = soc_high_critical_alerts = soc_active_rules = soc_active_blocklist_entries = 0
    if "document:read" not in permissions:
        document_total_analyses = document_suspicious_high_risk = document_high_critical_findings = document_active_content = 0
    if "phishing:read" not in permissions:
        phishing_total_analyses = phishing_suspicious_high_risk = phishing_high_critical_findings = phishing_active_watchlist_entries = 0
    if "correlation:read" not in permissions:
        active_correlation_matches = multi_module_entities = 0
    if "cases:read" not in permissions:
        open_incident_cases = p1_incident_cases = high_critical_incident_cases = 0
    if "governance:read" not in permissions:
        governance_open_risks = governance_high_critical_risks = governance_risks_exceeding_appetite = governance_control_gaps = governance_mappings_awaiting_review = governance_active_exceptions = 0
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
        api_finding_count=api_finding_count,
        api_high_risk_finding_count=api_high_risk_finding_count,
        api_owasp_observed_category_count=api_owasp_observed_category_count,
        api_authorization_matrix_coverage=api_authorization_matrix_coverage,
        api_unresolved_authorization_review_count=api_unresolved_authorization_review_count,
        api_business_flow_count=api_business_flow_count,
        api_high_risk_flow_indicator_count=api_high_risk_flow_indicator_count,
        soc_total_events=soc_total_events,
        soc_open_alerts=soc_open_alerts,
        soc_high_critical_alerts=soc_high_critical_alerts,
        soc_active_rules=soc_active_rules,
        soc_active_blocklist_entries=soc_active_blocklist_entries,
        document_total_analyses=document_total_analyses,
        document_suspicious_high_risk=document_suspicious_high_risk,
        document_high_critical_findings=document_high_critical_findings,
        document_active_content=document_active_content,
        phishing_total_analyses=phishing_total_analyses,
        phishing_suspicious_high_risk=phishing_suspicious_high_risk,
        phishing_high_critical_findings=phishing_high_critical_findings,
        phishing_active_watchlist_entries=phishing_active_watchlist_entries,
        active_correlation_matches=active_correlation_matches,
        open_incident_cases=open_incident_cases,
        p1_incident_cases=p1_incident_cases,
        high_critical_incident_cases=high_critical_incident_cases,
        multi_module_entities=multi_module_entities,
        governance_open_risks=governance_open_risks,
        governance_high_critical_risks=governance_high_critical_risks,
        governance_risks_exceeding_appetite=governance_risks_exceeding_appetite,
        governance_control_gaps=governance_control_gaps,
        governance_mappings_awaiting_review=governance_mappings_awaiting_review,
        governance_active_exceptions=governance_active_exceptions,
        severity_distribution=distribution,
        recent_scans=recent_scans,
        highest_risk_targets=highest_risk_targets,
        operations=operations,
    )
