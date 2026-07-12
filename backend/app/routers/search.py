from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app import schemas, models
from app.database import get_db
from app.modules.api_security.service import endpoint_to_schema, jwt_to_schema, report_to_schema

router = APIRouter()

@router.get("/", response_model=schemas.SearchResults)
def search(q: str = "", db: Session = Depends(get_db)):
    if not q or len(q) < 2:
        return schemas.SearchResults(targets=[], scans=[], findings=[], reports=[], api_assessments=[], api_endpoints=[], api_findings=[], jwt_analyses=[], api_reports=[], api_roles=[], authorization_reviews=[], api_business_flows=[], api_business_flow_risks=[], soc_events=[], soc_alerts=[], soc_rules=[], soc_reports=[], soc_blocklist_entries=[], document_analyses=[], document_findings=[], document_indicators=[], document_reports=[], phishing_analyses=[], phishing_findings=[], phishing_indicators=[], phishing_watchlist_entries=[], phishing_reports=[], unified_entities=[], correlation_matches=[], incident_cases=[], incident_evidence=[], incident_reports=[], governance_risks=[], governance_frameworks=[], governance_controls=[], governance_mappings=[], governance_treatments=[], governance_exceptions=[], governance_evidence_packages=[], governance_reviews=[], governance_reports=[])
        
    query = f"%{q}%"
    
    targets = db.query(models.Target).filter(
        or_(
            models.Target.name.ilike(query),
            models.Target.domain.ilike(query),
            models.Target.base_url.ilike(query)
        )
    ).limit(10).all()
    
    scans = db.query(models.Scan).join(models.Target).filter(
        or_(
            models.Scan.profile.ilike(query),
            models.Scan.status.ilike(query),
            models.Target.name.ilike(query)
        )
    ).limit(10).all()
    
    findings = db.query(models.Finding).filter(
        or_(
            models.Finding.title.ilike(query),
            models.Finding.category.ilike(query),
            models.Finding.severity.ilike(query),
            models.Finding.affected_url.ilike(query)
        )
    ).limit(15).all()
    
    reports = db.query(models.Report).join(models.Target).filter(
        or_(
            models.Report.title.ilike(query),
            models.Target.name.ilike(query)
        )
    ).limit(10).all()

    api_assessments = db.query(models.ApiAssessment).filter(
        or_(
            models.ApiAssessment.name.ilike(query),
            models.ApiAssessment.description.ilike(query),
            models.ApiAssessment.source_filename.ilike(query),
            models.ApiAssessment.base_url.ilike(query),
        )
    ).limit(10).all()

    api_endpoints = db.query(models.ApiEndpoint).filter(
        or_(
            models.ApiEndpoint.path.ilike(query),
            models.ApiEndpoint.method.ilike(query),
            models.ApiEndpoint.summary.ilike(query),
            models.ApiEndpoint.operation_id.ilike(query),
            models.ApiEndpoint.tags_json.ilike(query),
        )
    ).limit(15).all()

    api_findings = db.query(models.ApiFinding).filter(
        or_(
            models.ApiFinding.title.ilike(query),
            models.ApiFinding.severity.ilike(query),
            models.ApiFinding.owasp_category.ilike(query),
            models.ApiFinding.source.ilike(query),
        )
    ).limit(15).all()

    jwt_analyses = db.query(models.JwtAnalysis).filter(
        or_(
            models.JwtAnalysis.token_fingerprint.ilike(query),
            models.JwtAnalysis.algorithm.ilike(query),
            models.JwtAnalysis.issuer.ilike(query),
            models.JwtAnalysis.expiration_status.ilike(query),
        )
    ).limit(10).all()

    api_reports = db.query(models.ApiReport).filter(
        or_(
            models.ApiReport.title.ilike(query),
            models.ApiReport.executive_summary.ilike(query),
        )
    ).limit(10).all()

    api_roles = db.query(models.ApiRole).filter(or_(models.ApiRole.name.ilike(query), models.ApiRole.description.ilike(query), models.ApiRole.privilege_level.ilike(query))).limit(10).all()
    authorization_reviews = db.query(models.AuthorizationReview).filter(or_(models.AuthorizationReview.review_type.ilike(query), models.AuthorizationReview.risk_indicator.ilike(query), models.AuthorizationReview.expected_behavior.ilike(query), models.AuthorizationReview.analyst_decision.ilike(query))).limit(15).all()
    api_business_flows = db.query(models.ApiBusinessFlow).filter(or_(models.ApiBusinessFlow.name.ilike(query), models.ApiBusinessFlow.description.ilike(query), models.ApiBusinessFlow.business_goal.ilike(query))).limit(10).all()
    api_business_flow_risks = db.query(models.ApiBusinessFlowRisk).join(models.ApiBusinessFlow).filter(or_(models.ApiBusinessFlowRisk.title.ilike(query), models.ApiBusinessFlowRisk.risk_type.ilike(query), models.ApiBusinessFlowRisk.evidence_summary.ilike(query))).limit(15).all()
    soc_events = db.query(models.SocEvent).filter(or_(models.SocEvent.message.ilike(query), models.SocEvent.raw_preview_redacted.ilike(query), models.SocEvent.source_ip.ilike(query), models.SocEvent.username.ilike(query), models.SocEvent.request_path.ilike(query))).limit(15).all()
    soc_alerts = db.query(models.SocAlert).filter(or_(models.SocAlert.title.ilike(query), models.SocAlert.evidence_summary.ilike(query), models.SocAlert.source_ip.ilike(query), models.SocAlert.username.ilike(query))).limit(15).all()
    soc_rules = db.query(models.SocDetectionRule).filter(or_(models.SocDetectionRule.rule_code.ilike(query), models.SocDetectionRule.name.ilike(query), models.SocDetectionRule.description.ilike(query))).limit(10).all()
    soc_reports = db.query(models.SocReport).filter(models.SocReport.title.ilike(query)).limit(10).all()
    soc_blocklist_entries = db.query(models.SocBlocklistEntry).filter(or_(models.SocBlocklistEntry.indicator_value.ilike(query), models.SocBlocklistEntry.reason.ilike(query))).limit(10).all()
    document_analyses = db.query(models.DocumentAnalysis).filter(or_(models.DocumentAnalysis.filename_sanitized.ilike(query), models.DocumentAnalysis.file_hash.ilike(query), models.DocumentAnalysis.classification.ilike(query))).limit(10).all()
    document_findings = db.query(models.DocumentFinding).filter(or_(models.DocumentFinding.rule_code.ilike(query), models.DocumentFinding.title.ilike(query), models.DocumentFinding.category.ilike(query), models.DocumentFinding.evidence_summary.ilike(query))).limit(15).all()
    document_indicators = db.query(models.DocumentIndicator).filter(or_(models.DocumentIndicator.display_value_redacted.ilike(query), models.DocumentIndicator.context.ilike(query))).limit(15).all()
    document_reports = db.query(models.DocumentReport).filter(models.DocumentReport.title.ilike(query)).limit(10).all()
    phishing_analyses = db.query(models.PhishingAnalysis).filter(or_(models.PhishingAnalysis.subject_redacted.ilike(query), models.PhishingAnalysis.sender_address_redacted.ilike(query), models.PhishingAnalysis.source_hash.ilike(query), models.PhishingAnalysis.classification.ilike(query))).limit(10).all()
    phishing_findings = db.query(models.PhishingFinding).filter(or_(models.PhishingFinding.rule_code.ilike(query), models.PhishingFinding.title.ilike(query), models.PhishingFinding.category.ilike(query), models.PhishingFinding.evidence_summary.ilike(query))).limit(15).all()
    phishing_indicators = db.query(models.PhishingIndicator).filter(or_(models.PhishingIndicator.display_value_redacted.ilike(query), models.PhishingIndicator.context.ilike(query))).limit(15).all()
    phishing_watchlist_entries = db.query(models.PhishingWatchlistEntry).filter(or_(models.PhishingWatchlistEntry.display_value_redacted.ilike(query), models.PhishingWatchlistEntry.reason.ilike(query))).limit(10).all()
    phishing_reports = db.query(models.PhishingReport).filter(models.PhishingReport.title.ilike(query)).limit(10).all()
    unified_entities=db.query(models.UnifiedEntity).filter(or_(models.UnifiedEntity.display_value_redacted.ilike(query),models.UnifiedEntity.value_hash.ilike(query))).limit(10).all()
    correlation_matches=db.query(models.CorrelationMatch).filter(or_(models.CorrelationMatch.title.ilike(query),models.CorrelationMatch.explanation.ilike(query),models.CorrelationMatch.rule_code.ilike(query))).limit(10).all()
    incident_cases=db.query(models.IncidentCase).filter(or_(models.IncidentCase.title.ilike(query),models.IncidentCase.summary.ilike(query),models.IncidentCase.case_key.ilike(query))).limit(10).all()
    incident_evidence=db.query(models.IncidentEvidence).filter(or_(models.IncidentEvidence.title_snapshot.ilike(query),models.IncidentEvidence.evidence_snapshot.ilike(query))).limit(10).all()
    incident_reports=db.query(models.IncidentReport).filter(models.IncidentReport.title.ilike(query)).limit(10).all()
    governance_risks=db.query(models.GovernanceRisk).filter(or_(models.GovernanceRisk.risk_key.ilike(query),models.GovernanceRisk.title.ilike(query),models.GovernanceRisk.description.ilike(query),models.GovernanceRisk.owner_name.ilike(query))).limit(15).all()
    governance_frameworks=db.query(models.GovernanceFramework).filter(or_(models.GovernanceFramework.name.ilike(query),models.GovernanceFramework.version.ilike(query),models.GovernanceFramework.framework_key.ilike(query))).limit(10).all()
    governance_controls=db.query(models.GovernanceControl).filter(or_(models.GovernanceControl.control_key.ilike(query),models.GovernanceControl.title.ilike(query),models.GovernanceControl.summary.ilike(query))).limit(15).all()
    governance_mappings=db.query(models.GovernanceControlMapping).filter(or_(models.GovernanceControlMapping.rationale.ilike(query),models.GovernanceControlMapping.analyst_notes.ilike(query))).limit(10).all()
    governance_treatments=db.query(models.RiskTreatmentPlan).filter(or_(models.RiskTreatmentPlan.title.ilike(query),models.RiskTreatmentPlan.description.ilike(query),models.RiskTreatmentPlan.owner_name.ilike(query))).limit(10).all()
    governance_exceptions=db.query(models.RiskException).filter(or_(models.RiskException.exception_key.ilike(query),models.RiskException.justification.ilike(query),models.RiskException.approver_name.ilike(query))).limit(10).all()
    governance_evidence_packages=db.query(models.GovernanceEvidencePackage).filter(or_(models.GovernanceEvidencePackage.package_key.ilike(query),models.GovernanceEvidencePackage.title.ilike(query),models.GovernanceEvidencePackage.description.ilike(query))).limit(10).all()
    governance_reviews=db.query(models.GovernanceReview).filter(or_(models.GovernanceReview.review_key.ilike(query),models.GovernanceReview.title.ilike(query),models.GovernanceReview.scope_summary.ilike(query))).limit(10).all()
    governance_reports=db.query(models.GovernanceReport).filter(models.GovernanceReport.title.ilike(query)).limit(10).all()
    
    return schemas.SearchResults(
        targets=targets,
        scans=scans,
        findings=findings,
        reports=reports,
        api_assessments=[{
            "id": item.id,
            "name": item.name,
            "status": item.status,
            "source_type": item.source_type,
            "endpoint_count": item.endpoint_count,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in api_assessments],
        api_endpoints=[endpoint_to_schema(item) for item in api_endpoints],
        api_findings=[{
            "id": item.id,
            "assessment_id": item.assessment_id,
            "title": item.title,
            "severity": item.severity,
            "owasp_category": item.owasp_category,
            "source": item.source,
            "created_at": item.created_at.isoformat() if item.created_at else None,
        } for item in api_findings],
        jwt_analyses=[jwt_to_schema(item) for item in jwt_analyses],
        api_reports=[report_to_schema(item) for item in api_reports],
        api_roles=[{"id": item.id, "assessment_id": item.assessment_id, "name": item.name, "privilege_level": item.privilege_level, "description": item.description} for item in api_roles],
        authorization_reviews=[{"id": item.id, "assessment_id": item.assessment_id, "endpoint_id": item.endpoint_id, "review_type": item.review_type, "severity": item.severity, "risk_indicator": item.risk_indicator, "analyst_decision": item.analyst_decision} for item in authorization_reviews],
        api_business_flows=[{"id": item.id, "assessment_id": item.assessment_id, "name": item.name, "description": item.description, "status": item.status, "risk_score": item.risk_score} for item in api_business_flows],
        api_business_flow_risks=[{"id": item.id, "flow_id": item.flow_id, "assessment_id": item.flow.assessment_id, "title": item.title, "severity": item.severity, "status": item.status, "risk_type": item.risk_type} for item in api_business_flow_risks],
        soc_events=[{"id": item.id, "event_type": item.event_type, "severity": item.severity, "event_time": item.event_time, "source_ip": item.source_ip, "username": item.username, "snippet": (item.message or item.raw_preview_redacted or "")[:240]} for item in soc_events],
        soc_alerts=[{"id": item.id, "title": item.title, "severity": item.severity, "status": item.status, "snippet": item.evidence_summary[:240]} for item in soc_alerts],
        soc_rules=[{"id": item.id, "rule_code": item.rule_code, "name": item.name, "severity": item.severity, "enabled": item.enabled} for item in soc_rules],
        soc_reports=[{"id": item.id, "title": item.title, "created_at": item.created_at} for item in soc_reports],
        soc_blocklist_entries=[{"id": item.id, "indicator_type": item.indicator_type, "indicator_value": item.indicator_value, "status": item.status, "reason": item.reason[:240]} for item in soc_blocklist_entries],
        document_analyses=[{"id": item.id, "filename_sanitized": item.filename_sanitized, "file_hash": item.file_hash, "classification": item.classification, "risk_score": item.risk_score, "created_at": item.created_at} for item in document_analyses],
        document_findings=[{"id": item.id, "analysis_id": item.analysis_id, "rule_code": item.rule_code, "title": item.title, "severity": item.severity, "snippet": item.evidence_summary[:240]} for item in document_findings],
        document_indicators=[{"id": item.id, "analysis_id": item.analysis_id, "indicator_type": item.indicator_type, "display_value_redacted": item.display_value_redacted, "snippet": item.context[:240]} for item in document_indicators],
        document_reports=[{"id": item.id, "analysis_id": item.analysis_id, "title": item.title, "created_at": item.created_at} for item in document_reports],
        phishing_analyses=[{"id": item.id, "subject_redacted": item.subject_redacted, "sender_address_redacted": item.sender_address_redacted, "source_hash": item.source_hash, "classification": item.classification, "final_risk_score": item.final_risk_score, "created_at": item.created_at} for item in phishing_analyses],
        phishing_findings=[{"id": item.id, "analysis_id": item.analysis_id, "rule_code": item.rule_code, "title": item.title, "severity": item.severity, "snippet": item.evidence_summary[:240]} for item in phishing_findings],
        phishing_indicators=[{"id": item.id, "analysis_id": item.analysis_id, "indicator_type": item.indicator_type, "display_value_redacted": item.display_value_redacted, "snippet": item.context[:240]} for item in phishing_indicators],
        phishing_watchlist_entries=[{"id": item.id, "indicator_type": item.indicator_type, "display_value_redacted": item.display_value_redacted, "status": item.status, "reason": item.reason[:240]} for item in phishing_watchlist_entries],
        phishing_reports=[{"id": item.id, "analysis_id": item.analysis_id, "title": item.title, "created_at": item.created_at} for item in phishing_reports],
        unified_entities=[{"id":x.id,"entity_type":x.entity_type,"display_value_redacted":x.display_value_redacted,"value_hash":x.value_hash,"severity":x.severity,"risk_score":x.risk_score} for x in unified_entities],
        correlation_matches=[{"id":x.id,"rule_code":x.rule_code,"title":x.title,"severity":x.severity,"status":x.status,"snippet":x.explanation[:240]} for x in correlation_matches],
        incident_cases=[{"id":x.id,"case_key":x.case_key,"title":x.title,"status":x.status,"priority":x.priority,"severity":x.severity} for x in incident_cases],
        incident_evidence=[{"id":x.id,"case_id":x.case_id,"title_snapshot":x.title_snapshot,"snippet":x.evidence_snapshot[:240]} for x in incident_evidence],
        incident_reports=[{"id":x.id,"case_id":x.case_id,"title":x.title,"created_at":x.created_at} for x in incident_reports],
        governance_risks=[{"id":x.id,"risk_key":x.risk_key,"title":x.title,"status":x.status,"severity":x.severity,"snippet":x.description[:240]} for x in governance_risks],
        governance_frameworks=[{"id":x.id,"framework_key":x.framework_key,"name":x.name,"version":x.version,"enabled":x.enabled} for x in governance_frameworks],
        governance_controls=[{"id":x.id,"framework_id":x.framework_id,"control_key":x.control_key,"title":x.title,"snippet":x.summary[:240]} for x in governance_controls],
        governance_mappings=[{"id":x.id,"risk_id":x.risk_id,"control_id":x.control_id,"mapping_status":x.mapping_status,"confidence":x.confidence,"snippet":x.rationale[:240]} for x in governance_mappings],
        governance_treatments=[{"id":x.id,"risk_id":x.risk_id,"title":x.title,"status":x.status,"strategy":x.strategy} for x in governance_treatments],
        governance_exceptions=[{"id":x.id,"risk_id":x.risk_id,"exception_key":x.exception_key,"status":x.status,"justification":x.justification[:240]} for x in governance_exceptions],
        governance_evidence_packages=[{"id":x.id,"package_key":x.package_key,"title":x.title,"status":x.status} for x in governance_evidence_packages],
        governance_reviews=[{"id":x.id,"review_key":x.review_key,"title":x.title,"status":x.status,"review_type":x.review_type} for x in governance_reviews],
        governance_reports=[{"id":x.id,"title":x.title,"report_type":x.report_type,"created_at":x.created_at} for x in governance_reports],
    )
