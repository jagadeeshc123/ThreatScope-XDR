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
        return schemas.SearchResults(targets=[], scans=[], findings=[], reports=[], api_assessments=[], api_endpoints=[], api_findings=[], jwt_analyses=[], api_reports=[], api_roles=[], authorization_reviews=[], api_business_flows=[], api_business_flow_risks=[])
        
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
    )
