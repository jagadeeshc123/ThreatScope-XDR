from app import models
from .common import row


def candidates(db, limit=500):
    out=[]
    for x in db.query(models.ApiFinding).limit(limit):out.append(row("api_security","finding",x,"api_security",x.title,getattr(x,"evidence",None) or getattr(x,"description",None),x.severity,getattr(x,"confidence","medium"),f"/api-security/assessments/{x.assessment_id}"))
    for x in db.query(models.AuthorizationReview).limit(limit):out.append(row("api_security","authorization_review",x,"authorization",f"Authorization review: {x.review_type}",f"{x.risk_indicator}; decision={x.analyst_decision}",x.severity,x.confidence,f"/api-security/assessments/{x.assessment_id}/authorization-reviews"))
    for x in db.query(models.AuthorizationMatrixEntry).limit(limit):out.append(row("api_security","authorization_matrix",x,"authorization","Authorization matrix coverage gap",f"Expected={x.expected_access}; review={x.review_status}","medium","medium",f"/api-security/assessments/{x.assessment_id}/authorization"))
    for x in db.query(models.ApiBusinessFlowRisk).limit(limit):out.append(row("api_security","business_flow_risk",x,"business_flow",x.title,x.evidence_summary,x.severity,x.confidence,f"/api-security/business-flows/{x.flow_id}"))
    return out
