from sqlalchemy import func
from app import models
from .service import dump


def control_coverage(db,control):
    mappings=db.query(models.GovernanceControlMapping).filter_by(control_id=control.id).all();confirmed=[x for x in mappings if x.mapping_status=="confirmed"];na=[x for x in mappings if x.mapping_status=="not_applicable"]
    evidence=db.query(models.GovernanceEvidenceItem).filter_by(control_id=control.id).all();critical=any(x.risk and x.risk.status not in {"closed","mitigated"} and x.risk.severity=="critical" for x in confirmed)
    if na and not confirmed:status="not_applicable"
    elif confirmed and evidence:status="partial" if critical else "supported"
    elif confirmed:status="partial"
    elif any(x.mapping_status=="candidate" for x in mappings):status="gap"
    else:status="not_assessed"
    return {"control":dump(control),"status":status,"confirmed_mappings":len(confirmed),"candidate_mappings":sum(x.mapping_status=="candidate" for x in mappings),"evidence_items":len(evidence),"explanation":f"Evidence-based status: {status.replace('_',' ')}. Candidate relationships are excluded from confirmed coverage.","contributing_evidence":[dump(x) for x in evidence],"open_gaps":[dump(x) for x in mappings if x.mapping_status=="candidate"]}


def framework_coverage(db,framework):
    rows=[control_coverage(db,x) for x in framework.controls if x.enabled];counts={x:sum(r["status"]==x for r in rows) for x in ["supported","partial","gap","not_assessed","not_applicable"]};assessed=len(rows)-counts["not_assessed"];coverage=round((counts["supported"]+counts["partial"]*.5)/len(rows)*100,1) if rows else 0
    return {"framework":dump(framework),"total_controls":len(rows),"assessed_controls":assessed,"supported_controls":counts["supported"],"partial_controls":counts["partial"],"gap_controls":counts["gap"],"not_assessed_controls":counts["not_assessed"],"not_applicable_controls":counts["not_applicable"],"evidence_coverage_percentage":coverage,"controls_by_status":counts,"top_gaps":[r for r in rows if r["status"]=="gap"][:10],"recently_changed_controls":[],"controls":rows}


def summary(db):return [framework_coverage(db,x) for x in db.query(models.GovernanceFramework).filter_by(enabled=True).all()]
