import hashlib,json,time
from pathlib import Path
from app import models
from .redaction import redact
from .service import activity,notify_once

RULES=Path(__file__).parent/"rules"/"mapping_rules.json"


def generate(db,risk_ids=None,source_modules=None,framework_keys=None,minimum_confidence="low"):
    started=time.perf_counter();rules=json.loads(RULES.read_text(encoding="utf-8"));rank={"low":1,"medium":2,"high":3};query=db.query(models.GovernanceRisk)
    if risk_ids:query=query.filter(models.GovernanceRisk.id.in_(risk_ids))
    risks=query.all();created=reused=skipped=sources=0;errors=[]
    enabled={x.framework_key:x for x in db.query(models.GovernanceFramework).filter_by(enabled=True)}
    for risk in risks:
        for rule in rules:
            if risk.category not in rule["categories"] or rank[rule["confidence"]]<rank.get(minimum_confidence,1):continue
            for reference in rule["controls"]:
                framework_key,control_key=reference.split(":",1);framework=enabled.get(framework_key)
                if not framework or framework_keys and framework_key not in framework_keys:skipped+=1;continue
                control=db.query(models.GovernanceControl).filter_by(framework_id=framework.id,control_key=control_key,enabled=True).first()
                if not control:skipped+=1;continue
                source=next((x for x in risk.sources if not source_modules or x.source_module in source_modules),None);sources+=1 if source else 0
                fingerprint=hashlib.sha256(f"{risk.id}:{control.id}:deterministic_rule".encode()).hexdigest();mapping=db.query(models.GovernanceControlMapping).filter_by(mapping_fingerprint=fingerprint).first()
                if mapping:reused+=1;continue
                rationale=redact(f"Deterministic local rule relates {risk.category} evidence to {framework.name} {control.control_key}. Analyst confirmation is required.",1000);evidence=redact(source.evidence_snapshot if source else risk.description,1000)
                db.add(models.GovernanceControlMapping(risk_id=risk.id,source_module=source.source_module if source else None,source_record_type=source.source_record_type if source else None,source_record_id=source.source_record_id if source else None,control_id=control.id,confidence=rule["confidence"],rationale=rationale,evidence_summary=evidence,mapping_fingerprint=fingerprint));created+=1
    db.flush()
    for risk in risks:risk.control_mapping_count=db.query(models.GovernanceControlMapping).filter_by(risk_id=risk.id).count()
    if created:notify_once(db,"Governance Mappings Await Review",f"{created} deterministic candidate mappings require analyst review.","info","governance_mapping",None)
    activity(db,"governance_mapping_generated",f"Generated {created} candidate mappings; {reused} reused.");db.commit();return {"risks_evaluated":len(risks),"source_records_evaluated":sources,"rules_evaluated":len(rules),"candidates_created":created,"candidates_reused":reused,"candidates_skipped":skipped,"errors":errors,"duration_ms":round((time.perf_counter()-started)*1000,2)}
