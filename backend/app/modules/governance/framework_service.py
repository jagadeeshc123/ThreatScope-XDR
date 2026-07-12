import json
from pathlib import Path
from app import models
from .service import DISCLAIMER, activity

ROOT=Path(__file__).parent/"rules"/"frameworks"


def seed(db):
    created=updated=controls_created=controls_reused=0
    for path in sorted(ROOT.glob("*.json")):
        spec=json.loads(path.read_text(encoding="utf-8"));framework=db.query(models.GovernanceFramework).filter_by(framework_key=spec["framework_key"]).first()
        if not framework:
            framework=models.GovernanceFramework(framework_key=spec["framework_key"],name=spec["name"],version=spec["version"],description=spec["description"],source_note=spec["source_note"],disclaimer=DISCLAIMER+" Bundled summaries do not replace official publications.");db.add(framework);db.flush();created+=1
        else:
            framework.name=spec["name"];framework.version=spec["version"];framework.description=spec["description"];framework.source_note=spec["source_note"];framework.disclaimer=DISCLAIMER+" Bundled summaries do not replace official publications.";updated+=1
        for order,item in enumerate(spec["controls"]):
            control=db.query(models.GovernanceControl).filter_by(framework_id=framework.id,control_key=item[0]).first()
            if not control:
                db.add(models.GovernanceControl(framework_id=framework.id,control_key=item[0],title=item[1],summary=item[2],control_type=item[3],sort_order=order));controls_created+=1
            else:controls_reused+=1
        db.flush();framework.control_count=db.query(models.GovernanceControl).filter_by(framework_id=framework.id).count()
    if created:activity(db,"governance_framework_seeded",f"Seeded {created} local framework catalogs.")
    db.commit();return {"frameworks_created":created,"frameworks_updated":updated,"controls_created":controls_created,"controls_reused":controls_reused,"frameworks_total":db.query(models.GovernanceFramework).count(),"controls_total":db.query(models.GovernanceControl).count()}
