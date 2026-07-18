from sqlalchemy.orm import Session

from app.models import Target

from .configuration_service import get_operations_config
from .maintenance_service import add_activity, notify
from .models import utcnow

DEMO_TARGET_NAME = "ThreatScope Synthetic Demo Target"
SCENARIOS = ["Web Exposure", "API Authorization", "SOC Detection", "Document Threat", "Phishing", "Correlation", "Incident Case", "Governance Evidence"]


def require_demo_mode():
    if not get_operations_config().demo_mode: raise ValueError("Demo mode is not enabled")


def status(db: Session) -> dict:
    target = db.query(Target).filter_by(name=DEMO_TARGET_NAME).first()
    from app.modules.vulnerability_management.models import Asset
    vm_assets = db.query(Asset).filter_by(source_module="platform_operations_demo").count()
    return {"demo_mode": get_operations_config().demo_mode, "seeded": bool(target), "record_counts": {"web_targets": 1 if target else 0, "vulnerability_management_assets": vm_assets}, "last_seed_time": target.created_at if target else None, "scenarios": SCENARIOS, "synthetic_data": True, "local_target_restriction": True, "demo_users_created": False}


def seed(db: Session) -> dict:
    require_demo_mode(); target = db.query(Target).filter_by(name=DEMO_TARGET_NAME).first()
    created = False
    if not target:
        target = Target(name=DEMO_TARGET_NAME, base_url="http://192.0.2.10", domain="demo.example.test", authorization_confirmed=True, environment="synthetic-demo")
        db.add(target); db.flush(); created = True
    from app.modules.vulnerability_management.service import get_or_create_asset
    get_or_create_asset(db, asset_type="custom", identifier="threatscope-synthetic-demo-asset", name="ThreatScope Synthetic Demo Asset", source_module="platform_operations_demo", source_entity_type="target", source_entity_id=target.id, observed_at=target.created_at, defaults={"environment": "testing", "tags": ["threatscope-demo"]})
    add_activity(db, "demo_seeded", "Deterministic synthetic demo environment seeded locally.", "operational_demo", target.id); notify(db,"Demo seed succeeded","Synthetic local demo records are ready.","success","operational_demo",target.id); db.commit()
    return {**status(db), "created": created, "credentials_created": False}


def reset(db: Session) -> dict:
    require_demo_mode(); targets = db.query(Target).filter_by(name=DEMO_TARGET_NAME, environment="synthetic-demo").all(); count = len(targets)
    from app.modules.vulnerability_management.models import Asset
    demo_vm_assets = db.query(Asset).filter_by(source_module="platform_operations_demo").all()
    for asset in demo_vm_assets: db.delete(asset)
    for target in targets: db.delete(target)
    from app.modules.threat_intelligence.models import ThreatIndicator, ThreatIntelSource
    demo_indicators = db.query(ThreatIndicator).filter(ThreatIndicator.tags_json.like('%"threatscope-demo"%')).all()
    for indicator in demo_indicators: db.delete(indicator)
    demo_sources = db.query(ThreatIntelSource).filter_by(name="ThreatScope Synthetic Demo Intelligence", system_owned=True).all()
    for source in demo_sources: db.delete(source)
    from app.modules.detection_engineering.models import DetectionExecution, DetectionRule
    demo_rules = db.query(DetectionRule).filter(DetectionRule.tags_json.like('%"threatscope-demo"%'), DetectionRule.system_owned.is_(False)).all()
    demo_rule_ids = [rule.id for rule in demo_rules]
    demo_detection_executions = db.query(DetectionExecution).filter(DetectionExecution.rule_id.in_(demo_rule_ids)).all() if demo_rule_ids else []
    for execution in demo_detection_executions: db.delete(execution)
    for rule in demo_rules: db.delete(rule)
    from app.modules.soar.models import SoarAnalystInput, SoarApproval, SoarApprovalDecision, SoarExecution, SoarExecutionEvent, SoarExecutionEvidence, SoarPlaybook, SoarPlaybookStep, SoarPlaybookVersion, SoarReport, SoarRollbackRecord, SoarStepExecution, SoarTriggerRule
    demo_executions = db.query(SoarExecution).filter_by(demo_owned=True).all()
    demo_execution_ids = [item.id for item in demo_executions]
    demo_step_ids = [row[0] for row in db.query(SoarStepExecution.id).filter(SoarStepExecution.execution_id.in_(demo_execution_ids)).all()] if demo_execution_ids else []
    demo_approval_ids = [row[0] for row in db.query(SoarApproval.id).filter(SoarApproval.execution_id.in_(demo_execution_ids)).all()] if demo_execution_ids else []
    if demo_approval_ids: db.query(SoarApprovalDecision).filter(SoarApprovalDecision.approval_id.in_(demo_approval_ids)).delete(synchronize_session=False)
    if demo_execution_ids:
        db.query(SoarRollbackRecord).filter(SoarRollbackRecord.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarAnalystInput).filter(SoarAnalystInput.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarApproval).filter(SoarApproval.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarExecutionEvidence).filter(SoarExecutionEvidence.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarExecutionEvent).filter(SoarExecutionEvent.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarStepExecution).filter(SoarStepExecution.execution_id.in_(demo_execution_ids)).delete(synchronize_session=False)
        db.query(SoarExecution).filter(SoarExecution.id.in_(demo_execution_ids)).delete(synchronize_session=False)
    demo_playbooks = db.query(SoarPlaybook).filter_by(demo_owned=True, system_owned=False).all(); demo_playbook_ids = [item.id for item in demo_playbooks]
    if demo_playbook_ids:
        db.query(SoarTriggerRule).filter(SoarTriggerRule.playbook_id.in_(demo_playbook_ids)).delete(synchronize_session=False)
        db.query(SoarPlaybookStep).filter(SoarPlaybookStep.playbook_id.in_(demo_playbook_ids)).delete(synchronize_session=False)
        db.query(SoarPlaybookVersion).filter(SoarPlaybookVersion.playbook_id.in_(demo_playbook_ids)).delete(synchronize_session=False)
        db.query(SoarPlaybook).filter(SoarPlaybook.id.in_(demo_playbook_ids)).delete(synchronize_session=False)
    demo_soar_reports = db.query(SoarReport).filter_by(demo_owned=True).delete(synchronize_session=False)
    add_activity(db, "demo_reset", f"Removed {count} demo-owned target records; analyst records were preserved.", "operational_demo", None); notify(db,"Demo reset succeeded",f"Removed {count} demo-owned records and preserved analyst data.","success","operational_demo",None); db.commit()
    return {**status(db), "deleted_demo_records": count + len(demo_vm_assets) + len(demo_indicators) + len(demo_sources) + len(demo_rules) + len(demo_detection_executions) + len(demo_executions) + len(demo_playbooks) + demo_soar_reports, "deleted_demo_vulnerability_management_records": len(demo_vm_assets), "deleted_demo_threat_intel_records": len(demo_indicators) + len(demo_sources), "deleted_demo_detection_records": len(demo_rules) + len(demo_detection_executions), "deleted_demo_soar_records": len(demo_executions) + len(demo_playbooks) + demo_soar_reports, "non_demo_records_preserved": True, "protected_soar_templates_preserved": True}
