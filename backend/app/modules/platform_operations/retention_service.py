import json
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import Notification
from app.modules.access_control.models import AuthSession, LoginAttempt, MfaLoginChallenge
from app.modules.soc_monitor.models import SocActivity
from app.modules.threat_intelligence.models import ThreatCorrelationRun, ThreatIntelImport
from app.modules.detection_engineering.models import DetectionExecution, DetectionReport
from app.modules.vulnerability_management.models import AssetSynchronizationRun, VulnerabilityIngestionRun
from app.modules.soar.models import SoarExecution, SoarReport
from app.modules.integrations.models import ConnectorDelivery, ConnectorDeliveryAttempt, ConnectorHealthCheck, ConnectorInboundEvent, ConnectorReplayNonce, ConnectorReport, ConnectorInboundRateCounter

from .maintenance_service import add_activity, new_key, notify
from .models import ExportPackage, OperationalJob, RetentionPolicy, RetentionRun, BackupRecord, utcnow

DEFAULTS = [
    ("successful_jobs", "Old successful operational jobs", "operational_jobs", 90, 50),
    ("deleted_backups", "Deleted backup metadata", "deleted_backups", 365, 10),
    ("deleted_exports", "Deleted export metadata", "deleted_exports", 180, 10),
    ("login_attempts", "Expired login-attempt history", "login_attempts", 90, 100),
    ("revoked_sessions", "Revoked expired sessions", "revoked_sessions", 30, 20),
    ("used_mfa_challenges", "Used MFA challenges", "used_mfa_challenges", 7, 20),
    ("read_notifications", "Old read notifications", "read_notifications", 90, 20),
    ("old_activity", "Old operational activity", "old_activity", 180, 100),
    ("threat_intel_import_manifests", "Old threat-intelligence import manifests", "threat_intel_import_manifests", 365, 50),
    ("threat_correlation_runs", "Old completed threat-intelligence correlation runs", "threat_correlation_runs", 180, 50),
    ("detection_executions", "Old completed detection executions", "detection_executions", 180, 50),
    ("detection_reports", "Old generated detection reports", "detection_reports", 365, 25),
    ("vm_asset_sync_runs", "Old completed asset synchronization runs", "vm_asset_sync_runs", 180, 25),
    ("vm_ingestion_runs", "Old completed vulnerability ingestion runs", "vm_ingestion_runs", 180, 25),
    ("soar_dry_runs", "Old terminal SOAR dry runs", "soar_dry_runs", 90, 50),
    ("soar_simulations", "Old terminal SOAR simulations", "soar_simulations", 180, 50),
    ("soar_live_local_executions", "Old terminal SOAR live-local executions", "soar_live_local_executions", 365, 100),
    ("soar_reports", "Old generated SOAR reports", "soar_reports", 365, 25),
    ("integration_delivery_attempts", "Old connector delivery attempts", "integration_delivery_attempts", 180, 100),
    ("integration_successful_deliveries", "Old successful connector deliveries", "integration_successful_deliveries", 180, 100),
    ("integration_rejected_inbound", "Old rejected inbound events", "integration_rejected_inbound", 90, 100),
    ("integration_health_checks", "Old connector health checks", "integration_health_checks", 90, 50),
    ("integration_replay_nonces", "Expired inbound replay nonces", "integration_replay_nonces", 1, 0),
    ("integration_inbound_rate_counters", "Expired inbound rate counters", "integration_inbound_rate_counters", 1, 0),
    ("integration_reports", "Old integration reports", "integration_reports", 365, 25),
]


def seed_policies(db: Session):
    for key, name, entity, days, keep in DEFAULTS:
        if not db.query(RetentionPolicy).filter_by(policy_key=key).first():
            db.add(RetentionPolicy(policy_key=key, name=name, entity_type=entity, retention_days=days, enabled=True, dry_run_only=True, minimum_keep_count=keep))
    db.commit()


def _model_and_filters(policy: RetentionPolicy):
    now = utcnow(); cutoff = now - timedelta(days=policy.retention_days)
    if policy.entity_type == "operational_jobs": return OperationalJob, [OperationalJob.status == "succeeded", OperationalJob.completed_at < cutoff]
    if policy.entity_type == "deleted_backups": return BackupRecord, [BackupRecord.deleted_at.is_not(None), BackupRecord.deleted_at < cutoff, BackupRecord.protected.is_(False)]
    if policy.entity_type == "deleted_exports": return ExportPackage, [ExportPackage.deleted_at.is_not(None), ExportPackage.deleted_at < cutoff]
    if policy.entity_type == "login_attempts": return LoginAttempt, [LoginAttempt.attempted_at < cutoff]
    if policy.entity_type == "revoked_sessions": return AuthSession, [AuthSession.revoked_at.is_not(None), AuthSession.expires_at < now]
    if policy.entity_type == "used_mfa_challenges": return MfaLoginChallenge, [MfaLoginChallenge.used_at.is_not(None), MfaLoginChallenge.used_at < cutoff]
    if policy.entity_type == "read_notifications": return Notification, [Notification.is_read.is_(True), Notification.created_at < cutoff]
    if policy.entity_type == "old_activity": return SocActivity, [SocActivity.created_at < cutoff, SocActivity.entity_type.like("operational_%")]
    if policy.entity_type == "threat_intel_import_manifests": return ThreatIntelImport, [ThreatIntelImport.completed_at.is_not(None), ThreatIntelImport.completed_at < cutoff]
    if policy.entity_type == "threat_correlation_runs": return ThreatCorrelationRun, [ThreatCorrelationRun.status.in_(["completed", "failed"]), ThreatCorrelationRun.completed_at < cutoff]
    if policy.entity_type == "detection_executions": return DetectionExecution, [DetectionExecution.status.in_(["completed", "failed", "cancelled"]), DetectionExecution.completed_at < cutoff]
    if policy.entity_type == "detection_reports": return DetectionReport, [DetectionReport.created_at < cutoff]
    if policy.entity_type == "vm_asset_sync_runs": return AssetSynchronizationRun, [AssetSynchronizationRun.status.in_(["completed", "failed"]), AssetSynchronizationRun.completed_at < cutoff]
    if policy.entity_type == "vm_ingestion_runs": return VulnerabilityIngestionRun, [VulnerabilityIngestionRun.status.in_(["completed", "failed"]), VulnerabilityIngestionRun.completed_at < cutoff]
    terminal = ["completed", "completed_with_warnings", "failed", "cancelled", "rolled_back", "rollback_failed", "expired"]
    if policy.entity_type == "soar_dry_runs": return SoarExecution, [SoarExecution.mode == "dry_run", SoarExecution.status.in_(terminal), SoarExecution.completed_at < cutoff, SoarExecution.trigger_source_type != "incident_case"]
    if policy.entity_type == "soar_simulations": return SoarExecution, [SoarExecution.mode == "simulation", SoarExecution.status.in_(terminal), SoarExecution.completed_at < cutoff, SoarExecution.trigger_source_type != "incident_case"]
    if policy.entity_type == "soar_live_local_executions": return SoarExecution, [SoarExecution.mode == "live_local", SoarExecution.status.in_(terminal), SoarExecution.completed_at < cutoff, SoarExecution.trigger_source_type != "incident_case"]
    if policy.entity_type == "soar_reports": return SoarReport, [SoarReport.created_at < cutoff]
    if policy.entity_type == "integration_delivery_attempts": return ConnectorDeliveryAttempt, [ConnectorDeliveryAttempt.completed_at.is_not(None), ConnectorDeliveryAttempt.completed_at < cutoff]
    if policy.entity_type == "integration_successful_deliveries": return ConnectorDelivery, [ConnectorDelivery.status.in_(["succeeded", "succeeded_with_warnings"]), ConnectorDelivery.completed_at < cutoff]
    if policy.entity_type == "integration_rejected_inbound": return ConnectorInboundEvent, [ConnectorInboundEvent.status == "rejected", ConnectorInboundEvent.updated_at < cutoff]
    if policy.entity_type == "integration_health_checks": return ConnectorHealthCheck, [ConnectorHealthCheck.created_at < cutoff]
    if policy.entity_type == "integration_replay_nonces": return ConnectorReplayNonce, [ConnectorReplayNonce.expires_at < now]
    if policy.entity_type == "integration_inbound_rate_counters": return ConnectorInboundRateCounter, [ConnectorInboundRateCounter.expires_at < now]
    if policy.entity_type == "integration_reports": return ConnectorReport, [ConnectorReport.created_at < cutoff]
    raise ValueError("Unsupported retention entity")


def preview(db: Session, policy: RetentionPolicy, user_id: int) -> RetentionRun:
    if not policy.enabled: raise ValueError("Retention policy is disabled")
    model, filters = _model_and_filters(policy)
    all_ids = [row[0] for row in db.query(model.id).filter(*filters).order_by(model.id).all()]
    candidates = all_ids[:-policy.minimum_keep_count] if len(all_ids) > policy.minimum_keep_count else []
    run = RetentionRun(run_key=new_key("retention"), policy_id=policy.id, mode="preview", candidate_count=len(candidates), deleted_count=0, preserved_count=len(all_ids) - len(candidates), status="preview_ready", summary_json=json.dumps({"candidate_ids": candidates, "expires_at": (utcnow() + timedelta(minutes=15)).isoformat(), "entity_type": policy.entity_type}, sort_keys=True), requested_by_user_id=user_id, completed_at=utcnow())
    policy.last_preview_at = utcnow(); db.add(run); db.flush(); add_activity(db, "retention_previewed", f"Retention preview {run.run_key} identified {len(candidates)} candidates.", "operational_retention", run.id); notify(db,"Retention preview ready",f"Retention preview {run.run_key} is ready for review.","info","operational_retention",run.id); db.commit(); db.refresh(run); return run


def apply_preview(db: Session, preview_run: RetentionRun, user_id: int) -> RetentionRun:
    if preview_run.mode != "preview" or preview_run.status != "preview_ready": raise ValueError("A valid preview is required")
    summary = json.loads(preview_run.summary_json); expires = __import__("datetime").datetime.fromisoformat(summary["expires_at"])
    if expires < utcnow(): raise ValueError("Retention preview has expired")
    policy = db.get(RetentionPolicy, preview_run.policy_id); model, filters = _model_and_filters(policy); expected = summary.get("candidate_ids", [])
    current = [row[0] for row in db.query(model.id).filter(model.id.in_(expected), *filters).order_by(model.id).all()] if expected else []
    if current != expected: raise ValueError("Retention candidates changed; run a new preview")
    run = RetentionRun(run_key=new_key("retention-apply"), policy_id=policy.id, mode="apply", candidate_count=len(expected), status="running", requested_by_user_id=user_id, summary_json=json.dumps({"candidate_ids": expected}, sort_keys=True))
    db.add(run); db.flush()
    try:
        deleted = db.query(model).filter(model.id.in_(expected)).delete(synchronize_session=False) if expected else 0
        run.deleted_count = deleted; run.preserved_count = preview_run.preserved_count; run.status = "succeeded"; run.completed_at = utcnow(); policy.last_applied_at = utcnow(); preview_run.status = "consumed"
        add_activity(db, "retention_applied", f"Retention run {run.run_key} removed {deleted} previewed records.", "operational_retention", run.id); notify(db,"Retention apply succeeded",f"Retention run {run.run_key} applied the exact preview set.","success","operational_retention",run.id); db.commit(); db.refresh(run); return run
    except Exception:
        db.rollback(); raise
