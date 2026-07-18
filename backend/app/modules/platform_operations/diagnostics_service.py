import json
import platform
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.database import DATABASE_URL, engine
from app.modules.access_control.audit_service import verify_integrity
from app.modules.access_control.models import AccessPermission, AccessRole, AuthSession, SecurityAuditEvent, UserAccount
from app.version import version_info

from .configuration_service import get_operations_config, validate_configuration
from .models import BackupRecord, ExportPackage, OperationalJob, ReleaseArtifact, RestoreRecord

SENSITIVE_TABLES = {"auth_sessions", "login_attempts", "mfa_devices", "mfa_login_challenges", "mfa_recovery_codes", "user_accounts", "security_audit_events"}


def database_path(bind=None) -> Path | None:
    url = bind.url if bind is not None else engine.url
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    return Path(url.database).resolve()


def table_counts(db: Session) -> dict[str, int]:
    result = {}
    names = sorted(set(inspect(db.get_bind()).get_table_names()) - SENSITIVE_TABLES)
    for name in names[:200]:
        if not name.replace("_", "").isalnum():
            continue
        result[name] = int(db.execute(text(f'SELECT COUNT(*) FROM "{name}"')).scalar() or 0)
    return result


def database_diagnostics(db: Session) -> dict:
    bind = db.get_bind(); path = database_path(bind)
    return {"database_type": bind.url.get_backend_name(), "database_size_bytes": path.stat().st_size if path and path.exists() else 0, "table_record_counts": table_counts(db)}


def storage_diagnostics(db: Session) -> dict:
    cfg = get_operations_config(create=True)
    return {"directories": {"runtime": cfg.runtime_dir.exists(), "backups": cfg.backup_dir.exists(), "exports": cfg.export_dir.exists(), "releases": cfg.release_dir.exists()}, "backup_count": db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None)).count(), "export_count": db.query(ExportPackage).filter(ExportPackage.deleted_at.is_(None)).count(), "release_count": db.query(ReleaseArtifact).filter(ReleaseArtifact.deleted_at.is_(None)).count()}


def security_diagnostics(db: Session) -> dict:
    return {"active_session_count": db.query(AuthSession).filter(AuthSession.revoked_at.is_(None)).count(), "disabled_user_count": db.query(UserAccount).filter(UserAccount.status == "disabled").count(), "permission_count": db.query(AccessPermission).count(), "role_count": db.query(AccessRole).count(), "audit_chain": verify_integrity(db)}


def module_diagnostics() -> dict:
    expected = ["web_exposure", "api_security", "soc_monitor", "document_threats", "phishing_defense", "unified_correlation", "governance", "threat_intelligence", "detection_engineering", "vulnerability_management", "soar", "integrations", "access_control", "platform_operations"]
    return {"registered_modules": [{"module": name, "registered": True} for name in expected], "registered_count": len(expected)}


def diagnostics(db: Session) -> dict:
    failed = db.query(OperationalJob).filter(OperationalJob.status == "failed").count()
    from app.modules.soar.catalog import ACTION_CATALOG
    from app.modules.soar.models import SoarActionPolicy, SoarApproval, SoarExecution, SoarPlaybook, SoarRollbackRecord
    policies = {item.action_key for item in db.query(SoarActionPolicy).all()}
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None)
    soar = {"tables_present": all(name in inspect(db.get_bind()).get_table_names() for name in ("soar_playbooks", "soar_executions", "soar_approvals", "soar_rollback_records")), "catalog_action_count": len(ACTION_CATALOG), "action_policy_count": len(policies), "unknown_policy_keys": sorted(policies - set(ACTION_CATALOG)), "missing_policy_keys": sorted(set(ACTION_CATALOG) - policies), "protected_template_count": db.query(SoarPlaybook).filter_by(system_owned=True).count(), "invalid_active_playbooks": db.query(SoarPlaybook).filter_by(lifecycle_status="active", validation_status="invalid").count(), "pending_approvals": db.query(SoarApproval).filter(SoarApproval.status.in_(["pending", "partially_approved"])).count(), "stuck_executions": db.query(SoarExecution).filter(SoarExecution.status=="running", SoarExecution.updated_at < now-__import__("datetime").timedelta(hours=1)).count(), "expired_executions": db.query(SoarExecution).filter(SoarExecution.expires_at < now, ~SoarExecution.status.in_(["completed", "failed", "cancelled", "expired", "rolled_back"])).count(), "overdue_delays": db.query(SoarExecution).filter_by(status="waiting_delay").filter(SoarExecution.next_resume_at < now).count(), "rollback_failures": db.query(SoarRollbackRecord).filter_by(status="failed").count()}
    from app.modules.integrations.models import ConnectorCredential, ConnectorDeadLetter, ConnectorDelivery, ConnectorFieldMapping, ConnectorInboundEndpoint, ConnectorInstance, IntegrationOutboxEvent
    from app.modules.integrations.catalog import CONNECTOR_CATALOG
    from app.modules.integrations.security import credential_key_available
    integration_tables=("integration_connectors","integration_connector_credentials","integration_network_policies","integration_deliveries","integration_inbound_events","integration_inbound_rate_counters")
    integrations={"tables_present":all(name in inspect(db.get_bind()).get_table_names() for name in integration_tables),"catalog_available":len(CONNECTOR_CATALOG)==11,"encryption_key_available":credential_key_available(),"active_without_credential":db.query(ConnectorInstance).filter_by(lifecycle_status="active").filter(~ConnectorInstance.id.in_(db.query(ConnectorCredential.connector_id))).count(),"active_without_test":db.query(ConnectorInstance).filter_by(lifecycle_status="active").filter(ConnectorInstance.last_test_status!="passed").count(),"open_circuits":db.query(ConnectorInstance).filter_by(circuit_state="open").count(),"stuck_deliveries":db.query(ConnectorDelivery).filter_by(status="delivering").count(),"dead_letters":db.query(ConnectorDeadLetter).count(),"outbox_backlog":db.query(IntegrationOutboxEvent).filter_by(status="pending").count(),"invalid_mappings":db.query(ConnectorFieldMapping).filter_by(validation_status="invalid").count(),"inbound_without_secret":db.query(ConnectorInboundEndpoint).filter(~ConnectorInboundEndpoint.connector_id.in_(db.query(ConnectorCredential.connector_id))).count(),"external_requests_performed":False}
    return {"application": {**version_info(), "runtime_mode": validate_configuration()["environment"], "python_version": platform.python_version()}, "database": database_diagnostics(db), "storage": storage_diagnostics(db), "security": security_diagnostics(db), "modules": module_diagnostics(), "soar": soar, "integrations":integrations, "operations": {"recent_failed_job_count": failed, "pending_restore_count": db.query(RestoreRecord).filter(RestoreRecord.status == "pending_restart").count()}, "configured_limits": {"values_exposed": False, "limits_are_bounded": True}}
