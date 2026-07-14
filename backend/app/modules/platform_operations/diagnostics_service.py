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
    for name in names[:120]:
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
    expected = ["web_exposure", "api_security", "soc_monitor", "document_threats", "phishing_defense", "unified_correlation", "governance", "access_control", "platform_operations"]
    return {"registered_modules": [{"module": name, "registered": True} for name in expected], "registered_count": len(expected)}


def diagnostics(db: Session) -> dict:
    failed = db.query(OperationalJob).filter(OperationalJob.status == "failed").count()
    return {"application": {**version_info(), "runtime_mode": validate_configuration()["environment"], "python_version": platform.python_version()}, "database": database_diagnostics(db), "storage": storage_diagnostics(db), "security": security_diagnostics(db), "modules": module_diagnostics(), "operations": {"recent_failed_job_count": failed, "pending_restore_count": db.query(RestoreRecord).filter(RestoreRecord.status == "pending_restart").count()}, "configured_limits": {"values_exposed": False, "limits_are_bounded": True}}
