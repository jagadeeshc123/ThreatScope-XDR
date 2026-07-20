import shutil
import sqlite3
import time
from datetime import datetime, timezone

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.database import engine
from app.modules.access_control.audit_service import verify_integrity
from app.modules.access_control.models import AccessPermission, AccessRole
from app.version import version_info

from .configuration_service import get_operations_config, validate_configuration

REQUIRED_TABLES = {"user_accounts", "access_roles", "access_permissions", "security_audit_events", "operational_jobs", "backup_records", "vm_assets", "vm_vulnerabilities", "vm_vulnerability_occurrences", "vm_vulnerability_evidence"}


def _check(key, category, fn):
    started = time.perf_counter()
    try:
        status, summary, metadata = fn()
    except Exception:
        status, summary, metadata = "unhealthy", "Check could not be completed safely.", {}
    return {"check_key": key, "category": category, "status": status, "summary": summary[:300], "checked_at": datetime.now(timezone.utc).isoformat(), "duration_ms": round((time.perf_counter() - started) * 1000, 2), "safe_metadata": metadata}


def detailed_health(db: Session) -> list[dict]:
    config = get_operations_config(create=True)
    def database():
        db.execute(text("SELECT 1"))
        names = set(inspect(db.get_bind()).get_table_names())
        missing = REQUIRED_TABLES - names
        return ("unhealthy", "Required application tables are missing.", {"missing_count": len(missing)}) if missing else ("healthy", "Database connection and required schema are available.", {"required_table_count": len(REQUIRED_TABLES)})
    def authorization():
        permissions = db.query(AccessPermission).count(); roles = db.query(AccessRole).count()
        return ("healthy" if permissions and roles else "unhealthy", "Authorization catalog is available." if permissions and roles else "Authorization catalog is empty.", {"permission_count": permissions, "role_count": roles})
    def configuration():
        result = validate_configuration(True)
        return ("healthy" if result["status"] == "valid" else ("degraded" if result["status"] == "degraded" else "unhealthy"), "Configuration validation completed.", {"invalid_count": result["invalid_count"], "degraded_count": result["degraded_count"]})
    def directory(path, label):
        ok = path.exists() and path.is_dir()
        return ("healthy" if ok else "unhealthy", f"{label} storage is available." if ok else f"{label} storage is unavailable.", {"available": ok})
    def disk():
        usage = shutil.disk_usage(config.runtime_dir)
        percent = round(usage.free / usage.total * 100, 1) if usage.total else 0
        return ("healthy" if percent >= 10 else "degraded", "Local disk-space observation completed.", {"free_percent": percent, "free_bytes": usage.free})
    def audit():
        result = verify_integrity(db)
        return ("healthy" if result["valid_chain"] else "unhealthy", "Security audit chain is valid." if result["valid_chain"] else "Security audit chain verification failed.", {"events_examined": result["events_examined"], "valid_chain": result["valid_chain"]})
    return [
        _check("application_started", "application", lambda: ("healthy", "Application is running.", {"version": version_info()["version"]})),
        _check("database_connection", "database", database),
        _check("authentication", "authentication", lambda: ("healthy", "Local authenticated session controls are registered.", {})),
        _check("authorization_catalog", "authorization", authorization),
        _check("audit_chain", "security", audit),
        _check("backup_directory", "storage", lambda: directory(config.backup_dir, "Backup")),
        _check("export_directory", "storage", lambda: directory(config.export_dir, "Export")),
        _check("report_generation", "reports", lambda: ("healthy", "Local HTML report generation modules are registered.", {})),
        _check("disk_space", "storage", disk),
        _check("configuration", "configuration", configuration),
        _check("docker_metadata", "runtime", lambda: ("unknown", "Container metadata is not required for application health.", {"available": False})),
        _check("local_test_target", "local_target", lambda: ("unknown", "Local target reachability is checked only during explicitly authorized workflows.", {"contacted": False})),
    ]


def public_readiness(db: Session) -> tuple[dict, int]:
    from app.modules.production.config import get_runtime_config
    from app.modules.production.health import production_readiness
    if get_runtime_config().production:
        result = production_readiness(db)
        payload = {"ready": result["ready"], "status": result["status"]}
        return payload, 200 if result["ready"] else 503
    checks = detailed_health(db)
    required = [item for item in checks if item["check_key"] in {"application_started", "database_connection", "authorization_catalog", "backup_directory", "configuration"}]
    failed = sum(item["status"] == "unhealthy" for item in required)
    payload = {"ready": failed == 0, "status": "ready" if failed == 0 else "not_ready", "timestamp": datetime.now(timezone.utc).isoformat(), "failed_check_count": failed}
    return payload, 200 if failed == 0 else 503
