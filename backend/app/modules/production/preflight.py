from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.version import SCHEMA_IDENTIFIER

from .config import ConfigurationError, RuntimeConfig, RuntimeProfile, get_runtime_config


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    state: str
    summary: str
    remediation_code: str


def _result(name: str, state: str, summary: str, remediation: str) -> PreflightCheck:
    return PreflightCheck(name, state, summary, remediation)


def _writable_directory(path: Path, *, create: bool) -> bool:
    try:
        if create:
            path.mkdir(parents=True, exist_ok=True, mode=0o750)
        if not path.is_dir():
            return False
        fd, probe = tempfile.mkstemp(prefix=".threatscope-write-", dir=path)
        os.close(fd)
        Path(probe).unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _sqlite_path(database_url: str) -> Path | None:
    prefix = "sqlite:////"
    if not database_url.startswith(prefix):
        return None
    value = "/" + database_url.removeprefix(prefix)
    if os.name == "nt" and len(value) > 3 and value[0] == "/" and value[2] == ":":
        value = value[1:]
    return Path(value)


def _database_check(config: RuntimeConfig) -> PreflightCheck:
    path = _sqlite_path(config.database_url)
    if path is None:
        return _result("database", "failure", "Production database path is not a persistent absolute SQLite path.", "database_path")
    if not path.exists():
        return _result("database", "pass", "Database will be initialized on persistent storage.", "none")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=rw", uri=True, timeout=5)
        try:
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                return _result("database", "failure", "Database quick-check failed.", "database_integrity")
            table = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='production_runtime_metadata'").fetchone()
            if table:
                row = connection.execute("SELECT value FROM production_runtime_metadata WHERE key='schema_identifier'").fetchone()
                if row and row[0] not in {"threatscope-schema-v18", SCHEMA_IDENTIFIER}:
                    return _result("schema", "failure", "Database schema is newer or unsupported.", "schema_unsupported")
        finally:
            connection.close()
    except sqlite3.Error:
        return _result("database", "failure", "Database could not be opened safely.", "database_unavailable")
    return _result("database", "pass", "Database quick-check succeeded.", "none")


def run_preflight(*, config: RuntimeConfig | None = None, create_directories: bool = False, db: Session | None = None) -> dict:
    checks: list[PreflightCheck] = []
    try:
        config = config or get_runtime_config()
    except ConfigurationError as exc:
        return {"ready": False, "status": "failed", "failure_count": 1, "warning_count": 0, "checks": [asdict(_result("configuration", "failure", str(exc), "configuration_invalid"))]}
    checks.append(_result("profile", "pass" if config.profile is RuntimeProfile.PRODUCTION else "failure", "Runtime profile is production." if config.production else "Runtime profile is not production.", "set_production_profile"))
    checks.append(_result("configuration", "pass", "Strict production configuration validation passed.", "none"))
    for name, path in (("data_storage", config.data_dir), ("backup_storage", config.backup_dir), ("upload_storage", config.upload_dir), ("report_storage", config.report_dir), ("runtime_storage", config.runtime_dir)):
        ok = _writable_directory(path, create=create_directories)
        checks.append(_result(name, "pass" if ok else "failure", f"{name.replace('_', ' ').title()} is writable." if ok else f"{name.replace('_', ' ').title()} is unavailable.", "storage_permissions"))
    checks.append(_database_check(config))
    try:
        free = shutil.disk_usage(config.data_dir if config.data_dir.exists() else config.runtime_dir).free
        state = "pass" if free >= config.minimum_free_bytes else "failure"
        checks.append(_result("disk_space", state, "Free disk space exceeds the configured minimum." if state == "pass" else "Free disk space is critically low.", "disk_space"))
    except OSError:
        checks.append(_result("disk_space", "failure", "Disk space could not be measured.", "disk_space"))
    secret_ok = all(item.configured and item.source == "file" for item in config.secret_statuses if item.name in {"THREATSCOPE_SESSION_SECRET", "THREATSCOPE_MFA_ENCRYPTION_KEY", "THREATSCOPE_CONNECTOR_SECRETS_KEY"})
    checks.append(_result("secret_loader", "pass" if secret_ok else "failure", "Required secrets were loaded from files." if secret_ok else "Required production secrets are not file-loaded.", "secret_files"))
    tls_paths = (Path(config.tls_certificate_file), Path(config.tls_private_key_file)) if config.tls_certificate_file and config.tls_private_key_file else ()
    tls_ok = bool(tls_paths) and all(path.is_absolute() and path.is_file() for path in tls_paths)
    if tls_ok and os.getenv("THREATSCOPE_LOCAL_PRODUCTION_SMOKE", "").strip().casefold() not in {"1", "true", "yes", "on"}:
        repository = Path(__file__).resolve().parents[4]
        tls_ok = all(repository not in path.resolve().parents for path in tls_paths)
    checks.append(_result("tls_material", "pass" if tls_ok else "failure", "TLS certificate and key references are available." if tls_ok else "TLS certificate or key reference is unavailable.", "tls_material"))
    checks.append(_result("worker_count", "pass" if config.worker_count == 1 else "failure", "SQLite worker count is one." if config.worker_count == 1 else "SQLite requires one worker.", "worker_count"))
    checks.append(_result("connector_egress", "pass" if not config.connector_egress_enabled else "warning", "Connector egress is disabled by default." if not config.connector_egress_enabled else "Connector egress is explicitly enabled; review destination policy.", "review_connector_egress"))
    checks.append(_result("public_registration", "pass" if not config.public_registration else "warning", "Public registration is disabled." if not config.public_registration else "Public registration is explicitly enabled and acknowledged.", "review_registration"))
    checks.append(_result("api_documentation", "pass" if not config.api_docs else "failure", "Public API documentation is disabled." if not config.api_docs else "Public API documentation is enabled.", "disable_api_docs"))
    if db is not None:
        try:
            from app.modules.access_control.audit_service import verify_integrity
            integrity = verify_integrity(db)
            valid = bool(integrity["valid_chain"])
            checks.append(_result("audit_integrity", "pass" if valid else "failure", "Audit integrity is valid." if valid else "Audit integrity verification failed.", "audit_integrity"))
        except Exception:
            checks.append(_result("audit_integrity", "failure", "Audit integrity could not be verified.", "audit_integrity"))
    failures = sum(item.state == "failure" for item in checks)
    warnings = sum(item.state == "warning" for item in checks)
    return {"ready": failures == 0, "status": "ready" if failures == 0 else "failed", "failure_count": failures, "warning_count": warnings, "checks": [asdict(item) for item in checks]}


def ensure_schema_metadata(db: Session) -> None:
    from .models import ProductionRuntimeMetadata
    current = db.query(ProductionRuntimeMetadata).filter_by(key="schema_identifier").first()
    if current and current.value not in {"threatscope-schema-v18", SCHEMA_IDENTIFIER}:
        raise RuntimeError("Database schema is newer or unsupported")
    if current:
        current.value = SCHEMA_IDENTIFIER
    else:
        db.add(ProductionRuntimeMetadata(key="schema_identifier", value=SCHEMA_IDENTIFIER))
    db.commit()
