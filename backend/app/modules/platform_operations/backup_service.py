import hashlib
import json
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.database import engine
from app.version import BACKUP_MANIFEST_VERSION, APPLICATION_NAME, SCHEMA_IDENTIFIER, utc_iso, version_info

from .configuration_service import get_operations_config
from .diagnostics_service import SENSITIVE_TABLES, database_path
from .maintenance_service import add_activity, fail_job, finish_job, new_key, notify, start_job
from .models import BackupRecord, OperationalJob, utcnow

_LOCK = threading.Lock()
EXPECTED_TABLES = {"user_accounts", "access_roles", "access_permissions", "security_audit_events", "threat_indicators", "threat_intel_imports", "indicator_matches", "detection_rules", "detection_rule_versions", "detection_matches", "vm_assets", "vm_vulnerabilities", "vm_vulnerability_occurrences", "vm_vulnerability_evidence", "vm_remediation_plans", "vm_risk_acceptances", "vm_verification_requests", "soar_action_policies", "soar_playbooks", "soar_playbook_versions", "soar_executions", "soar_step_executions", "soar_execution_events", "soar_approvals", "soar_approval_decisions", "soar_analyst_inputs", "soar_rollback_records"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(base: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("Invalid managed artifact path")
    candidate = (base / relative).resolve()
    if candidate.parent != base.resolve() or (candidate.exists() and candidate.is_symlink()):
        raise ValueError("Managed artifact path escapes configured storage")
    return candidate


def _fernet(key: str) -> Fernet:
    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise ValueError("Backup encryption key must be a valid Fernet key") from exc


def _safe_counts(path: Path) -> dict[str, int]:
    result = {}
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = EXPECTED_TABLES - names
        if missing:
            raise ValueError("Backup is missing required core tables")
        for name in sorted(names - SENSITIVE_TABLES)[:200]:
            if name.replace("_", "").isalnum():
                result[name] = int(conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
    finally:
        conn.close()
    return result


def _manifest(record: BackupRecord) -> dict:
    info = version_info()
    return {"manifest_version": BACKUP_MANIFEST_VERSION, "application_name": APPLICATION_NAME, "application_version": info["version"], "commit_hash": info["commit_hash"], "created_timestamp": record.created_at.isoformat(), "backup_type": record.backup_type, "backup_filename": record.filename, "backup_sha256": record.sha256, "backup_size": record.size_bytes, "database_schema_identifier": SCHEMA_IDENTIFIER, "safe_table_count_summary": json.loads(record.record_counts_json), "included_artifacts": ["sqlite_database"], "excluded_artifact_categories": ["environment", "runtime_sessions_outside_database", "uploads", "reports", "exports", "release_artifacts"], "encrypted": record.encrypted, "classification": "sensitive_administrative_recovery_artifact", "limitations": ["A full database backup contains protected authentication tables for recovery.", "Store and transfer only through authorized local administrative controls."]}


def manifest_path(record: BackupRecord) -> Path:
    cfg = get_operations_config(True)
    return safe_path(cfg.backup_dir, record.relative_path + ".manifest.json")


def create_database_backup(db: Session, user_id: int | None, backup_type: str = "database") -> tuple[BackupRecord, OperationalJob]:
    cfg = get_operations_config(True)
    if cfg.require_backup_encryption and not cfg.backup_encryption_key:
        raise ValueError("Backup encryption is required but no key is configured")
    if not _LOCK.acquire(blocking=False):
        raise RuntimeError("A database backup is already running")
    job = start_job(db, "database_backup", user_id)
    plain = None; output = None; manifest = None
    try:
        if db.get_bind().url.get_backend_name() != "sqlite":
            raise ValueError("Only SQLite backups are supported")
        key = new_key("backup")
        encrypted = bool(cfg.backup_encryption_key)
        filename = f"{key}.sqlite.fernet" if encrypted else f"{key}.sqlite"
        output = safe_path(cfg.backup_dir, filename)
        if output.exists(): raise FileExistsError("Generated backup already exists")
        plain = safe_path(cfg.backup_dir, f".{key}.incomplete.sqlite")
        src = db.connection().connection.driver_connection; dst = sqlite3.connect(str(plain))
        try: src.backup(dst)
        finally: dst.close()
        counts = _safe_counts(plain)
        if encrypted:
            output.write_bytes(_fernet(cfg.backup_encryption_key).encrypt(plain.read_bytes()))
            plain.unlink(missing_ok=True)
        else:
            plain.replace(output)
        if output.stat().st_size > cfg.max_backup_bytes:
            raise ValueError("Backup exceeds configured maximum size")
        record = BackupRecord(backup_key=key, filename=filename, relative_path=filename, backup_type=backup_type, status="verified", size_bytes=output.stat().st_size, sha256=sha256_file(output), schema_version=SCHEMA_IDENTIFIER, application_version=version_info()["version"], record_counts_json=json.dumps(counts, sort_keys=True), encrypted=encrypted, created_by_user_id=user_id, verified_at=utcnow(), verification_status="valid")
        db.add(record); db.flush()
        payload = _manifest(record)
        manifest = manifest_path(record)
        manifest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        record.manifest_sha256 = sha256_file(manifest)
        add_activity(db, "backup_created", f"Database backup {record.backup_key} created and verified.", "operational_backup", record.id)
        notify(db, "Backup succeeded", f"Database backup {record.backup_key} completed.", "success", "operational_backup", record.id)
        db.commit(); db.refresh(record); finish_job(db, job, "Database backup created and verified.", {"backup_id": record.id})
        return record, job
    except Exception as exc:
        db.rollback()
        for path in (plain, output, manifest):
            if path: path.unlink(missing_ok=True)
        fail_job(db, job, "backup_failed", "Database backup failed safely.")
        notify(db, "Backup failed", "Database backup could not be completed safely.", "danger", "operational_job", job.id); db.commit()
        raise ValueError("Database backup failed safely") from exc
    finally:
        _LOCK.release()


def materialize_plain(record: BackupRecord, destination: Path) -> Path:
    cfg = get_operations_config(True); source = safe_path(cfg.backup_dir, record.relative_path)
    if record.encrypted:
        if not cfg.backup_encryption_key: raise ValueError("Backup encryption key is unavailable")
        try: destination.write_bytes(_fernet(cfg.backup_encryption_key).decrypt(source.read_bytes()))
        except InvalidToken as exc: raise ValueError("Backup decryption failed") from exc
    else:
        destination.write_bytes(source.read_bytes())
    return destination


def verify_backup(db: Session, record: BackupRecord) -> dict:
    cfg = get_operations_config(True); source = safe_path(cfg.backup_dir, record.relative_path); manifest = manifest_path(record)
    valid = source.exists() and manifest.exists() and sha256_file(source) == record.sha256 and sha256_file(manifest) == record.manifest_sha256
    temp = safe_path(cfg.backup_dir, f".{record.backup_key}.verify.sqlite")
    try:
        if valid:
            materialize_plain(record, temp); counts = _safe_counts(temp)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            valid = payload.get("backup_sha256") == record.sha256 and payload.get("database_schema_identifier") == SCHEMA_IDENTIFIER
        else: counts = {}
    except Exception:
        valid = False; counts = {}
    finally: temp.unlink(missing_ok=True)
    record.verification_status = "valid" if valid else "invalid"; record.verified_at = utcnow(); record.status = "verified" if valid else "invalid"
    if valid: add_activity(db, "backup_verified", f"Backup {record.backup_key} passed integrity verification.", "operational_backup", record.id)
    else: notify(db, "Backup verification failed", f"Backup {record.backup_key} failed integrity verification.", "danger", "operational_backup", record.id)
    db.commit()
    return {"valid": valid, "verification_status": record.verification_status, "record_counts": counts}


def delete_backup(db: Session, record: BackupRecord):
    if record.protected: raise ValueError("Protected backups cannot be deleted")
    cfg = get_operations_config(True); source = safe_path(cfg.backup_dir, record.relative_path); manifest = manifest_path(record)
    source.unlink(missing_ok=True); manifest.unlink(missing_ok=True)
    record.deleted_at = utcnow(); record.status = "deleted"
    add_activity(db, "backup_deleted", f"Backup metadata {record.backup_key} marked deleted.", "operational_backup", record.id); db.commit()


def retention_preview(db: Session) -> dict:
    cfg = get_operations_config(True); active = db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None)).order_by(BackupRecord.created_at.desc()).all()
    cutoff = utcnow() - timedelta(days=cfg.backup_max_age_days)
    newest_valid_id = next((item.id for item in active if item.verification_status == "valid"), None)
    candidates = []
    for index, item in enumerate(active):
        if index < cfg.backup_min_keep or item.protected or item.id == newest_valid_id: continue
        if len(active) - len(candidates) > cfg.backup_max_count or item.created_at < cutoff: candidates.append(item.id)
    return {"preview_token": new_key("backup-retention"), "candidate_ids": candidates, "candidate_count": len(candidates), "minimum_keep": cfg.backup_min_keep, "expires_at": (utcnow() + timedelta(minutes=15)).isoformat()}
