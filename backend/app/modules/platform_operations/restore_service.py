import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.modules.access_control.models import AuthSession
from app.version import SCHEMA_IDENTIFIER

from .backup_service import EXPECTED_TABLES, _safe_counts, manifest_path, materialize_plain, safe_path, sha256_file
from .configuration_service import get_operations_config
from .maintenance_service import add_activity, new_key, notify
from .models import BackupRecord, RestoreRecord, utcnow


def validate_managed_backup(db: Session, backup: BackupRecord, user_id: int) -> RestoreRecord:
    cfg = get_operations_config(True)
    record = RestoreRecord(restore_key=new_key("restore"), backup_id=backup.id, source_filename=backup.filename, mode="validate_only", status="validating", requested_by_user_id=user_id, started_at=utcnow())
    db.add(record); db.commit(); db.refresh(record)
    temp = safe_path(cfg.backup_dir, f".{record.restore_key}.validate.sqlite")
    try:
        source = safe_path(cfg.backup_dir, backup.relative_path)
        manifest = manifest_path(backup)
        if source.stat().st_size > cfg.max_import_bytes: raise ValueError("Restore package exceeds configured maximum size")
        if not (backup.filename.endswith(".sqlite") or backup.filename.endswith(".sqlite.fernet")): raise ValueError("Unsupported restore extension")
        if sha256_file(source) != backup.sha256 or sha256_file(manifest) != backup.manifest_sha256: raise ValueError("Restore checksum mismatch")
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        if manifest_data.get("database_schema_identifier") != SCHEMA_IDENTIFIER: raise ValueError("Restore schema is incompatible")
        materialize_plain(backup, temp); counts = _safe_counts(temp)
        summary = {"valid": True, "compatible": True, "schema_identifier": SCHEMA_IDENTIFIER, "record_counts": counts, "warnings": ["Execution creates a pre-restore backup and stages replacement for a controlled service restart."], "limitations": ["Validation never modifies the live database."]}
        record.status = "validated"; record.validation_summary = json.dumps(summary, sort_keys=True); record.completed_at = utcnow()
        add_activity(db, "restore_validated", f"Restore request {record.restore_key} validated without live mutation.", "operational_restore", record.id)
        notify(db, "Restore validation succeeded", f"Restore request {record.restore_key} is compatible.", "success", "operational_restore", record.id)
        db.commit(); db.refresh(record); return record
    except Exception as exc:
        record.status = "validation_failed"; record.validation_summary = json.dumps({"valid": False, "compatible": False, "error": "Restore package validation failed safely."}); record.completed_at = utcnow()
        notify(db, "Restore validation failed", f"Restore request {record.restore_key} could not be validated.", "danger", "operational_restore", record.id); db.commit()
        raise ValueError("Restore package validation failed safely") from exc
    finally: temp.unlink(missing_ok=True)


def stage_restore(db: Session, restore: RestoreRecord, user_id: int) -> tuple[RestoreRecord, BackupRecord]:
    from .backup_service import create_database_backup
    if restore.status != "validated": raise ValueError("Restore validation must succeed before execution")
    backup = db.get(BackupRecord, restore.backup_id)
    if not backup: raise ValueError("Managed backup is unavailable")
    safety, _ = create_database_backup(db, user_id, "database")
    safety.protected = True; db.commit()
    cfg = get_operations_config(True)
    staged = safe_path(cfg.runtime_dir, "restore-staged.sqlite")
    staged_manifest = safe_path(cfg.runtime_dir, "restore-staged.json")
    if staged.exists() or staged_manifest.exists(): raise ValueError("A staged restore is already pending")
    try:
        materialize_plain(backup, staged); counts = _safe_counts(staged)
        staged_manifest.write_text(json.dumps({"restore_key": restore.restore_key, "source_backup_key": backup.backup_key, "source_sha256": backup.sha256, "staged_sha256": sha256_file(staged), "pre_restore_backup_key": safety.backup_key, "schema_identifier": SCHEMA_IDENTIFIER}, indent=2, sort_keys=True), encoding="utf-8")
        restore.mode = "replace_database"; restore.status = "pending_restart"; restore.confirmed_by_user_id = user_id; restore.pre_restore_backup_id = safety.id; restore.restored_record_counts_json = json.dumps(counts, sort_keys=True); restore.completed_at = utcnow()
        add_activity(db, "restore_staged", f"Restore {restore.restore_key} staged for controlled service-stop replacement.", "operational_restore", restore.id)
        notify(db, "Restore staged", f"Restore {restore.restore_key} requires controlled service restart.", "warning", "operational_restore", restore.id)
        db.commit(); db.refresh(restore); return restore, safety
    except Exception:
        staged.unlink(missing_ok=True); staged_manifest.unlink(missing_ok=True)
        restore.status = "stage_failed"; db.commit(); raise


def revoke_all_sessions_after_restore(db: Session) -> int:
    now = utcnow()
    count = db.query(AuthSession).filter(AuthSession.revoked_at.is_(None)).update({AuthSession.revoked_at: now, AuthSession.revoke_reason: "database_restored"}, synchronize_session=False)
    db.commit(); return count
