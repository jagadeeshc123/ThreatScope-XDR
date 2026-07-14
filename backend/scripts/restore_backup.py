"""Controlled offline SQLite restore. Stop the backend before executing replacement."""
import argparse
import os
import sys
from pathlib import Path

from app import models  # noqa: F401
from app.database import SessionLocal, engine
from app.modules.access_control.audit_service import append_event
from app.modules.platform_operations.backup_service import _safe_counts, materialize_plain, safe_path
from app.modules.platform_operations.configuration_service import get_operations_config
from app.modules.platform_operations.diagnostics_service import database_path
from app.modules.platform_operations.models import BackupRecord, RestoreRecord
from app.modules.platform_operations.restore_service import revoke_all_sessions_after_restore
from app.modules.platform_operations.backup_service import create_database_backup
from app.modules.platform_operations.models import utcnow

CONFIRMATION = "RESTORE THREATSCOPE DATA"


def parser():
    result=argparse.ArgumentParser(description="Validate or restore a managed ThreatScope SQLite backup")
    result.add_argument("backup", help="Managed backup ID, key, or generated filename")
    result.add_argument("--validate-only", action="store_true")
    result.add_argument("--non-interactive", action="store_true")
    return result


def find_backup(db, value):
    query=db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None))
    if value.isdigit(): item=query.filter_by(id=int(value)).first()
    else: item=query.filter((BackupRecord.backup_key==value)|(BackupRecord.filename==value)).first()
    if not item: raise ValueError("Managed backup was not found")
    return item


def main(argv=None):
    args=parser().parse_args(argv);cfg=get_operations_config(True);source=database_path()
    if not source: print("SQLite database path is unavailable.",file=sys.stderr);return 2
    with SessionLocal() as db:
        try: backup=find_backup(db,args.backup)
        except ValueError as exc: print(str(exc),file=sys.stderr);return 2
        temp=safe_path(cfg.runtime_dir,"restore-offline-candidate.sqlite")
        if temp.exists(): print("A restore candidate already exists; remove it only after investigation.",file=sys.stderr);return 3
        try: materialize_plain(backup,temp);counts=_safe_counts(temp)
        except Exception: temp.unlink(missing_ok=True);print("Backup validation failed safely.",file=sys.stderr);return 4
        print(f"Validated managed backup {backup.backup_key}; {len(counts)} safe table counts checked.")
        if args.validate_only: temp.unlink(missing_ok=True);return 0
        if args.non_interactive:
            confirmed=os.getenv("THREATSCOPE_RESTORE_CONFIRMATION","")==CONFIRMATION
        else:
            confirmed=input(f"Type {CONFIRMATION} to replace the stopped service database: ").strip()==CONFIRMATION
        if not confirmed: temp.unlink(missing_ok=True);print("Restore confirmation refused.",file=sys.stderr);return 5
        safety,_=create_database_backup(db,None,"database")
    engine.dispose()
    previous=source.with_suffix(source.suffix+".pre-replace")
    if previous.exists(): temp.unlink(missing_ok=True);print("Preserved pre-replace database already exists.",file=sys.stderr);return 6
    try:
        source.replace(previous);temp.replace(source);_safe_counts(source)
    except Exception:
        if source.exists(): source.unlink(missing_ok=True)
        if previous.exists(): previous.replace(source)
        temp.unlink(missing_ok=True);print("Replacement failed; original database was restored.",file=sys.stderr);return 7
    with SessionLocal() as db:
        sessions=revoke_all_sessions_after_restore(db)
        restore=db.query(RestoreRecord).filter_by(backup_id=backup.id).order_by(RestoreRecord.created_at.desc()).first()
        if restore: restore.status="succeeded";restore.pre_restore_backup_id=safety.id;restore.completed_at=utcnow();db.commit()
        append_event(db,event_type="database_restored",action="offline_restore",request_id="local-restore-script",outcome="success",resource_type="backup",resource_id=backup.backup_key,status_code=200,metadata={"sessions_revoked":sessions,"pre_restore_backup_id":safety.id})
    print(f"Restore completed. {sessions} sessions revoked; restart and authenticate again. Previous database retained as {previous.name}.")
    return 0


if __name__=="__main__": raise SystemExit(main())
