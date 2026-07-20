import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.access_control import mfa_service
from app.modules.access_control.audit_service import append_event
from app.modules.access_control.dependencies import get_current_user, require_any_permission, require_authenticated_csrf, require_permission, require_system_admin
from app.modules.access_control.models import UserAccount
from app.modules.access_control.password_service import verify_password
from app.modules.access_control.role_service import effective_permissions
from app.version import utc_iso, version_info

from . import backup_service, demo_service, diagnostics_service, export_service, inventory_service, release_service, restore_service, retention_service
from .configuration_service import get_operations_config, validate_configuration
from .health_service import detailed_health, public_readiness
from .maintenance_service import add_activity, finish_job, new_key, notify, start_job
from .models import BackupRecord, ExportPackage, OperationalJob, ReleaseArtifact, RestoreRecord, RetentionPolicy, RetentionRun, utcnow
from .schemas import BackupCreate, BackupRetentionApply, BackupRetentionUpdate, ConfirmationRequest, ExportCreate, ImportValidate, ReleaseBuildRequest, RestoreExecute, RestoreValidate, RetentionApplyRequest, RetentionPolicyUpdate, RetentionPreviewRequest

health_router = APIRouter()
router = APIRouter()


def _audit(db, request, actor, action, resource_type, resource_id=None, metadata=None):
    append_event(db, event_type="operational_action", action=action, request_id=getattr(request.state,"request_id","unknown"), outcome="success", actor=actor, resource_type=resource_type, resource_id=resource_id, route_template=request.url.path, request_method=request.method, status_code=200, metadata=metadata or {})


def _json(value):
    if not value: return {} if value != "[]" else []
    try: return json.loads(value)
    except (TypeError, json.JSONDecodeError): return {}


def _job(item):
    return {"id":item.id,"job_key":item.job_key,"job_type":item.job_type,"status":item.status,"requested_by_user_id":item.requested_by_user_id,"started_at":item.started_at,"completed_at":item.completed_at,"progress_percent":item.progress_percent,"result_summary":item.result_summary,"error_code":item.error_code,"error_summary":item.error_summary,"metadata":_json(item.metadata_json),"created_at":item.created_at,"updated_at":item.updated_at}


def _backup(item):
    return {"id":item.id,"backup_key":item.backup_key,"filename":item.filename,"backup_type":item.backup_type,"status":item.status,"size_bytes":item.size_bytes,"sha256":item.sha256,"manifest_sha256":item.manifest_sha256,"schema_version":item.schema_version,"application_version":item.application_version,"record_counts":_json(item.record_counts_json),"encrypted":item.encrypted,"protected":item.protected,"created_at":item.created_at,"verified_at":item.verified_at,"verification_status":item.verification_status,"deleted_at":item.deleted_at}


def _restore(item):
    return {"id":item.id,"restore_key":item.restore_key,"backup_id":item.backup_id,"source_filename":item.source_filename,"mode":item.mode,"status":item.status,"pre_restore_backup_id":item.pre_restore_backup_id,"validation_summary":_json(item.validation_summary),"restored_record_counts":_json(item.restored_record_counts_json),"started_at":item.started_at,"completed_at":item.completed_at,"created_at":item.created_at}


def _export(item):
    return {"id":item.id,"package_key":item.package_key,"filename":item.filename,"package_type":item.package_type,"status":item.status,"size_bytes":item.size_bytes,"sha256":item.sha256,"manifest_sha256":item.manifest_sha256,"included_modules":_json(item.included_modules_json),"record_counts":_json(item.record_counts_json),"created_at":item.created_at,"verified_at":item.verified_at,"verification_status":item.verification_status,"deleted_at":item.deleted_at}


def _release(item):
    return {"id":item.id,"release_key":item.release_key,"version":item.version,"commit_hash":item.commit_hash,"filename":item.filename,"size_bytes":item.size_bytes,"sha256":item.sha256,"manifest_sha256":item.manifest_sha256,"status":item.status,"created_at":item.created_at,"deleted_at":item.deleted_at}


@health_router.get("/live")
def live():
    from app.modules.production.config import get_runtime_config
    if get_runtime_config().production:
        return {"status": "alive"}
    return {"status":"alive","service":"threatscope-xdr","timestamp":utc_iso(),"version":version_info()["version"]}


@health_router.get("/ready")
def ready(db: Session=Depends(get_db)):
    payload, code = public_readiness(db); return JSONResponse(status_code=code, content=payload)


@router.get("", dependencies=[Depends(require_permission("operations:view"))])
def overview(db: Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    permissions=effective_permissions(db,actor);readiness, _ = public_readiness(db); latest_backup=db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None),BackupRecord.verification_status=="valid").order_by(BackupRecord.created_at.desc()).first(); latest_release=db.query(ReleaseArtifact).filter(ReleaseArtifact.deleted_at.is_(None)).order_by(ReleaseArtifact.created_at.desc()).first()
    return {"readiness":readiness,"version":version_info(),"database":diagnostics_service.database_diagnostics(db),"latest_backup":_backup(latest_backup) if latest_backup and "operations:backup" in permissions else None,"recent_failed_jobs":db.query(OperationalJob).filter(OperationalJob.status=="failed").count() if "operations:maintenance" in permissions else None,"pending_restore_count":db.query(RestoreRecord).filter(RestoreRecord.status=="pending_restart").count() if "operations:restore" in permissions else None,"retention_policy_count":db.query(RetentionPolicy).filter(RetentionPolicy.enabled.is_(True)).count() if "operations:retention" in permissions else None,"demo":demo_service.status(db),"latest_release":_release(latest_release) if latest_release and "operations:release" in permissions else None}


@router.get("/health/details", dependencies=[Depends(require_permission("operations:diagnostics"))])
def health_details(db: Session=Depends(get_db)):
    checks=detailed_health(db); return {"status":"unhealthy" if any(c["status"]=="unhealthy" for c in checks) else ("degraded" if any(c["status"] in {"degraded","unknown"} for c in checks) else "healthy"),"checks":checks,"checked_at":utc_iso()}


@router.get("/diagnostics", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics(db: Session=Depends(get_db)): return diagnostics_service.diagnostics(db)
@router.get("/diagnostics/database", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics_database(db: Session=Depends(get_db)): return diagnostics_service.database_diagnostics(db)
@router.get("/diagnostics/storage", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics_storage(db: Session=Depends(get_db)): return diagnostics_service.storage_diagnostics(db)
@router.get("/diagnostics/configuration", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics_configuration(): return validate_configuration()
@router.get("/diagnostics/security", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics_security(db: Session=Depends(get_db)): return diagnostics_service.security_diagnostics(db)
@router.get("/diagnostics/modules", dependencies=[Depends(require_permission("operations:diagnostics"))])
def diagnostics_modules(): return diagnostics_service.module_diagnostics()


@router.get("/configuration/status", dependencies=[Depends(require_permission("operations:diagnostics"))])
def configuration_status(): return validate_configuration()
@router.post("/configuration/validate", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:diagnostics"))])
def configuration_validate(request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=validate_configuration();add_activity(db,"configuration_validated",f"Configuration validation completed with status {result['status']}.","operational_configuration",None)
    if not result["valid"]:notify(db,"Configuration is invalid","Operational configuration validation found critical issues.","danger","operational_configuration",None)
    db.commit();_audit(db,request,actor,"validate_configuration","configuration",metadata={"status":result["status"]});return result


@router.get("/jobs", dependencies=[Depends(require_permission("operations:maintenance"))])
def jobs(db:Session=Depends(get_db)): return [_job(x) for x in db.query(OperationalJob).order_by(OperationalJob.created_at.desc()).limit(200)]
@router.get("/jobs/{job_id}", dependencies=[Depends(require_permission("operations:maintenance"))])
def job_details(job_id:int,db:Session=Depends(get_db)):
    item=db.get(OperationalJob,job_id)
    if not item: raise HTTPException(404,"Operational job not found")
    return _job(item)
@router.post("/jobs/{job_id}/cancel", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:maintenance"))])
def cancel_job(job_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=db.get(OperationalJob,job_id)
    if not item: raise HTTPException(404,"Operational job not found")
    if item.status not in {"queued"}: raise HTTPException(422,"Only queued reversible jobs can be cancelled")
    item.status="cancelled";item.completed_at=utcnow();db.commit();_audit(db,request,actor,"cancel_job","operational_job",item.id);return _job(item)


@router.post("/backups/database", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_create(payload:BackupCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    try:item,job=backup_service.create_database_backup(db,actor.id,payload.backup_type)
    except (ValueError,RuntimeError) as exc:raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"create_backup","backup",item.id,{"backup_key":item.backup_key,"encrypted":item.encrypted});return {"backup":_backup(item),"job":_job(job)}
@router.get("/backups", dependencies=[Depends(require_any_permission("operations:backup","operations:restore"))])
def backups(db:Session=Depends(get_db)):return [_backup(x) for x in db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None)).order_by(BackupRecord.created_at.desc()).limit(200)]
@router.get("/backups/retention", dependencies=[Depends(require_permission("operations:backup"))])
def backup_retention():
    c=get_operations_config();return {"maximum_count":c.backup_max_count,"maximum_age_days":c.backup_max_age_days,"minimum_keep_count":c.backup_min_keep,"protected_backups_supported":True,"automatic_deletion":False}
@router.put("/backups/retention", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_retention_update(payload:BackupRetentionUpdate):return {**payload.model_dump(),"status":"validated","note":"Environment-backed settings require a controlled service restart; no environment was modified."}
@router.post("/backups/retention/preview", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_retention_preview(db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=backup_service.retention_preview(db);job=start_job(db,"backup_retention_preview",actor.id,result);finish_job(db,job,"Backup retention preview completed.",result);return result
@router.post("/backups/retention/apply", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_retention_apply(payload:BackupRetentionApply,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if payload.confirmation_phrase != "DELETE PREVIEWED BACKUPS":raise HTTPException(422,"Explicit confirmation phrase is required")
    job=db.query(OperationalJob).filter_by(job_type="backup_retention_preview",status="succeeded").order_by(OperationalJob.created_at.desc()).first();meta=_json(job.metadata_json) if job else {}
    if not job or meta.get("preview_token")!=payload.preview_token or meta.get("candidate_ids")!=payload.candidate_ids:raise HTTPException(422,"Retention apply must match the latest preview")
    deleted=[]
    newest_valid=db.query(BackupRecord).filter(BackupRecord.deleted_at.is_(None),BackupRecord.verification_status=="valid").order_by(BackupRecord.created_at.desc()).first()
    for item_id in payload.candidate_ids:
        item=db.get(BackupRecord,item_id)
        if not item or item.protected or item.deleted_at is not None or newest_valid and item.id==newest_valid.id:raise HTTPException(422,"Backup retention candidates changed")
        backup_service.delete_backup(db,item);deleted.append(item_id)
    job.status="consumed";db.commit();_audit(db,request,actor,"apply_backup_retention","backup_retention",metadata={"deleted_count":len(deleted)});return {"deleted_ids":deleted,"deleted_count":len(deleted)}


def _backup_or_404(db,id):
    item=db.get(BackupRecord,id)
    if not item or item.deleted_at is not None:raise HTTPException(404,"Backup not found")
    return item
@router.get("/backups/{backup_id}", dependencies=[Depends(require_any_permission("operations:backup","operations:restore"))])
def backup_details(backup_id:int,db:Session=Depends(get_db)):return _backup(_backup_or_404(db,backup_id))
@router.post("/backups/{backup_id}/verify", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_verify(backup_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_backup_or_404(db,backup_id);result=backup_service.verify_backup(db,item);_audit(db,request,actor,"verify_backup","backup",item.id,{"valid":result["valid"]});return result
@router.get("/backups/{backup_id}/download", dependencies=[Depends(require_any_permission("operations:backup","operations:restore"))])
def backup_download(backup_id:int,db:Session=Depends(get_db)):
    item=_backup_or_404(db,backup_id);path=backup_service.safe_path(get_operations_config(True).backup_dir,item.relative_path);return FileResponse(path,filename=item.filename,media_type="application/octet-stream")
@router.delete("/backups/{backup_id}", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:backup"))])
def backup_delete(backup_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_backup_or_404(db,backup_id)
    try:backup_service.delete_backup(db,item)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"delete_backup","backup",item.id);return {"ok":True}


@router.post("/restores/validate", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:restore"))])
def restore_validate(payload:RestoreValidate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    backup=_backup_or_404(db,payload.backup_id)
    try:item=restore_service.validate_managed_backup(db,backup,actor.id)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"validate_restore","restore",item.id);return _restore(item)
@router.get("/restores", dependencies=[Depends(require_permission("operations:restore"))])
def restores(db:Session=Depends(get_db)):return [_restore(x) for x in db.query(RestoreRecord).order_by(RestoreRecord.created_at.desc()).limit(200)]
@router.get("/restores/{restore_id}", dependencies=[Depends(require_permission("operations:restore"))])
def restore_details(restore_id:int,db:Session=Depends(get_db)):
    item=db.get(RestoreRecord,restore_id)
    if not item:raise HTTPException(404,"Restore request not found")
    return _restore(item)
@router.post("/restores/{restore_id}/execute", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:restore")),Depends(require_system_admin)])
def restore_execute(restore_id:int,payload:RestoreExecute,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if payload.confirmation_phrase!="RESTORE THREATSCOPE DATA":raise HTTPException(422,"Explicit restore confirmation phrase is required")
    if not verify_password(actor.password_hash,payload.current_password):raise HTTPException(403,"Recent password confirmation failed")
    if actor.mfa_enabled and not mfa_service.verify_user_factor(db,actor,payload.mfa_code,payload.recovery_code):raise HTTPException(403,"MFA confirmation failed")
    item=db.get(RestoreRecord,restore_id)
    if not item:raise HTTPException(404,"Restore request not found")
    try:item,safety=restore_service.stage_restore(db,item,actor.id)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"stage_restore","restore",item.id,{"pre_restore_backup_id":safety.id,"restart_required":True});return {**_restore(item),"restart_required":True,"live_database_replaced":False,"next_action":"Stop the backend and run scripts/restore_backup.py for deterministic final replacement."}


@router.get("/exports", dependencies=[Depends(require_permission("operations:export"))])
def exports(db:Session=Depends(get_db)):return [_export(x) for x in db.query(ExportPackage).filter(ExportPackage.deleted_at.is_(None)).order_by(ExportPackage.created_at.desc()).limit(200)]
@router.post("/exports", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:export"))])
def export_create(payload:ExportCreate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    try:item=export_service.create_export(db,actor.id,payload.modules,effective_permissions(db,actor))
    except PermissionError as exc:raise HTTPException(403,str(exc)) from exc
    _audit(db,request,actor,"create_export","export",item.id,{"module_count":len(payload.modules)});return _export(item)
def _export_or_404(db,id):
    item=db.get(ExportPackage,id)
    if not item or item.deleted_at is not None:raise HTTPException(404,"Export package not found")
    return item
@router.get("/exports/{export_id}", dependencies=[Depends(require_permission("operations:export"))])
def export_details(export_id:int,db:Session=Depends(get_db)):return _export(_export_or_404(db,export_id))
@router.post("/exports/{export_id}/verify", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:export"))])
def export_verify(export_id:int,db:Session=Depends(get_db)):return export_service.verify_export(db,_export_or_404(db,export_id))
@router.get("/exports/{export_id}/download", dependencies=[Depends(require_permission("operations:export"))])
def export_download(export_id:int,db:Session=Depends(get_db)):
    item=_export_or_404(db,export_id);path=backup_service.safe_path(get_operations_config(True).export_dir,item.relative_path);return FileResponse(path,filename=item.filename,media_type="application/zip")
@router.delete("/exports/{export_id}", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:export"))])
def export_delete(export_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_export_or_404(db,export_id);export_service.delete_export(db,item);_audit(db,request,actor,"delete_export","export",item.id);return {"ok":True}
@router.post("/imports/validate", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:import"))])
def import_validate(payload:ImportValidate,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_export_or_404(db,payload.export_id);before={name:count for name,count in diagnostics_service.table_counts(db).items()};result=export_service.validate_archive(backup_service.safe_path(get_operations_config(True).export_dir,item.relative_path),item.sha256);after=diagnostics_service.table_counts(db);result["source_mutation_count"]=sum(abs(after.get(k,0)-v) for k,v in before.items());_audit(db,request,actor,"validate_import","import_validation",item.id,{"valid":True,"source_mutation_count":result["source_mutation_count"]});return result


@router.get("/retention/policies", dependencies=[Depends(require_permission("operations:retention"))])
def policies(db:Session=Depends(get_db)):
    retention_service.seed_policies(db);return [{c.name:getattr(x,c.name) for c in x.__table__.columns} for x in db.query(RetentionPolicy).order_by(RetentionPolicy.policy_key)]
@router.put("/retention/policies/{policy_id}", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:retention"))])
def policy_update(policy_id:int,payload:RetentionPolicyUpdate,db:Session=Depends(get_db)):
    item=db.get(RetentionPolicy,policy_id)
    if not item:raise HTTPException(404,"Retention policy not found")
    for key,value in payload.model_dump(exclude_none=True).items():setattr(item,key,value)
    db.commit();db.refresh(item);return {c.name:getattr(item,c.name) for c in item.__table__.columns}
@router.post("/retention/preview", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:retention"))])
def retention_preview(payload:RetentionPreviewRequest,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=db.get(RetentionPolicy,payload.policy_id)
    if not item:raise HTTPException(404,"Retention policy not found")
    run=retention_service.preview(db,item,actor.id)
    return {c.name:getattr(run,c.name) for c in run.__table__.columns}
@router.post("/retention/apply", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:retention"))])
def retention_apply(payload:RetentionApplyRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if payload.confirmation_phrase!="APPLY RETENTION PREVIEW":raise HTTPException(422,"Explicit retention confirmation phrase is required")
    run=db.get(RetentionRun,payload.run_id)
    if not run:raise HTTPException(404,"Retention preview not found")
    try:result=retention_service.apply_preview(db,run,actor.id)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"apply_retention","retention_run",result.id,{"deleted_count":result.deleted_count});return {c.name:getattr(result,c.name) for c in result.__table__.columns}
@router.get("/retention/runs", dependencies=[Depends(require_permission("operations:retention"))])
def retention_runs(db:Session=Depends(get_db)):return [{c.name:getattr(x,c.name) for c in x.__table__.columns} for x in db.query(RetentionRun).order_by(RetentionRun.created_at.desc()).limit(200)]
@router.get("/retention/runs/{run_id}", dependencies=[Depends(require_permission("operations:retention"))])
def retention_run(run_id:int,db:Session=Depends(get_db)):
    item=db.get(RetentionRun,run_id)
    if not item:raise HTTPException(404,"Retention run not found")
    return {c.name:getattr(item,c.name) for c in item.__table__.columns}


@router.get("/demo/status", dependencies=[Depends(require_permission("operations:view"))])
def demo_status(db:Session=Depends(get_db)):return demo_service.status(db)
@router.post("/demo/seed", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:demo_manage"))])
def demo_seed(request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    try:result=demo_service.seed(db)
    except ValueError as exc:raise HTTPException(404,str(exc)) from exc
    _audit(db,request,actor,"seed_demo","demo_environment",metadata={"created":result["created"]});return result
@router.post("/demo/reset", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:demo_manage"))])
def demo_reset(payload:ConfirmationRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if payload.confirmation_phrase!="RESET DEMO DATA":raise HTTPException(422,"Explicit demo reset confirmation is required")
    try:result=demo_service.reset(db)
    except ValueError as exc:raise HTTPException(404,str(exc)) from exc
    _audit(db,request,actor,"reset_demo","demo_environment",metadata={"deleted_demo_records":result["deleted_demo_records"]});return result
@router.post("/demo/reseed", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:demo_manage"))])
def demo_reseed(payload:ConfirmationRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if payload.confirmation_phrase!="RESEED DEMO DATA":raise HTTPException(422,"Explicit demo reseed confirmation is required")
    demo_service.reset(db);result=demo_service.seed(db);_audit(db,request,actor,"reseed_demo","demo_environment");return result


@router.get("/version", dependencies=[Depends(require_permission("operations:view"))])
def version():return version_info()
@router.get("/inventory", dependencies=[Depends(require_permission("operations:inventory"))])
def inventory():return inventory_service.read_inventory()
@router.post("/inventory/generate", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:inventory"))])
def inventory_generate(request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=inventory_service.generate_inventory();add_activity(db,"inventory_generated","Local software inventory generated.","operational_inventory",None);db.commit();_audit(db,request,actor,"generate_inventory","software_inventory",metadata={"component_count":len(result["components"])});return result
@router.get("/inventory/download", dependencies=[Depends(require_permission("operations:inventory"))])
def inventory_download():return FileResponse(inventory_service.inventory_path(),filename="threatscope-software-inventory.json",media_type="application/json")
@router.post("/releases/build", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:release"))])
def release_build(payload:ReleaseBuildRequest,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    try:result,_=release_service.build_release(db,actor.id,payload.allow_dirty)
    except ValueError as exc:notify(db,"Release build failed","Release candidate could not be built safely.","danger","operational_release",None);db.commit();raise HTTPException(422,str(exc)) from exc
    _audit(db,request,actor,"build_release","release_artifact",result.get("id"),{"dirty":result["dirty_working_tree"]});return result
@router.get("/releases", dependencies=[Depends(require_permission("operations:release"))])
def releases(db:Session=Depends(get_db)):return [_release(x) for x in db.query(ReleaseArtifact).filter(ReleaseArtifact.deleted_at.is_(None)).order_by(ReleaseArtifact.created_at.desc()).limit(100)]
def _release_or_404(db,id):
    item=db.get(ReleaseArtifact,id)
    if not item or item.deleted_at is not None:raise HTTPException(404,"Release artifact not found")
    return item
@router.get("/releases/{release_id}", dependencies=[Depends(require_permission("operations:release"))])
def release_details(release_id:int,db:Session=Depends(get_db)):return _release(_release_or_404(db,release_id))
@router.get("/releases/{release_id}/download", dependencies=[Depends(require_permission("operations:release"))])
def release_download(release_id:int,db:Session=Depends(get_db)):
    item=_release_or_404(db,release_id);path=backup_service.safe_path(get_operations_config(True).release_dir,item.relative_path);return FileResponse(path,filename=item.filename,media_type="application/zip")
@router.delete("/releases/{release_id}", dependencies=[Depends(require_authenticated_csrf),Depends(require_permission("operations:release"))])
def release_delete(release_id:int,request:Request,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_release_or_404(db,release_id);path=backup_service.safe_path(get_operations_config(True).release_dir,item.relative_path);path.unlink(missing_ok=True);path.with_suffix(path.suffix+".sha256").unlink(missing_ok=True);item.deleted_at=utcnow();item.status="deleted";db.commit();_audit(db,request,actor,"delete_release","release_artifact",item.id);return {"ok":True}
