import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Notification
from app.modules.access_control.models import AccessPermission, AuthSession, UserAccount
from app.modules.access_control.redaction import redact
from app.modules.access_control.role_service import effective_permissions
from app.modules.platform_operations.maintenance_service import add_activity

from .catalog import ACTION_CATALOG, ActionDefinition
from .conditions import evaluate
from .models import (
    SoarActionPolicy, SoarAnalystInput, SoarApproval, SoarApprovalDecision, SoarExecution,
    SoarExecutionEvent, SoarExecutionEvidence, SoarPlaybook, SoarPlaybookStep,
    SoarPlaybookVersion, SoarReport, SoarRollbackRecord, SoarStepExecution,
    SoarTriggerEvaluationRun, SoarTriggerRule, utcnow,
)
from .validation import canonical, content_hash, validate_definition


TERMINAL = {"completed", "completed_with_warnings", "failed", "cancelled", "rolled_back", "rollback_failed", "expired"}
CASE_TRANSITIONS = {"new": {"triage", "investigating"}, "triage": {"investigating", "contained"}, "investigating": {"contained", "monitoring"}, "contained": {"monitoring"}, "monitoring": {"resolved"}, "reopened": {"investigating"}}


def error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, {"code": code, "message": message[:500]})


def dumps(value: Any, limit: int = 65536) -> str:
    encoded = canonical(redact(value))
    if len(encoded.encode("utf-8")) > limit: raise error(422, "SOAR_PLAYBOOK_INVALID", "JSON payload exceeds safe storage bound")
    return encoded


def loads(value: str | None, default: Any = None) -> Any:
    try: return json.loads(value) if value else ({} if default is None else default)
    except (TypeError, ValueError): return {} if default is None else default


def row(item) -> dict:
    result = {column.name: getattr(item, column.name) for column in item.__table__.columns}
    for key, value in list(result.items()):
        if key.endswith("_json") and isinstance(value, str): result[key[:-5]] = loads(value, [] if value == "[]" else {})
    return result


def page(query, page_number: int, page_size: int) -> dict:
    total = query.order_by(None).count(); items = query.offset((page_number - 1) * page_size).limit(page_size).all()
    return {"items": [row(item) for item in items], "page": page_number, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}


def normalize_name(name: str) -> str:
    return " ".join(name.casefold().split())[:200]


def policy_map(db: Session) -> dict[str, bool]:
    return {item.action_key: bool(item.enabled) for item in db.query(SoarActionPolicy).all()}


def automatic_policy_map(db: Session) -> dict[str, bool]:
    return {item.action_key: bool(item.automatic_local_allowed) for item in db.query(SoarActionPolicy).all()}


def seed_defaults(db: Session) -> None:
    for action in ACTION_CATALOG.values():
        policy = db.query(SoarActionPolicy).filter_by(action_key=action.action_key).first()
        if not policy:
            db.add(SoarActionPolicy(action_key=action.action_key, enabled=action.enabled_by_default, automatic_local_allowed=False, requester_approver_separation_required=action.requester_approver_separation_required, system_owned=True))
    db.flush()
    creator = db.query(UserAccount).filter(UserAccount.status == "active").order_by(UserAccount.is_system_admin.desc(), UserAccount.id).first()
    if creator:
        for name, category, definition in _templates():
            normalized = normalize_name(name)
            if db.query(SoarPlaybook).filter_by(normalized_name=normalized).first(): continue
            item = SoarPlaybook(playbook_uuid=str(uuid.uuid4()), name=name, normalized_name=normalized, description="Protected demonstration template. Adapt and validate for the local environment; it is not universally suitable incident-response guidance.", category=category, lifecycle_status="active", trigger_mode="proposal_only", enabled=True, system_owned=True, demo_owned=False, current_version=1, created_by_user_id=creator.id, activated_by_user_id=creator.id, activated_at=utcnow())
            result = validate_definition(definition, trigger_mode="proposal_only", policy_enabled=policy_map(db), policy_automatic=automatic_policy_map(db))
            item.validation_status = "valid" if result["valid"] else "invalid"; item.last_validated_at = utcnow(); item.validation_summary_json = dumps(result, 200000)
            db.add(item); db.flush()
            db.add(SoarPlaybookVersion(playbook_id=item.id, version_number=1, definition_json=canonical(definition), normalized_definition_json=canonical(result["normalized_definition"]), content_sha256=result["content_sha256"], change_summary="Protected system template seed", created_by_user_id=creator.id))
            _sync_steps(db, item.id, result["normalized_definition"])
    db.commit()


def _templates() -> list[tuple[str, str, dict]]:
    names = [
        ("Critical SOC Alert Triage", "soc", "load_soc_alert_context", "simulate_block_ip"),
        ("Confirmed Threat-Intelligence Match Investigation", "threat_intelligence", "load_threat_intelligence_match_context", None),
        ("High-Risk Phishing Response", "phishing", "load_phishing_analysis_context", "simulate_remove_malicious_email"),
        ("Malicious Document Investigation", "documents", "load_document_analysis_context", "simulate_quarantine_malicious_file"),
        ("Critical Vulnerability Escalation", "vulnerability", "load_vulnerability_context", None),
        ("Detection Match to Incident Case", "detections", "load_detection_match_context", None),
        ("Compromised ThreatScope Account Response", "identity", "load_user_security_context", None),
        ("SLA Breach Escalation", "vulnerability", "load_vulnerability_context", None),
        ("Reopened Vulnerability Investigation", "vulnerability", "load_vulnerability_context", None),
        ("Multiple High-Risk Signals Investigation", "correlation", "calculate_workflow_risk_summary", "simulate_isolate_host"),
    ]
    result = []
    for name, category, load_action, simulated in names:
        steps = [
            {"key": "load_context", "type": "action", "name": "Load permission-filtered context", "action_key": load_action, "position": 0, "on_success": "capture_evidence", "on_failure": "end_failed", "max_retries": 0},
            {"key": "capture_evidence", "type": "evidence_snapshot", "name": "Capture redacted evidence", "action_key": "capture_evidence_snapshot", "position": 1, "on_success": "create_case", "on_failure": "end_failed", "max_retries": 1},
            {"key": "create_case", "type": "case_workflow", "name": "Find or create incident case", "action_key": "create_incident_case", "position": 2, "on_success": "create_task", "on_failure": "end_failed", "max_retries": 1},
            {"key": "create_task", "type": "action", "name": "Create analyst review task", "action_key": "create_analyst_review_task", "position": 3, "on_success": "approval" if simulated else "notify", "on_failure": "end_failed", "max_retries": 1},
        ]
        if simulated:
            steps.extend([
                {"key": "approval", "type": "approval", "name": "Approve simulation", "position": 4, "configuration": {"approval_type": "containment_simulation", "minimum_approvals": 1, "required_permission": "soar:approve", "reason": "Explicit review before recording simulated containment"}, "on_success": "simulate", "on_failure": "end_failed", "on_timeout": "end_failed"},
                {"key": "simulate", "type": "action", "name": "Record simulation-only recommendation", "action_key": simulated, "position": 5, "configuration": {"target": "${trigger.source_id}", "reason": "Demonstration recommendation", "assumptions": ["No external infrastructure is modified"]}, "on_success": "notify", "on_failure": "end_failed"},
            ])
        steps.extend([
            {"key": "notify", "type": "notification", "name": "Notify analyst", "action_key": "create_internal_notification", "position": 6, "configuration": {"title": name, "body": "Review the playbook outcome."}, "on_success": "end_success", "on_failure": "end_failed"},
            {"key": "end_success", "type": "end", "name": "Completed", "position": 7},
            {"key": "end_failed", "type": "end", "name": "Stopped safely", "position": 8, "configuration": {"outcome": "failed"}},
        ])
        result.append((name, category, {"start_step": "load_context", "variables": {}, "constants": {"template": True}, "steps": steps}))
    return result


def _sync_steps(db: Session, playbook_id: int, definition: dict) -> None:
    db.query(SoarPlaybookStep).filter_by(playbook_id=playbook_id).delete(synchronize_session=False)
    for index, step in enumerate(definition.get("steps", [])):
        db.add(SoarPlaybookStep(playbook_id=playbook_id, stable_step_key=step["key"], step_type=step["type"], name=str(step.get("name", step["key"]))[:200], description=str(step.get("description", ""))[:2000] or None, action_key=step.get("action_key"), configuration_json=dumps(step.get("configuration", {})), input_mapping_json=dumps(step.get("input_mapping", {})), output_mapping_json=dumps(step.get("output_mapping", {})), position=int(step.get("position", index)), on_success_step_key=step.get("on_success"), on_failure_step_key=step.get("on_failure"), on_timeout_step_key=step.get("on_timeout"), timeout_seconds=step.get("timeout_seconds"), max_retries=int(step.get("max_retries", 0)), retry_delay_seconds=int(step.get("retry_delay_seconds", 0)), continue_on_failure=bool(step.get("continue_on_failure", False)), enabled=bool(step.get("enabled", True))))


def create_playbook(db: Session, payload, actor: UserAccount) -> tuple[SoarPlaybook, dict]:
    normalized = normalize_name(payload.name)
    if db.query(SoarPlaybook).filter_by(normalized_name=normalized).first(): raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "A playbook with this normalized name already exists")
    result = validate_definition(payload.definition, trigger_mode=payload.trigger_mode, policy_enabled=policy_map(db), policy_automatic=automatic_policy_map(db))
    item = SoarPlaybook(playbook_uuid=str(uuid.uuid4()), name=payload.name.strip(), normalized_name=normalized, description=payload.description, category=payload.category, lifecycle_status="draft", trigger_mode=payload.trigger_mode, severity_threshold=payload.severity_threshold, enabled=True, demo_owned=payload.demo_owned, current_version=1, owner_user_id=payload.owner_user_id, created_by_user_id=actor.id, validation_status="valid" if result["valid"] else "invalid", validation_summary_json=dumps(result, 200000), last_validated_at=utcnow())
    db.add(item); db.flush(); db.add(SoarPlaybookVersion(playbook_id=item.id, version_number=1, definition_json=canonical(payload.definition), normalized_definition_json=canonical(result["normalized_definition"]), content_sha256=result["content_sha256"], change_summary=payload.change_summary, created_by_user_id=actor.id)); _sync_steps(db, item.id, result["normalized_definition"])
    add_activity(db, "soar_playbook_created", f"SOAR playbook {item.name} created as draft.", "soar_playbook", item.id); db.commit(); db.refresh(item); return item, result


def update_playbook(db: Session, item: SoarPlaybook, payload, actor: UserAccount) -> tuple[SoarPlaybook, dict, bool]:
    if item.system_owned: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "Protected templates must be cloned before editing")
    if item.optimistic_lock_version != payload.optimistic_lock_version: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "Playbook was modified by another request")
    definition = payload.definition or loads(db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id, version_number=item.current_version).one().definition_json)
    trigger_mode = payload.trigger_mode or item.trigger_mode
    result = validate_definition(definition, trigger_mode=trigger_mode, policy_enabled=policy_map(db), policy_automatic=automatic_policy_map(db))
    new_hash = result["content_sha256"]; current = db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id, version_number=item.current_version).one()
    meaningful = new_hash != current.content_sha256
    if payload.name is not None:
        normalized = normalize_name(payload.name); existing = db.query(SoarPlaybook).filter(SoarPlaybook.normalized_name == normalized, SoarPlaybook.id != item.id).first()
        if existing: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "A playbook with this normalized name already exists")
        item.name = payload.name.strip(); item.normalized_name = normalized
    for field in ("description", "category", "trigger_mode", "severity_threshold", "owner_user_id"):
        value = getattr(payload, field)
        if value is not None: setattr(item, field, value)
    if meaningful:
        item.current_version += 1; db.add(SoarPlaybookVersion(playbook_id=item.id, version_number=item.current_version, definition_json=canonical(definition), normalized_definition_json=canonical(result["normalized_definition"]), content_sha256=new_hash, change_summary=payload.change_summary, created_by_user_id=actor.id)); _sync_steps(db, item.id, result["normalized_definition"])
    else: result["warnings"].append({"code": "SOAR_PLAYBOOK_UNCHANGED", "message": "Definition is unchanged; no meaningless version was created"})
    item.optimistic_lock_version += 1; item.validation_status = "valid" if result["valid"] else "invalid"; item.validation_summary_json = dumps(result, 200000); item.last_validated_at = utcnow()
    db.commit(); db.refresh(item); return item, result, meaningful


def validate_playbook(db: Session, item: SoarPlaybook) -> dict:
    version = db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id, version_number=item.current_version).one(); result = validate_definition(loads(version.definition_json), trigger_mode=item.trigger_mode, policy_enabled=policy_map(db), policy_automatic=automatic_policy_map(db)); item.validation_status = "valid" if result["valid"] else "invalid"; item.validation_summary_json = dumps(result, 200000); item.last_validated_at = utcnow(); db.commit(); return result


def lifecycle(db: Session, item: SoarPlaybook, target: str, actor: UserAccount, lock_version: int) -> SoarPlaybook:
    if item.optimistic_lock_version != lock_version: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "Playbook was modified by another request")
    allowed = {"draft": {"testing", "archived"}, "testing": {"active", "archived"}, "active": {"disabled"}, "disabled": {"active", "archived"}}
    if target not in allowed.get(item.lifecycle_status, set()): raise error(409, "SOAR_PLAYBOOK_INVALID", f"Transition {item.lifecycle_status} to {target} is not allowed")
    if item.system_owned and target == "archived": raise error(409, "SOAR_PLAYBOOK_INVALID", "Protected templates cannot be archived")
    validation = validate_playbook(db, item)
    if target in {"testing", "active"} and not validation["valid"]: raise error(409, "SOAR_PLAYBOOK_INVALID", "Current version must validate before lifecycle transition")
    item.lifecycle_status = target; item.enabled = target in {"testing", "active"}; item.optimistic_lock_version += 1
    if target == "active": item.activated_at = utcnow(); item.activated_by_user_id = actor.id
    elif target == "disabled": item.disabled_at = utcnow()
    elif target == "archived": item.archived_at = utcnow()
    db.commit(); db.refresh(item); return item


def clone_playbook(db: Session, source: SoarPlaybook, name: str, summary: str, actor: UserAccount) -> SoarPlaybook:
    version = db.query(SoarPlaybookVersion).filter_by(playbook_id=source.id, version_number=source.current_version).one()
    class Payload: pass
    payload = Payload(); payload.name=name; payload.description=source.description; payload.category=source.category; payload.trigger_mode="proposal_only" if source.system_owned else source.trigger_mode; payload.severity_threshold=source.severity_threshold; payload.owner_user_id=actor.id; payload.definition=loads(version.definition_json); payload.change_summary=summary; payload.demo_owned=False
    return create_playbook(db, payload, actor)[0]


def version_rollback(db: Session, item: SoarPlaybook, version_number: int, summary: str, actor: UserAccount, lock_version: int) -> SoarPlaybook:
    if item.system_owned: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "Protected templates cannot be rolled back")
    if item.optimistic_lock_version != lock_version: raise error(409, "SOAR_PLAYBOOK_VERSION_CONFLICT", "Playbook was modified by another request")
    source = db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id, version_number=version_number).first()
    if not source: raise error(404, "SOAR_PLAYBOOK_INVALID", "Version not found")
    item.current_version += 1; item.optimistic_lock_version += 1; db.add(SoarPlaybookVersion(playbook_id=item.id, version_number=item.current_version, definition_json=source.definition_json, normalized_definition_json=source.normalized_definition_json, content_sha256=source.content_sha256, change_summary=summary, created_by_user_id=actor.id)); _sync_steps(db, item.id, loads(source.normalized_definition_json)); item.validation_status = None; item.validation_summary_json = None; db.commit(); db.refresh(item); return item


def event(db: Session, execution: SoarExecution, event_type: str, summary: str, *, actor_id: int | None = None, step_id: int | None = None, previous: str | None = None, new: str | None = None, metadata: dict | None = None) -> SoarExecutionEvent:
    item = SoarExecutionEvent(execution_id=execution.id, step_execution_id=step_id, event_type=event_type[:80], previous_status=previous, new_status=new, actor_user_id=actor_id, summary=summary[:1000], metadata_json=dumps(metadata or {}, 16000)); db.add(item); return item


def _notify_once(db: Session, execution_id: int, recipient_id: int | None, title: str, message: str, level: str = "info") -> None:
    duplicate = db.query(Notification).filter_by(entity_type="soar_execution", entity_id=execution_id, recipient_user_id=recipient_id, title=title[:150]).first()
    if not duplicate: db.add(Notification(title=title[:150], message=message[:500], type=level, entity_type="soar_execution", entity_id=execution_id, recipient_user_id=recipient_id))


def _version(db: Session, execution: SoarExecution) -> SoarPlaybookVersion:
    return db.query(SoarPlaybookVersion).filter_by(playbook_id=execution.playbook_id, version_number=execution.playbook_version).one()


def create_execution(db: Session, playbook: SoarPlaybook, payload, actor: UserAccount, *, trigger_rule_id: int | None = None, proposed: bool = False) -> SoarExecution:
    existing = db.query(SoarExecution).filter_by(playbook_id=playbook.id, idempotency_key=payload.idempotency_key).first()
    if existing: return existing
    if playbook.lifecycle_status == "archived" or (payload.mode == "live_local" and playbook.lifecycle_status != "active") or (payload.mode != "live_local" and playbook.lifecycle_status not in {"testing", "active"}): raise error(409, "SOAR_PLAYBOOK_NOT_ACTIVE", "Playbook lifecycle does not permit this execution mode")
    version = db.query(SoarPlaybookVersion).filter_by(playbook_id=playbook.id, version_number=playbook.current_version).one(); validation = validate_definition(loads(version.definition_json), trigger_mode=playbook.trigger_mode, policy_enabled=policy_map(db), policy_automatic=automatic_policy_map(db))
    if not validation["valid"]: raise error(422, "SOAR_PLAYBOOK_INVALID", "Current playbook version is invalid")
    if payload.mode == "live_local" and validation["simulation_only_actions"]: raise error(422, "SOAR_ACTION_MODE_NOT_ALLOWED", "A playbook containing simulation-only actions cannot execute in live-local mode")
    execution = SoarExecution(execution_uuid=str(uuid.uuid4()), playbook_id=playbook.id, playbook_version=playbook.current_version, trigger_rule_id=trigger_rule_id, trigger_source_type=payload.trigger_source_type, trigger_source_id=payload.trigger_source_id, idempotency_key=payload.idempotency_key, mode=payload.mode, status="proposed" if proposed else "queued", requested_by_user_id=actor.id, current_step_key=loads(version.definition_json).get("start_step"), input_context_json=dumps(payload.input_context), variable_state_json=dumps(loads(version.definition_json).get("variables", {})), output_summary_json="{}", expires_at=utcnow()+timedelta(hours=72), demo_owned=playbook.demo_owned)
    db.add(execution)
    try: db.flush()
    except IntegrityError:
        db.rollback(); existing = db.query(SoarExecution).filter_by(playbook_id=playbook.id, idempotency_key=payload.idempotency_key).first()
        if existing: return existing
        raise
    event(db, execution, "execution_proposed" if proposed else "execution_requested", "Execution proposal created." if proposed else "Execution requested.", actor_id=actor.id, new=execution.status, metadata={"mode": execution.mode, "playbook_version": execution.playbook_version})
    if proposed:_notify_once(db,execution.id,actor.id,"SOAR execution proposed",f"Execution proposal {execution.execution_uuid[:16]} is ready for analyst review.","info")
    add_activity(db,"soar_execution_proposed" if proposed else "soar_execution_requested",f"SOAR execution {execution.execution_uuid[:16]} was {'proposed' if proposed else 'requested' }.","soar_execution",execution.id)
    playbook.execution_count += 1; playbook.last_executed_at = utcnow(); db.commit(); db.refresh(execution)
    if not proposed: run_execution(db, execution, actor)
    return execution


def _context(db: Session, execution: SoarExecution, definition: dict) -> dict:
    variables = loads(execution.variable_state_json); step_outputs = {}
    for item in db.query(SoarStepExecution).filter_by(execution_id=execution.id).filter(SoarStepExecution.status.in_(["succeeded", "simulated", "skipped"])).order_by(SoarStepExecution.id): step_outputs[item.step_key] = {"output": loads(item.output_snapshot_json)}
    return {"trigger": {"source_type": execution.trigger_source_type, "source_id": execution.trigger_source_id, **loads(execution.input_context_json)}, "execution": {"id": execution.id, "uuid": execution.execution_uuid, "mode": execution.mode}, "playbook": {"id": execution.playbook_id, "version": execution.playbook_version}, "steps": step_outputs, "analyst_input": {}, "constants": definition.get("constants", {}), **variables}


def _create_step(db: Session, execution: SoarExecution, step: dict) -> SoarStepExecution:
    sequence = db.query(func.count(SoarStepExecution.id)).filter_by(execution_id=execution.id).scalar() + 1
    idem = hashlib.sha256(f"{execution.execution_uuid}:{step['key']}".encode()).hexdigest()
    existing = db.query(SoarStepExecution).filter_by(execution_id=execution.id, idempotency_key=idem).order_by(SoarStepExecution.attempt_number.desc()).first()
    if existing and existing.status in {"succeeded", "simulated", "skipped", "approved", "waiting_approval", "waiting_input", "waiting_delay"}: return existing
    attempt = (existing.attempt_number + 1) if existing and existing.status == "failed" else 1
    item = SoarStepExecution(execution_id=execution.id, step_key=step["key"], step_name=str(step.get("name", step["key"]))[:200], step_type=step["type"], action_key=step.get("action_key"), sequence_number=sequence, attempt_number=attempt, idempotency_key=idem, status="running", input_snapshot_json=dumps(step.get("configuration", {})), redacted_input_summary=f"Bounded {step['type']} input", started_at=utcnow())
    db.add(item); db.flush(); return item


def _pending_approval(db: Session, execution: SoarExecution, step: SoarStepExecution, definition: ActionDefinition | None, config: dict, actor: UserAccount, approval_type: str) -> SoarApproval:
    existing = db.query(SoarApproval).filter_by(execution_id=execution.id, step_execution_id=step.id).order_by(SoarApproval.id.desc()).first()
    if existing: return existing
    sensitive = definition is not None and definition.safety_classification == "sensitive_local"
    approval = SoarApproval(approval_uuid=str(uuid.uuid4()), execution_id=execution.id, step_execution_id=step.id, approval_type=approval_type, required_permission="soar:approve" if not sensitive else "soar:sensitive_actions", minimum_approvals=max(1, min(5, int(config.get("minimum_approvals", 1)))), requester_user_id=actor.id, assigned_to_user_id=config.get("assigned_to_user_id"), assigned_role_name=str(config.get("assigned_role_name", "Administrator" if sensitive else ""))[:100] or None, status="pending", request_reason=str(config.get("reason", "Explicit approval required before execution"))[:2000], request_context_json=dumps({"action_key": definition.action_key if definition else None, "safety_classification": definition.safety_classification if definition else "approval"}), separation_required=bool(sensitive or config.get("separation_required", False)), expires_at=utcnow()+timedelta(hours=min(72, max(1, int(config.get("expires_hours", 24))))))
    db.add(approval); step.status="waiting_approval"; execution.status="waiting_approval"; event(db, execution, "approval_requested", "Execution paused for explicit approval.", actor_id=actor.id, step_id=step.id, previous="running", new="waiting_approval", metadata={"approval_type": approval_type, "safety_classification": definition.safety_classification if definition else "approval"}); _notify_once(db,execution.id,approval.assigned_to_user_id,"SOAR approval requested",f"Execution {execution.execution_uuid[:16]} requires {approval_type.replace('_',' ')} approval.","warning"); add_activity(db,"soar_approval_requested",f"SOAR execution {execution.execution_uuid[:16]} paused for {approval_type} approval.","soar_execution",execution.id); db.flush(); return approval


def run_execution(db: Session, execution: SoarExecution, actor: UserAccount) -> SoarExecution:
    if execution.status in TERMINAL: raise error(409, "SOAR_EXECUTION_TERMINAL", "Terminal execution cannot resume")
    if execution.expires_at and execution.expires_at <= utcnow(): execution.status="expired"; execution.completed_at=utcnow(); event(db, execution, "execution_expired", "Execution expired before completion.", actor_id=actor.id, new="expired"); db.commit(); return execution
    definition = loads(_version(db, execution).definition_json); by_key={step["key"]: step for step in definition.get("steps", [])}; previous=execution.status; execution.status="running"; execution.started_at=execution.started_at or utcnow(); event(db, execution, "execution_resumed" if previous.startswith("waiting") else "execution_started", "Execution processing started.", actor_id=actor.id, previous=previous, new="running")
    processed=0
    while execution.current_step_key and processed < 50:
        processed += 1
        step = by_key.get(execution.current_step_key)
        if not step: return _fail(db, execution, actor, "SOAR_PLAYBOOK_INVALID", "Current step is unavailable")
        step_run = _create_step(db, execution, step)
        if step_run.status in {"waiting_approval", "waiting_input", "waiting_delay"}: db.commit(); return execution
        try:
            step_type = step["type"]; config = step.get("configuration", {}) if isinstance(step.get("configuration", {}), dict) else {}
            if execution.mode == "dry_run" and step_type != "end":
                output={"status":"intended", "summary":f"Dry run recorded intended {step_type} step; no mutation was performed."}; status="skipped"; route=step.get("on_success")
            elif step_type == "end":
                outcome=config.get("outcome", "completed")
                if outcome == "failed": return _fail(db, execution, actor, "SOAR_STEP_FAILED", "Workflow reached its failure terminal")
                step_run.status="succeeded"; step_run.output_snapshot_json=dumps({"status":"completed","summary":"Terminal step reached"}); step_run.completed_at=utcnow(); execution.status="completed"; execution.completed_at=utcnow(); execution.current_step_key=None; event(db, execution, "execution_completed", "Execution completed.", actor_id=actor.id, step_id=step_run.id, previous="running", new="completed"); playbook=db.get(SoarPlaybook,execution.playbook_id); playbook.successful_execution_count+=1; add_activity(db,"soar_execution_completed",f"SOAR execution {execution.execution_uuid[:16]} completed.","soar_execution",execution.id); db.commit(); return execution
            elif step_type == "condition":
                decision=evaluate(step.get("condition"), _context(db, execution, definition)); output={"status":"succeeded","matched":decision.matched,"summary":decision.explanation}; status="succeeded"; route=step.get("on_success") if decision.matched else step.get("on_failure")
            elif step_type == "approval":
                approval=_pending_approval(db, execution, step_run, None, config, actor, str(config.get("approval_type","step"))); db.commit(); return execution
            elif step_type == "analyst_input":
                existing=db.query(SoarAnalystInput).filter_by(step_execution_id=step_run.id).first()
                if not existing:
                    fields=config.get("fields", []); existing=SoarAnalystInput(input_uuid=str(uuid.uuid4()),execution_id=execution.id,step_execution_id=step_run.id,title=str(config.get("title",step_run.step_name))[:200],instructions=str(config.get("instructions","Analyst input is required."))[:4000],schema_json=dumps(fields),required_fields_json=dumps([f.get("name") for f in fields if f.get("required")]),requested_from_user_id=config.get("requested_from_user_id"),requested_from_role=str(config.get("requested_from_role","Security Analyst"))[:100],status="pending",expires_at=utcnow()+timedelta(hours=min(72,max(1,int(config.get("expires_hours",24))))));db.add(existing)
                step_run.status="waiting_input";execution.status="waiting_input";event(db,execution,"analyst_input_requested","Execution paused for bounded analyst input.",actor_id=actor.id,step_id=step_run.id,previous="running",new="waiting_input");_notify_once(db,execution.id,existing.requested_from_user_id or execution.requested_by_user_id,"SOAR analyst input required",f"Execution {execution.execution_uuid[:16]} requires bounded analyst input.","warning");add_activity(db,"soar_analyst_input_requested",f"SOAR execution {execution.execution_uuid[:16]} paused for analyst input.","soar_execution",execution.id);db.commit();return execution
            elif step_type == "delay":
                seconds=int(config.get("delay_seconds",1));step_run.status="waiting_delay";execution.status="waiting_delay";execution.next_resume_at=utcnow()+timedelta(seconds=seconds);event(db,execution,"delay_started",f"Execution paused for {seconds} seconds without blocking.",actor_id=actor.id,step_id=step_run.id,previous="running",new="waiting_delay");db.commit();return execution
            else:
                action=ACTION_CATALOG.get(step.get("action_key"));
                if not action: return _fail(db,execution,actor,"SOAR_ACTION_UNKNOWN","Action is not in the server-owned catalog")
                policy=db.query(SoarActionPolicy).filter_by(action_key=action.action_key).first()
                if not policy or not policy.enabled: return _fail(db,execution,actor,"SOAR_ACTION_DISABLED","Action is disabled by policy")
                if execution.mode not in action.allowed_execution_modes: return _fail(db,execution,actor,"SOAR_ACTION_MODE_NOT_ALLOWED","Action cannot run in this execution mode")
                if action.required_permission not in effective_permissions(db,actor): return _fail(db,execution,actor,"SOAR_PERMISSION_DENIED","Dispatch-time action permission denied")
                approval_type="sensitive_action" if action.safety_classification=="sensitive_local" else "containment_simulation" if action.simulation_only else None
                if approval_type:
                    approval=_pending_approval(db,execution,step_run,action,config,actor,approval_type)
                    if approval.status!="approved": db.commit();return execution
                output=_dispatch(db,execution,step_run,action,config,actor);status="simulated" if action.simulation_only else "succeeded";route=step.get("on_success")
            step_run.status=status;step_run.output_snapshot_json=dumps(output);step_run.redacted_output_summary=str(output.get("summary",""))[:2000];step_run.completed_at=utcnow();execution.current_step_key=route;event(db,execution,"step_completed",f"Step {step_run.step_name} completed with status {status}.",actor_id=actor.id,step_id=step_run.id,previous="running",new=status,metadata={"action_key":step_run.action_key,"safety_classification":ACTION_CATALOG[step_run.action_key].safety_classification if step_run.action_key in ACTION_CATALOG else None})
            db.commit()
            if not route:
                execution.status="completed_with_warnings";execution.completed_at=utcnow();event(db,execution,"execution_completed_with_warnings","Execution stopped at a step without a success route.",actor_id=actor.id,new=execution.status);_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR execution completed with warnings",f"Execution {execution.execution_uuid[:16]} completed with warnings.","warning");add_activity(db,"soar_execution_completed_with_warnings",f"SOAR execution {execution.execution_uuid[:16]} completed with warnings.","soar_execution",execution.id);db.commit();return execution
        except HTTPException: raise
        except Exception as exc:
            db.rollback(); execution=db.get(SoarExecution,execution.id); return _fail(db,execution,actor,"SOAR_STEP_FAILED",str(exc)[:500])
    return _fail(db,execution,actor,"SOAR_PLAYBOOK_INVALID","Execution exceeded the bounded 50-step dispatch limit")


def _fail(db:Session,execution:SoarExecution,actor:UserAccount,code:str,summary:str)->SoarExecution:
    latest=db.query(SoarStepExecution).filter_by(execution_id=execution.id,status="running").order_by(SoarStepExecution.id.desc()).first()
    if latest:latest.status="failed";latest.error_code=code;latest.error_summary=summary[:1000];latest.completed_at=utcnow()
    execution.status="failed";execution.error_code=code;execution.error_summary=summary[:1000];execution.completed_at=utcnow();event(db,execution,"execution_failed",summary[:1000],actor_id=actor.id,step_id=latest.id if latest else None,new="failed",metadata={"error_code":code});playbook=db.get(SoarPlaybook,execution.playbook_id);playbook.failed_execution_count+=1;_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR execution failed",f"Execution {execution.execution_uuid[:16]} failed safely with {code}.","danger");add_activity(db,"soar_execution_failed",f"SOAR execution {execution.execution_uuid[:16]} failed safely.","soar_execution",execution.id);db.commit();return execution


def _dispatch(db:Session,execution:SoarExecution,step:SoarStepExecution,action:ActionDefinition,config:dict,actor:UserAccount)->dict:
    if action.simulation_only:
        execution.simulated_action_count+=1
        return {"status":"simulated","summary":f"Simulated {action.display_name.lower()}. No external infrastructure was modified.","intended_target":str(config.get("target",execution.trigger_source_id))[:500],"reason":str(config.get("reason","Approved simulation"))[:2000],"assumptions":redact(config.get("assumptions",[])),"simulation_only":True,"external_infrastructure_modified":False}
    if action.safety_classification=="read_only": return _read_context(db,action.action_key,int(config.get("source_id") or execution.trigger_source_id or 0))
    if execution.mode=="simulation" and not config.get("perform_harmless_local",False): return {"status":"intended","summary":"Simulation recorded the intended local action; no local mutation was configured."}
    before={};record_id=None;key=action.action_key
    from app.modules.unified_correlation.models import IncidentActionItem,IncidentCase,IncidentEvidence,IncidentNote,IncidentTimelineEvent
    from app.modules.soc_monitor.models import SocAlert
    from app.modules.detection_engineering.models import DetectionMatch,DetectionSuppression
    from app.modules.threat_intelligence.models import IndicatorMatch,ThreatWatchlist,ThreatWatchlistEntry
    from app.modules.vulnerability_management.models import RemediationPlan,RemediationTask,RiskAcceptance,VerificationRequest,VulnerabilityComment,VulnerabilityRecord
    case_id=int(config.get("case_id") or loads(execution.variable_state_json).get("case_id") or 0)
    case=db.get(IncidentCase,case_id) if case_id else None
    if key=="create_incident_case":
        fingerprint=hashlib.sha256(f"soar:{execution.id}:{step.step_key}".encode()).hexdigest()[:20];case=db.query(IncidentCase).filter_by(case_key=f"SOAR-{fingerprint}").first()
        if not case: case=IncidentCase(case_key=f"SOAR-{fingerprint}",title=str(config.get("title") or f"SOAR investigation {execution.execution_uuid[:8]}")[:240],summary=str(config.get("body") or "Created by an approved ThreatScope SOAR-Lite playbook.")[:8000],case_type="soar_investigation",severity=str(config.get("severity","high")),priority="P2",confidence="medium",risk_score=50,status="new",source_module_count=1,evidence_count=0,tags_json='["soar"]');db.add(case);db.flush();execution.records_created+=1
        variables=loads(execution.variable_state_json);variables["case_id"]=case.id;execution.variable_state_json=dumps(variables);record_id=case.id
    elif key in {"assign_case_owner","change_case_severity","transition_case_lifecycle","add_case_tag","remove_case_tag","restore_case_owner","restore_case_severity","restore_case_status"}:
        if not case: raise ValueError("Incident case target is invalid")
        if key in {"assign_case_owner","restore_case_owner"}:before={"case_id":case.id,"assignee_name":case.assignee_name};case.assignee_name=str(config.get("value") or config.get("owner_user_id") or "Unassigned")[:200]
        elif key in {"change_case_severity","restore_case_severity"}:before={"case_id":case.id,"severity":case.severity};case.severity=str(config.get("severity") or config.get("value") or case.severity)[:16]
        elif key in {"transition_case_lifecycle","restore_case_status"}:before={"case_id":case.id,"status":case.status};target=str(config.get("status") or config.get("value"));
        if key in {"transition_case_lifecycle","restore_case_status"}:
            if key=="transition_case_lifecycle" and target not in CASE_TRANSITIONS.get(case.status,set()): raise ValueError("Invalid incident-case lifecycle transition")
            if target=="resolved": raise ValueError("Automatic case closure is prohibited")
            case.status=target[:30]
        if key in {"add_case_tag","remove_case_tag"}:
            tags=loads(case.tags_json,[]);value=str(config.get("value") or "soar")[:100];before={"case_id":case.id,"tags":tags};tags=([*tags,value] if key=="add_case_tag" and value not in tags else [item for item in tags if item!=value] if key=="remove_case_tag" else tags);case.tags_json=dumps(tags)
        execution.records_updated+=1;record_id=case.id
    elif key=="add_case_comment":
        if not case: raise ValueError("Incident case target is invalid")
        item=IncidentNote(case_id=case.id,note_text=str(config.get("body") or config.get("reason"))[:8000],author_label=actor.display_name[:100]);db.add(item);db.flush();record_id=item.id;execution.records_created+=1
    elif key in {"create_investigation_checklist_item","create_case_follow_up_task","create_alert_review_task","create_analyst_review_task","create_ioc_review_task","cancel_case_task","assign_internal_task"}:
        if key=="cancel_case_task":
            item=db.get(IncidentActionItem,int(config.get("record_id") or 0));
            if not item: raise ValueError("Case task is unavailable")
            before={"record_id":item.id,"status":item.status};item.status="cancelled";record_id=item.id;execution.records_updated+=1
        else:
            if not case:
                case=db.query(IncidentCase).filter_by(case_key=f"SOAR-{hashlib.sha256(f'soar:{execution.id}:create_case'.encode()).hexdigest()[:20]}").first()
            if not case: raise ValueError("A case is required for this analyst task")
            stable=f"[SOAR:{execution.id}:{step.step_key}]";item=db.query(IncidentActionItem).filter(IncidentActionItem.case_id==case.id,IncidentActionItem.description.like(f"%{stable}%")).first()
            if not item:item=IncidentActionItem(case_id=case.id,title=str(config.get("title") or action.display_name)[:240],description=(str(config.get("body") or config.get("reason") or "Review playbook output")+" "+stable)[:8000],status="open",priority="medium",assignee_name=str(config.get("owner_user_id") or actor.display_name)[:200]);db.add(item);db.flush();execution.records_created+=1
            record_id=item.id
    elif key in {"add_case_evidence","link_soc_alert_to_case","link_detection_match_to_case","link_threat_intelligence_match_to_case","link_vulnerability_to_case","link_phishing_analysis_to_case","link_document_analysis_to_case"}:
        if not case: raise ValueError("Incident case target is invalid")
        source_id=int(config.get("source_id") or execution.trigger_source_id or 0);source_type=key.removeprefix("link_").removesuffix("_to_case");fingerprint=hashlib.sha256(f"{case.id}:{source_type}:{source_id}:{step.id}".encode()).hexdigest();item=db.query(IncidentEvidence).filter_by(evidence_fingerprint=fingerprint).first()
        if not item:item=IncidentEvidence(case_id=case.id,source_module=source_type[:30],source_record_type=source_type[:50],source_record_id=source_id,source_internal_route=None,title_snapshot=action.display_name[:500],evidence_snapshot="Redacted SOAR source link",severity="high",confidence="medium",evidence_fingerprint=fingerprint);db.add(item);case.evidence_count+=1;execution.records_created+=1
        if key=="link_detection_match_to_case":
            target=db.get(DetectionMatch,source_id)
            if target:target.case_id=case.id
        if key=="link_threat_intelligence_match_to_case":
            target=db.get(IndicatorMatch,source_id)
            if target:target.case_id=case.id
        db.flush();record_id=item.id
    elif key in {"mark_soc_alert_reviewing","add_soc_alert_note"}:
        target=db.get(SocAlert,int(config.get("source_id") or execution.trigger_source_id or 0));
        if not target:raise ValueError("SOC alert target is invalid")
        before={"record_id":target.id,"status":target.status,"analyst_notes":target.analyst_notes};target.status="reviewing" if key=="mark_soc_alert_reviewing" else target.status;target.analyst_notes=(target.analyst_notes or "")+("\n" if target.analyst_notes else "")+str(config.get("body") or config.get("reason") or "SOAR review")[:4000];record_id=target.id;execution.records_updated+=1
    elif key=="create_detection_suppression_proposal":
        item=DetectionSuppression(name=str(config.get("title") or "SOAR suppression proposal")[:160],description=(str(config.get("reason") or "Analyst review required")+" [PROPOSAL ONLY]")[:4000],field_conditions_json="{}",enabled=False,created_by_user_id=actor.id);db.add(item);db.flush();record_id=item.id;execution.records_created+=1
    elif key=="add_indicator_to_watchlist":
        indicator_id=int(config.get("source_id") or execution.trigger_source_id or 0);watch=db.query(ThreatWatchlist).filter_by(name="Under Investigation").first() or db.query(ThreatWatchlist).filter_by(enabled=True).first();
        if not watch:raise ValueError("No enabled ThreatScope watchlist is available")
        item=db.query(ThreatWatchlistEntry).filter_by(watchlist_id=watch.id,indicator_id=indicator_id).first()
        if not item:item=ThreatWatchlistEntry(watchlist_id=watch.id,indicator_id=indicator_id,added_by_user_id=actor.id,note="Added by approved SOAR workflow");db.add(item);db.flush();execution.records_created+=1
        record_id=item.id
    elif key in {"assign_vulnerability","restore_vulnerability_owner","add_vulnerability_comment","create_remediation_plan_draft","create_remediation_task","cancel_remediation_task","request_vulnerability_verification","create_risk_acceptance_proposal"}:
        if key=="cancel_remediation_task":item=db.get(RemediationTask,int(config.get("record_id") or 0));item.status="cancelled" if item else None;record_id=item.id if item else None
        else:
            vulnerability=db.get(VulnerabilityRecord,int(config.get("source_id") or execution.trigger_source_id or 0));
            if not vulnerability:raise ValueError("Vulnerability target is invalid")
            if key in {"assign_vulnerability","restore_vulnerability_owner"}:before={"vulnerability_id":vulnerability.id,"owner_user_id":vulnerability.current_owner_user_id};vulnerability.current_owner_user_id=config.get("owner_user_id") or config.get("value");record_id=vulnerability.id
            elif key=="add_vulnerability_comment":item=VulnerabilityComment(vulnerability_id=vulnerability.id,author_user_id=actor.id,comment_type="analyst_note",body=str(config.get("body") or config.get("reason"))[:8000]);db.add(item);db.flush();record_id=item.id
            elif key=="create_remediation_plan_draft":item=RemediationPlan(vulnerability_id=vulnerability.id,title=str(config.get("title") or "SOAR remediation plan")[:300],objective=str(config.get("reason") or "Review and remediate")[:8000],remediation_guidance="Analyst-defined local remediation is required; no external action was performed.",status="draft",priority=str(config.get("severity") or "high"),owner_user_id=config.get("owner_user_id"),created_by_user_id=actor.id);db.add(item);db.flush();record_id=item.id
            elif key=="create_remediation_task":
                plan=db.get(RemediationPlan,int(config.get("plan_id") or 0)) or db.query(RemediationPlan).filter_by(vulnerability_id=vulnerability.id,status="draft").order_by(RemediationPlan.id.desc()).first()
                if not plan:raise ValueError("A remediation plan is required")
                item=RemediationTask(plan_id=plan.id,title=str(config.get("title") or "SOAR remediation review")[:300],description=str(config.get("body") or config.get("reason"))[:8000],task_type="coordination",status="todo",assignee_user_id=config.get("owner_user_id"),created_by_user_id=actor.id);db.add(item);db.flush();record_id=item.id
            elif key=="request_vulnerability_verification":item=VerificationRequest(vulnerability_id=vulnerability.id,requested_by_user_id=actor.id,assigned_to_user_id=config.get("owner_user_id"),verification_type="manual_confirmation",status="requested",request_note=str(config.get("reason"))[:8000],source_module="soar",source_entity_type="execution",source_entity_id=execution.id);db.add(item);db.flush();record_id=item.id
            else:item=RiskAcceptance(vulnerability_id=vulnerability.id,reason=str(config.get("reason"))[:8000],residual_risk=str(config.get("severity") or "high"),accepted_by_user_id=actor.id,accepted_at=utcnow(),expires_at=utcnow()+timedelta(days=30),status="pending");db.add(item);db.flush();record_id=item.id
            execution.records_created+=1
    elif key=="create_internal_notification":
        stable=f"SOAR execution {execution.execution_uuid}";item=db.query(Notification).filter_by(title=str(config.get("title") or action.display_name)[:150],entity_type="soar_execution",entity_id=execution.id,recipient_user_id=config.get("owner_user_id") or actor.id).first()
        if not item:item=Notification(title=str(config.get("title") or action.display_name)[:150],message=(str(config.get("body") or config.get("reason") or stable)+f" ({stable})")[:500],type="info",entity_type="soar_execution",entity_id=execution.id,recipient_user_id=config.get("owner_user_id") or actor.id);db.add(item);db.flush();execution.records_created+=1
        record_id=item.id
    elif key in {"capture_evidence_snapshot","add_supported_record_tag"}:
        snapshot=redact({"source_id":config.get("source_id") or execution.trigger_source_id,"source_type":execution.trigger_source_type,"summary":config.get("body") or config.get("reason")});encoded=dumps(snapshot,16000);digest=hashlib.sha256(encoded.encode()).hexdigest();item=db.query(SoarExecutionEvidence).filter_by(execution_id=execution.id,content_sha256=digest).first()
        if not item:item=SoarExecutionEvidence(execution_id=execution.id,step_execution_id=step.id,evidence_type="audit_safe_snapshot",source_module=execution.trigger_source_type,source_entity_type=execution.trigger_source_type,source_entity_id=int(config.get("source_id") or execution.trigger_source_id or execution.id),summary="Redacted evidence snapshot captured by SOAR.",redacted_snapshot_json=encoded,content_sha256=digest);db.add(item);db.flush();execution.records_created+=1
        record_id=item.id
    elif key in {"revoke_selected_session","revoke_other_user_sessions","temporarily_disable_user","reenable_user"}:
        reason=str(config.get("reason") or "")
        if not reason:raise ValueError("Sensitive action requires an explicit reason")
        target_user=db.get(UserAccount,int(config.get("user_id") or config.get("source_id") or execution.trigger_source_id or 0))
        if key=="revoke_selected_session":
            session=db.get(AuthSession,int(config.get("session_id") or 0));
            if not session:raise ValueError("Target session is invalid")
            if session.id==getattr(actor,"_soar_current_session_id",None):raise ValueError("Unsafe current-session revocation is prohibited")
            session.revoked_at=session.revoked_at or utcnow();session.revoke_reason="soar_sensitive_action";record_id=session.id
        else:
            if not target_user:raise ValueError("Target user is invalid")
            active_admins=db.query(UserAccount).filter(UserAccount.status=="active",UserAccount.is_system_admin.is_(True)).count()
            if key=="temporarily_disable_user":
                if target_user.id==actor.id:raise error(409,"SOAR_SENSITIVE_ACTION_DENIED","Unsafe self-disablement is prohibited")
                if target_user.is_system_admin and active_admins<=1:raise error(409,"SOAR_LAST_ADMIN_PROTECTED","The only active Administrator cannot be disabled")
                target_user.status="disabled";target_user.disabled_at=utcnow();db.query(AuthSession).filter(AuthSession.user_id==target_user.id,AuthSession.revoked_at.is_(None)).update({AuthSession.revoked_at:utcnow(),AuthSession.revoke_reason:"user_disabled_by_soar"},synchronize_session=False)
            elif key=="reenable_user":target_user.status="active";target_user.disabled_at=None
            else:
                if target_user.id==actor.id:raise error(409,"SOAR_SENSITIVE_ACTION_DENIED","Use normal session controls for the current user; this action is limited to another user")
                db.query(AuthSession).filter(AuthSession.user_id==target_user.id,AuthSession.revoked_at.is_(None)).update({AuthSession.revoked_at:utcnow(),AuthSession.revoke_reason:"soar_sensitive_action"},synchronize_session=False)
            record_id=target_user.id
        execution.records_updated+=1
    else: raise ValueError("Action implementation is not allowlisted")
    return {"status":"succeeded","record_id":record_id,"summary":f"Allowlisted local action completed: {action.display_name}.","before_state":redact(before),"safety_classification":action.safety_classification}


def _read_context(db:Session,key:str,source_id:int)->dict:
    model=None
    if key=="load_soc_alert_context":from app.modules.soc_monitor.models import SocAlert;model=SocAlert
    elif key=="load_incident_case_context":from app.modules.unified_correlation.models import IncidentCase;model=IncidentCase
    elif key=="load_detection_match_context":from app.modules.detection_engineering.models import DetectionMatch;model=DetectionMatch
    elif key=="load_threat_intelligence_match_context":from app.modules.threat_intelligence.models import IndicatorMatch;model=IndicatorMatch
    elif key=="load_vulnerability_context":from app.modules.vulnerability_management.models import VulnerabilityRecord;model=VulnerabilityRecord
    elif key=="load_phishing_analysis_context":from app.modules.phishing_defense.models import PhishingAnalysis;model=PhishingAnalysis
    elif key=="load_document_analysis_context":from app.modules.document_threats.models import DocumentAnalysis;model=DocumentAnalysis
    elif key=="load_user_security_context":model=UserAccount
    elif key=="load_session_metadata":model=AuthSession
    elif key=="load_asset_context":from app.modules.vulnerability_management.models import Asset;model=Asset
    elif key=="check_existing_case_link":from app.modules.unified_correlation.models import IncidentEvidence;model=IncidentEvidence
    elif key=="check_existing_remediation_task":from app.modules.vulnerability_management.models import RemediationTask;model=RemediationTask
    elif key=="check_existing_notification":model=Notification
    elif key=="check_current_ownership":from app.modules.vulnerability_management.models import VulnerabilityRecord;model=VulnerabilityRecord
    elif key=="calculate_workflow_risk_summary":
        from app.modules.unified_correlation.models import IncidentCase
        from app.modules.soc_monitor.models import SocAlert
        from app.modules.vulnerability_management.models import VulnerabilityRecord
        return {"status":"succeeded","record_id":None,"summary":"Bounded current workflow risk summary calculated from local records.","context":{"open_high_critical_cases":db.query(IncidentCase).filter(IncidentCase.status.notin_(["resolved","closed"]),IncidentCase.severity.in_(["high","critical"])).count(),"open_high_critical_alerts":db.query(SocAlert).filter(SocAlert.status.notin_(["closed","dismissed"]),SocAlert.severity.in_(["high","critical"])).count(),"open_high_critical_vulnerabilities":db.query(VulnerabilityRecord).filter(VulnerabilityRecord.status.notin_(["resolved","archived","false_positive"]),VulnerabilityRecord.severity.in_(["high","critical"])).count()}}
    item=db.get(model,source_id) if model and source_id else None
    data={}
    if item:
        deny={"password_hash","token_hash","csrf_token_hash","secret_encrypted_or_protected","mfa_secret","recovery_code"};data={column.name:getattr(item,column.name) for column in item.__table__.columns if column.name not in deny};data=redact(data)
    return {"status":"succeeded","record_id":source_id if item else None,"summary":"Permission-filtered local context loaded." if item else "No matching local context was found.","context":data}


def decide_approval(db:Session,approval:SoarApproval,actor:UserAccount,decision:str,note:str)->SoarApproval:
    if approval.status not in {"pending","partially_approved"}:raise error(409,"SOAR_APPROVAL_ALREADY_DECIDED","Approval is no longer pending")
    if approval.expires_at and approval.expires_at<=utcnow():approval.status="expired";db.commit();raise error(409,"SOAR_APPROVAL_EXPIRED","Approval has expired")
    permissions=effective_permissions(db,actor)
    if approval.required_permission not in permissions and "soar:approve" not in permissions:raise error(403,"SOAR_APPROVAL_NOT_ELIGIBLE","Current user is not eligible to decide")
    if actor.status!="active" or (actor.locked_until and actor.locked_until>utcnow()):raise error(403,"SOAR_APPROVAL_NOT_ELIGIBLE","Disabled or locked users cannot approve")
    if approval.assigned_to_user_id and approval.assigned_to_user_id!=actor.id:raise error(403,"SOAR_APPROVAL_NOT_ELIGIBLE","Approval is assigned to another user")
    if approval.separation_required and approval.requester_user_id==actor.id:
        eligible=[u for u in db.query(UserAccount).filter(UserAccount.status=="active",UserAccount.id!=actor.id).all() if approval.required_permission in effective_permissions(db,u) or "soar:approve" in effective_permissions(db,u)]
        if eligible:raise error(403,"SOAR_APPROVAL_NOT_ELIGIBLE","Requester/approver separation is required")
    if db.query(SoarApprovalDecision).filter_by(approval_id=approval.id,decided_by_user_id=actor.id).first():raise error(409,"SOAR_APPROVAL_ALREADY_DECIDED","User already decided this approval")
    db.add(SoarApprovalDecision(approval_id=approval.id,decision=decision,decided_by_user_id=actor.id,decision_note=note));db.flush();execution=db.get(SoarExecution,approval.execution_id)
    if decision=="reject":approval.status="rejected";approval.decided_at=utcnow();execution.status="failed";execution.error_code="SOAR_APPROVAL_REQUIRED";execution.error_summary="Approval was rejected";execution.completed_at=utcnow();event(db,execution,"approval_rejected","Approval rejected; execution stopped.",actor_id=actor.id,new="failed");_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR approval rejected",f"Approval for execution {execution.execution_uuid[:16]} was rejected.","danger")
    else:
        count=db.query(SoarApprovalDecision).filter_by(approval_id=approval.id,decision="approve").count()
        if count>=approval.minimum_approvals:approval.status="approved";approval.decided_at=utcnow();execution.approved_by_user_id=actor.id;step=db.get(SoarStepExecution,approval.step_execution_id);step.status="succeeded" if step.step_type=="approval" else "approved";step.completed_at=utcnow() if step.step_type=="approval" else None;definition=loads(_version(db,execution).definition_json);source=next(item for item in definition["steps"] if item["key"]==step.step_key);execution.current_step_key=source.get("on_success") if step.step_type=="approval" else step.step_key;execution.status="queued";event(db,execution,"approval_approved","Required approval count reached.",actor_id=actor.id,new="queued")
        else:approval.status="partially_approved";event(db,execution,"approval_partially_approved","Partial approval recorded.",actor_id=actor.id,metadata={"current":count,"required":approval.minimum_approvals});_notify_once(db,execution.id,approval.assigned_to_user_id or execution.requested_by_user_id,"SOAR approval partially complete",f"Execution {execution.execution_uuid[:16]} has {count} of {approval.minimum_approvals} required approvals.","warning")
    add_activity(db,"soar_approval_decided",f"SOAR approval {approval.approval_uuid[:16]} recorded a {decision} decision.","soar_approval",approval.id)
    db.commit();db.refresh(approval)
    if approval.status=="approved":run_execution(db,execution,actor)
    return approval


def submit_analyst_input(db:Session,item:SoarAnalystInput,actor:UserAccount,response:dict)->SoarAnalystInput:
    if item.status!="pending":raise error(409,"SOAR_ANALYST_INPUT_INVALID","Analyst input is no longer pending")
    if item.expires_at and item.expires_at<=utcnow():item.status="expired";db.commit();raise error(409,"SOAR_ANALYST_INPUT_INVALID","Analyst input has expired")
    if item.requested_from_user_id and item.requested_from_user_id!=actor.id:raise error(403,"SOAR_PERMISSION_DENIED","Analyst input is assigned to another user")
    fields={field.get("name"):field for field in loads(item.schema_json,[]) if isinstance(field,dict)};required=set(loads(item.required_fields_json,[]))
    if set(response)-set(fields) or not required.issubset(response):raise error(422,"SOAR_ANALYST_INPUT_INVALID","Response fields do not match the bounded server schema")
    for key,value in response.items():
        if len(str(value))>8000:raise error(422,"SOAR_ANALYST_INPUT_INVALID","Response value is too long")
    item.response_json=dumps(response,32000);item.submitted_by_user_id=actor.id;item.status="submitted";item.submitted_at=utcnow();step=db.get(SoarStepExecution,item.step_execution_id);step.status="succeeded";step.output_snapshot_json=dumps({"status":"submitted","response":response});step.completed_at=utcnow();execution=db.get(SoarExecution,item.execution_id);definition=loads(_version(db,execution).definition_json);source=next(s for s in definition["steps"] if s["key"]==step.step_key);execution.current_step_key=source.get("on_success");execution.status="queued";event(db,execution,"analyst_input_submitted","Bounded analyst input submitted.",actor_id=actor.id,step_id=step.id,new="queued",metadata={"field_names":sorted(response)});db.commit();run_execution(db,execution,actor);return item


def cancel_execution(db:Session,execution:SoarExecution,actor:UserAccount,reason:str)->SoarExecution:
    if execution.status in TERMINAL:raise error(409,"SOAR_EXECUTION_TERMINAL","Terminal execution cannot be cancelled")
    previous=execution.status;execution.status="cancelled";execution.cancelled_at=utcnow();execution.completed_at=utcnow();execution.cancellation_reason=reason;db.query(SoarApproval).filter(SoarApproval.execution_id==execution.id,SoarApproval.status.in_(["pending","partially_approved"])).update({SoarApproval.status:"cancelled"},synchronize_session=False);db.query(SoarAnalystInput).filter_by(execution_id=execution.id,status="pending").update({SoarAnalystInput.status:"cancelled"},synchronize_session=False);event(db,execution,"execution_cancelled",reason,actor_id=actor.id,previous=previous,new="cancelled");_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR execution cancelled",f"Execution {execution.execution_uuid[:16]} was cancelled with history preserved.","warning");add_activity(db,"soar_execution_cancelled",f"SOAR execution {execution.execution_uuid[:16]} was cancelled.","soar_execution",execution.id);db.commit();return execution


def process_due(db:Session,actor:UserAccount,batch_size:int)->dict:
    now=utcnow();items=db.query(SoarExecution).filter(SoarExecution.status=="waiting_delay",SoarExecution.next_resume_at<=now).order_by(SoarExecution.next_resume_at,SoarExecution.id).limit(batch_size).all();processed=[]
    for execution in items:
        step=db.query(SoarStepExecution).filter_by(execution_id=execution.id,step_key=execution.current_step_key,status="waiting_delay").order_by(SoarStepExecution.id.desc()).first()
        if not step:continue
        definition=loads(_version(db,execution).definition_json);source=next(s for s in definition["steps"] if s["key"]==step.step_key);step.status="succeeded";step.completed_at=now;step.output_snapshot_json=dumps({"status":"delay_completed","summary":"Persistent delay became due"});execution.current_step_key=source.get("on_success");execution.next_resume_at=None;execution.status="queued";event(db,execution,"delay_completed","Due execution resumed without blocking sleep.",actor_id=actor.id,step_id=step.id,new="queued");db.commit();run_execution(db,execution,actor);processed.append(execution.id)
    expired=db.query(SoarExecution).filter(~SoarExecution.status.in_(TERMINAL),SoarExecution.expires_at<=now).all()
    for execution in expired:execution.status="expired";execution.completed_at=now;event(db,execution,"execution_expired","Execution expired during due processing.",actor_id=actor.id,new="expired")
    db.commit();return {"processed_execution_ids":processed,"processed_count":len(processed),"expired_count":len(expired),"batch_size":batch_size}


def evaluate_triggers(db:Session,payload,actor:UserAccount)->SoarTriggerEvaluationRun:
    run=SoarTriggerEvaluationRun(source_type=payload.source_type,source_entity_id=payload.source_entity_id,status="running",requested_by_user_id=actor.id);db.add(run);db.flush();rules=db.query(SoarTriggerRule).filter_by(source_type=payload.source_type,enabled=True).order_by(SoarTriggerRule.id).limit(100).all();context={"trigger":{"source_type":payload.source_type,"source_id":payload.source_entity_id,**redact(payload.source_context)}}
    for rule in rules:
        run.rules_evaluated+=1
        try:matched=evaluate(loads(rule.conditions_json),context).matched
        except Exception:run.errors_count+=1;continue
        if not matched:continue
        run.rules_matched+=1;fingerprint=hashlib.sha256(f"trigger:{rule.id}:{payload.source_type}:{payload.source_entity_id}".encode()).hexdigest();existing=db.query(SoarExecution).filter_by(playbook_id=rule.playbook_id,idempotency_key=fingerprint).first()
        if existing:run.duplicates_suppressed+=1;continue
        recent=db.query(SoarExecution).filter(SoarExecution.trigger_rule_id==rule.id,SoarExecution.created_at>=utcnow()-timedelta(minutes=rule.cooldown_minutes)).first()
        if recent:run.cooldown_suppressed+=1;continue
        hourly=db.query(SoarExecution).filter(SoarExecution.trigger_rule_id==rule.id,SoarExecution.created_at>=utcnow()-timedelta(hours=1)).count()
        if hourly>=rule.maximum_proposals_per_hour:run.cooldown_suppressed+=1;continue
        playbook=db.get(SoarPlaybook,rule.playbook_id)
        class Payload:pass
        p=Payload();p.idempotency_key=fingerprint;p.trigger_source_type=payload.source_type;p.trigger_source_id=payload.source_entity_id;p.input_context=payload.source_context;p.mode="live_local" if rule.automatic_local else "dry_run"
        execution=create_execution(db,playbook,p,actor,trigger_rule_id=rule.id,proposed=not rule.automatic_local);run.automatic_executions_created+=int(rule.automatic_local);run.proposals_created+=int(not rule.automatic_local)
    run.status="completed_with_errors" if run.errors_count else "completed";run.completed_at=utcnow();run.error_summary_json=dumps(["A bounded trigger evaluation failed"]*min(run.errors_count,20));db.commit();return run


def request_rollbacks(db:Session,execution:SoarExecution,actor:UserAccount,reason:str)->list[SoarRollbackRecord]:
    if execution.status not in TERMINAL-{"rolled_back","rollback_failed"}:raise error(409,"SOAR_EXECUTION_TERMINAL","Rollback requires a completed, failed, or cancelled execution")
    records=[]
    for step in db.query(SoarStepExecution).filter(SoarStepExecution.execution_id==execution.id,SoarStepExecution.status.in_(["succeeded","simulated"])).order_by(SoarStepExecution.id.desc()).all():
        action=ACTION_CATALOG.get(step.action_key or "");comp=action.compensating_action_key if action else None;existing=db.query(SoarRollbackRecord).filter_by(source_step_execution_id=step.id,compensating_action_key=comp).first()
        if existing:records.append(existing);continue
        output=loads(step.output_snapshot_json);record=SoarRollbackRecord(rollback_uuid=str(uuid.uuid4()),execution_id=execution.id,source_step_execution_id=step.id,compensating_action_key=comp,status="waiting_approval" if comp else "not_supported",before_state_json=dumps(output.get("before_state",{})),intended_after_state_json=dumps({"compensating_action_key":comp}) if comp else None,reason=reason,requested_by_user_id=actor.id,completed_at=utcnow() if not comp else None);db.add(record);records.append(record)
    if not records:raise error(409,"SOAR_ROLLBACK_UNSUPPORTED","Execution has no compensatable step history")
    execution.status="rollback_requested";event(db,execution,"rollback_requested","Rollback records created; unsupported actions remain explicit.",actor_id=actor.id,new="rollback_requested",metadata={"record_count":len(records)});_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR rollback requested",f"Execution {execution.execution_uuid[:16]} has {len(records)} explicit compensation records.","warning");add_activity(db,"soar_rollback_requested",f"Rollback requested for SOAR execution {execution.execution_uuid[:16]}.","soar_execution",execution.id);db.commit();return records


def execute_rollback(db:Session,record:SoarRollbackRecord,actor:UserAccount)->SoarRollbackRecord:
    if record.status!="approved":raise error(409,"SOAR_ROLLBACK_CONFLICT","Rollback must be approved before execution")
    action=ACTION_CATALOG.get(record.compensating_action_key or "")
    if not action:record.status="not_supported";record.completed_at=utcnow();db.commit();raise error(409,"SOAR_ROLLBACK_UNSUPPORTED","This action cannot be securely reversed")
    execution=db.get(SoarExecution,record.execution_id);source=db.get(SoarStepExecution,record.source_step_execution_id);config={**loads(record.before_state_json),"record_id":loads(source.output_snapshot_json).get("record_id"),"value":next((v for k,v in loads(record.before_state_json).items() if k not in {"case_id","vulnerability_id","record_id"}),None),"case_id":loads(record.before_state_json).get("case_id"),"source_id":loads(record.before_state_json).get("vulnerability_id"),"reason":record.reason};record.status="running";db.flush()
    try:output=_dispatch(db,execution,source,action,config,actor);record.status="completed";record.actual_after_state_json=dumps(output);record.executed_by_user_id=actor.id;record.completed_at=utcnow();event(db,execution,"rollback_completed","Approved local compensation completed.",actor_id=actor.id,step_id=source.id,new="rolled_back",metadata={"compensating_action_key":action.action_key});pending=db.query(SoarRollbackRecord).filter_by(execution_id=execution.id,status="waiting_approval").count();execution.status="rolled_back" if pending==0 else "rollback_requested"
    except Exception as exc:db.rollback();record=db.get(SoarRollbackRecord,record.id);record.status="failed";record.error_summary=str(exc)[:1000];record.completed_at=utcnow();execution=db.get(SoarExecution,record.execution_id);execution.status="rollback_failed";event(db,execution,"rollback_failed","Rollback failed safely and history was preserved.",actor_id=actor.id,new="rollback_failed");_notify_once(db,execution.id,execution.requested_by_user_id,"SOAR rollback failed",f"Rollback for execution {execution.execution_uuid[:16]} failed safely; history was preserved.","danger")
    add_activity(db,"soar_rollback_completed" if record.status=="completed" else "soar_rollback_failed",f"SOAR rollback {record.rollback_uuid[:16]} finished with status {record.status}.","soar_rollback",record.id)
    db.commit();return record
