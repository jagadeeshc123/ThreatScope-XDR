from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.access_control.audit_service import append_event
from app.modules.access_control.dependencies import get_current_user
from app.modules.access_control.models import SecurityAuditEvent, UserAccount
from app.modules.access_control.role_service import effective_permissions

from .catalog import DETECTOR_CATALOG, FEATURE_CATALOG, method_catalog
from .models import AnalyticsBacktest, AnalyticsBaseline, AnalyticsDetector, AnalyticsDetectorVersion, AnalyticsDriftRecord, AnalyticsEvaluation, AnalyticsJob, AnalyticsReport, AnalyticsSuppression, AnomalyContribution, AnomalyFeedback, SecurityAnomaly
from .schemas import AssignAction, BacktestCreate, BaselineBuild, DetectorCreate, DetectorPatch, DriftAcknowledge, DriftEvaluate, FeedbackCreate, JobCreate, LifecycleAction, LinkCaseAction, ProcessDue, ReasonAction, ReportCreate, SuppressionCreate, SuppressionPatch, VersionCreate
from . import service


router = APIRouter()


def _get(db: Session, model, item_id: int, label: str):
    item = db.get(model, item_id)
    if not item: raise HTTPException(404, f"{label} not found")
    return item


def _audit(db: Session, request: Request, actor: UserAccount, event_type: str, action: str, resource_type: str, resource_id, metadata=None):
    append_event(db, event_type=event_type, action=action, request_id=getattr(request.state, "request_id", "analytics"), outcome="success", actor=actor, resource_type=resource_type, resource_id=resource_id, route_template=request.url.path, request_method=request.method, status_code=200, metadata=metadata or {})


def _rate_limit(db: Session, request: Request, actor: UserAccount, operation: str, limit: int = 10):
    cutoff = service.utcnow() - timedelta(minutes=1)
    used = db.query(SecurityAuditEvent).filter(SecurityAuditEvent.actor_user_id == actor.id, SecurityAuditEvent.event_type == "analytics_rate_limit_consumed", SecurityAuditEvent.action == operation, SecurityAuditEvent.occurred_at >= cutoff).count()
    if used >= limit: raise HTTPException(429, "Analytics operation rate limit exceeded", headers={"Retry-After": "60"})
    append_event(db, event_type="analytics_rate_limit_consumed", action=operation, request_id=getattr(request.state, "request_id", "analytics"), outcome="success", actor=actor, resource_type="analytics_rate_limit", resource_id=None, route_template=request.url.path, request_method=request.method, status_code=200, metadata={"limit": limit, "window_seconds": 60})


@router.get("/catalog/features")
def features_catalog(): return {"items": [FEATURE_CATALOG[key].public() for key in sorted(FEATURE_CATALOG)], "server_owned": True, "immutable": True}


@router.get("/catalog/detectors")
def detectors_catalog(): return {"items": [DETECTOR_CATALOG[key].public() for key in sorted(DETECTOR_CATALOG)], "server_owned": True, "immutable": True, "unsupported_are_explicit": True}


@router.get("/catalog/methods")
def methods_catalog(): return {"items": method_catalog(), "server_owned": True, "immutable": True}


@router.get("/overview")
def overview(db: Session = Depends(get_db)): return service.overview(db)


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)): return service.metrics(db)


@router.get("/detectors")
def detectors(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100), state: str | None = None, source_domain: str | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsDetector).order_by(AnalyticsDetector.id.desc())
    if state:
        if state not in service.LIFECYCLE: raise HTTPException(422, "Invalid detector lifecycle filter")
        query = query.filter_by(lifecycle_state=state)
    if source_domain:
        if source_domain not in {item.source_domain for item in FEATURE_CATALOG.values()}: raise HTTPException(422, "Invalid source-domain filter")
        query = query.filter_by(source_domain=source_domain)
    return service.page(query, page, page_size)


@router.post("/detectors", status_code=201)
def create_detector(payload: DetectorCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "detector_create", 20)
    try: item = service.create_detector(db, payload, actor)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_detector_created", "detector_create", "analytics_detector", item.id, {"template_key": item.template_key})
    return service.row(item)


@router.get("/detectors/{detector_id}")
def detector(detector_id: int, db: Session = Depends(get_db)):
    item = _get(db, AnalyticsDetector, detector_id, "Detector"); result = service.row(item); result["active_version"] = service.row(db.get(AnalyticsDetectorVersion, item.active_version_id)) if item.active_version_id else None; return result


@router.patch("/detectors/{detector_id}")
def patch_detector(detector_id: int, payload: DetectorPatch, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.patch_detector(db, _get(db, AnalyticsDetector, detector_id, "Detector"), payload, actor); _audit(db, request, actor, "analytics_detector_updated", "detector_update", "analytics_detector", item.id); return service.row(item)


@router.get("/detectors/{detector_id}/versions")
def versions(detector_id: int, db: Session = Depends(get_db)):
    _get(db, AnalyticsDetector, detector_id, "Detector"); return {"items": [service.row(item) for item in db.query(AnalyticsDetectorVersion).filter_by(detector_id=detector_id).order_by(AnalyticsDetectorVersion.version_number.desc()).all()]}


@router.post("/detectors/{detector_id}/versions", status_code=201)
def create_version(detector_id: int, payload: VersionCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "detector_version_create", 20)
    try: item = service.create_version(db, _get(db, AnalyticsDetector, detector_id, "Detector"), payload, actor)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_detector_version_created", "detector_version_create", "analytics_detector_version", item.id, {"configuration_hash": item.configuration_hash}); return service.row(item)


@router.post("/detectors/{detector_id}/validate")
def validate(detector_id: int, payload: LifecycleAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "detector_validation", 10)
    detector = _get(db, AnalyticsDetector, detector_id, "Detector"); service.claim_lock(db, detector, payload.optimistic_lock_version)
    if payload.limited_validation and not actor.is_system_admin: raise HTTPException(403, "Administrator approval is required for limited validation")
    item = service.validate_detector(db, detector, actor, limited_validation=payload.limited_validation); _audit(db, request, actor, "analytics_validation_result", "detector_validate", "analytics_evaluation", item.id, {"passed": item.quality_gate_passed, "limited_validation": item.limited_validation}); return service.row(item)


def _lifecycle(detector_id: int, action: str, payload: LifecycleAction, request: Request, db: Session, actor: UserAccount):
    item = service.lifecycle(db, _get(db, AnalyticsDetector, detector_id, "Detector"), action, payload, actor); _audit(db, request, actor, f"analytics_detector_{action}", f"detector_{action}", "analytics_detector", item.id, {"reason": payload.reason, "target_version_id": payload.target_version_id}); return service.row(item)


@router.post("/detectors/{detector_id}/activate")
def activate(detector_id: int, payload: LifecycleAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _lifecycle(detector_id, "activate", payload, request, db, actor)


@router.post("/detectors/{detector_id}/disable")
def disable(detector_id: int, payload: LifecycleAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _lifecycle(detector_id, "disable", payload, request, db, actor)


@router.post("/detectors/{detector_id}/retire")
def retire(detector_id: int, payload: LifecycleAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _lifecycle(detector_id, "retire", payload, request, db, actor)


@router.post("/detectors/{detector_id}/rollback")
def rollback(detector_id: int, payload: LifecycleAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _lifecycle(detector_id, "rollback", payload, request, db, actor)


@router.get("/baselines")
def baselines(page: int = 1, page_size: int = 50, detector_version_id: int | None = None, status: str | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsBaseline).order_by(AnalyticsBaseline.id.desc())
    if detector_version_id: query = query.filter_by(detector_version_id=detector_version_id)
    if status:
        if status not in {"ready", "insufficient_data", "unavailable"}: raise HTTPException(422, "Invalid baseline status filter")
        query = query.filter_by(baseline_status=status)
    return service.page(query, page, page_size)


@router.get("/baselines/{baseline_id}")
def baseline(baseline_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsBaseline, baseline_id, "Baseline"))


@router.post("/baselines/build", status_code=201)
def build_baselines(payload: BaselineBuild, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "baseline_build", 10)
    version = _get(db, AnalyticsDetectorVersion, payload.detector_version_id, "Detector version")
    try: items = service.build_detector_baselines(db, version, payload.cutoff, actor, source_scope=payload.source_scope, source_entity_identifier=payload.source_entity_identifier, peer_group_identifier=payload.peer_group_identifier, entity_id=payload.entity_id, peer_group_size=payload.peer_group_size)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_baseline_built", "baseline_build", "analytics_detector_version", version.id, {"baseline_ids": [item.id for item in items], "idempotency_key_hash": service.deterministic_hash(payload.idempotency_key)}); return {"items": [service.row(item) for item in items]}


@router.post("/backtests", status_code=201)
def create_backtest(payload: BacktestCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    version = _get(db, AnalyticsDetectorVersion, payload.detector_version_id, "Detector version")
    try: item = service.run_backtest(db, version, payload.range_start, payload.range_end, payload.scoring_interval_seconds, actor, payload.idempotency_key, entity_id=payload.entity_id)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_backtest_completed", "backtest", "analytics_backtest", item.id, {"deterministic_hash": item.deterministic_hash, "future_leakage": item.future_leakage_detected}); return service.row(item)


@router.get("/backtests/{backtest_id}")
def backtest(backtest_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsBacktest, backtest_id, "Backtest"))


@router.get("/evaluations")
def evaluations(page: int = 1, page_size: int = 50, detector_version_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsEvaluation).order_by(AnalyticsEvaluation.id.desc()); query = query.filter_by(detector_version_id=detector_version_id) if detector_version_id else query; return service.page(query, page, page_size)


@router.get("/evaluations/{evaluation_id}")
def evaluation(evaluation_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsEvaluation, evaluation_id, "Evaluation"))


@router.get("/jobs")
def jobs(page: int = 1, page_size: int = 50, status: str | None = None, job_type: str | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsJob).order_by(AnalyticsJob.id.desc())
    if status:
        if status not in {"queued", "running", "succeeded", "failed", "cancelled"}: raise HTTPException(422, "Invalid job-status filter")
        query = query.filter_by(status=status)
    if job_type: query = query.filter_by(job_type=job_type)
    return service.page(query, page, page_size)


@router.post("/jobs", status_code=201)
def create_job(payload: JobCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.queue_job(db, payload.job_type, payload.detector_version_id, actor.id, payload.payload, payload.idempotency_key, payload.demo_owned); _audit(db, request, actor, "analytics_job_queued", "job_create", "analytics_job", item.id, {"job_type": item.job_type}); return service.row(item)


@router.get("/jobs/{job_id}")
def job(job_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsJob, job_id, "Job"))


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.cancel_job(db, _get(db, AnalyticsJob, job_id, "Job"), actor); _audit(db, request, actor, "analytics_job_cancelled", "job_cancel", "analytics_job", item.id, {"reason": payload.reason}); return service.row(item)


@router.post("/process-due")
def process_due(payload: ProcessDue, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "process_due", 20)
    result = service.process_due(db, actor, payload.batch_size); _audit(db, request, actor, "analytics_jobs_processed", "analytics_process_due", "analytics_job", None, result); return result


@router.get("/anomalies")
def anomalies(page: int = 1, page_size: int = 50, detector_id: int | None = None, source_domain: str | None = None, minimum_score: float | None = Query(None, ge=0, le=100), maximum_score: float | None = Query(None, ge=0, le=100), confidence: str | None = None, severity: str | None = None, status: str | None = None, assigned_analyst: int | None = None, linked_case: int | None = None, suppressed: bool | None = None, date_from: datetime | None = None, date_to: datetime | None = None, db: Session = Depends(get_db)):
    query = db.query(SecurityAnomaly).order_by(SecurityAnomaly.created_at.desc(), SecurityAnomaly.id.desc())
    if detector_id: query = query.filter_by(detector_id=detector_id)
    if source_domain: query = query.filter_by(source_domain=source_domain)
    if minimum_score is not None: query = query.filter(SecurityAnomaly.anomaly_score >= minimum_score)
    if maximum_score is not None: query = query.filter(SecurityAnomaly.anomaly_score <= maximum_score)
    if confidence:
        if confidence not in {"insufficient", "low", "medium", "high"}: raise HTTPException(422, "Invalid confidence filter")
        query = query.filter_by(confidence=confidence)
    if severity:
        if severity not in {"informational", "low", "medium", "high", "critical"}: raise HTTPException(422, "Invalid severity filter")
        query = query.filter_by(severity=severity)
    if status:
        if status not in service.ANOMALY_TRANSITIONS: raise HTTPException(422, "Invalid anomaly status filter")
        query = query.filter_by(status=status)
    if assigned_analyst: query = query.filter_by(assigned_analyst_id=assigned_analyst)
    if linked_case: query = query.filter_by(linked_case_id=linked_case)
    if suppressed is not None: query = query.filter_by(suppression_status="suppressed" if suppressed else "not_suppressed")
    if date_from: query = query.filter(SecurityAnomaly.created_at >= service.utc(date_from))
    if date_to: query = query.filter(SecurityAnomaly.created_at < service.utc(date_to))
    return service.page(query, page, page_size)


@router.get("/anomalies/{anomaly_id}")
def anomaly(anomaly_id: int, db: Session = Depends(get_db)):
    item = _get(db, SecurityAnomaly, anomaly_id, "Anomaly"); result = service.row(item); result["contributions"] = [service.row(value) for value in db.query(AnomalyContribution).filter_by(anomaly_id=item.id).order_by(AnomalyContribution.normalized_contribution.desc()).all()]; result["feedback"] = [service.row(value) for value in db.query(AnomalyFeedback).filter_by(anomaly_id=item.id).order_by(AnomalyFeedback.created_at.desc()).all()]; return result


@router.get("/anomalies/{anomaly_id}/explanation")
def anomaly_explanation(anomaly_id: int, db: Session = Depends(get_db)): return service.loads(_get(db, SecurityAnomaly, anomaly_id, "Anomaly").explanation_json)


def _transition(anomaly_id: int, target: str, payload: ReasonAction, request: Request, db: Session, actor: UserAccount):
    item = service.transition_anomaly(db, _get(db, SecurityAnomaly, anomaly_id, "Anomaly"), target, payload, actor); _audit(db, request, actor, "analytics_anomaly_transition", f"anomaly_{target}", "security_anomaly", item.id, {"reason": payload.reason}); return service.row(item)


@router.post("/anomalies/{anomaly_id}/acknowledge")
def acknowledge(anomaly_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _transition(anomaly_id, "acknowledged", payload, request, db, actor)


@router.post("/anomalies/{anomaly_id}/investigate")
def investigate(anomaly_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _transition(anomaly_id, "investigating", payload, request, db, actor)


@router.post("/anomalies/{anomaly_id}/confirm")
def confirm(anomaly_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _transition(anomaly_id, "confirmed", payload, request, db, actor)


@router.post("/anomalies/{anomaly_id}/dismiss")
def dismiss(anomaly_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _transition(anomaly_id, "dismissed", payload, request, db, actor)


@router.post("/anomalies/{anomaly_id}/resolve")
def resolve(anomaly_id: int, payload: ReasonAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)): return _transition(anomaly_id, "resolved", payload, request, db, actor)


@router.post("/anomalies/{anomaly_id}/assign")
def assign(anomaly_id: int, payload: AssignAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.assign_anomaly(db, _get(db, SecurityAnomaly, anomaly_id, "Anomaly"), payload, actor); _audit(db, request, actor, "analytics_anomaly_assigned", "anomaly_assign", "security_anomaly", item.id, {"assignee_user_id": payload.analyst_user_id}); return service.row(item)


@router.post("/anomalies/{anomaly_id}/link-case")
def link_case(anomaly_id: int, payload: LinkCaseAction, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.link_case(db, _get(db, SecurityAnomaly, anomaly_id, "Anomaly"), payload, actor); _audit(db, request, actor, "analytics_anomaly_linked_to_case", "anomaly_link_case", "security_anomaly", item.id, {"case_id": payload.case_id, "reason": payload.reason}); return service.row(item)


@router.post("/anomalies/{anomaly_id}/case-proposal")
def proposal(anomaly_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = _get(db, SecurityAnomaly, anomaly_id, "Anomaly"); result = service.case_proposal(item); _audit(db, request, actor, "analytics_case_proposal", "case_proposal", "security_anomaly", item.id, {"case_created": False}); return result


@router.get("/feedback")
def feedback(page: int = 1, page_size: int = 50, anomaly_id: int | None = None, label: str | None = None, db: Session = Depends(get_db)):
    query = db.query(AnomalyFeedback).order_by(AnomalyFeedback.created_at.desc(), AnomalyFeedback.id.desc()); query = query.filter_by(anomaly_id=anomaly_id) if anomaly_id else query; query = query.filter_by(label=label) if label else query; return service.page(query, page, page_size)


@router.post("/anomalies/{anomaly_id}/feedback", status_code=201)
def create_feedback(anomaly_id: int, payload: FeedbackCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.add_feedback(db, _get(db, SecurityAnomaly, anomaly_id, "Anomaly"), payload, actor); _audit(db, request, actor, "analytics_feedback_created", "feedback_create", "anomaly_feedback", item.id, {"label": item.label, "revision": item.revision_number}); return service.row(item)


@router.get("/suppressions")
def suppressions(page: int = 1, page_size: int = 50, enabled: bool | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsSuppression).order_by(AnalyticsSuppression.created_at.desc()); query = query.filter_by(enabled=enabled) if enabled is not None else query; return service.page(query, page, page_size)


@router.post("/suppressions", status_code=201)
def create_suppression(payload: SuppressionCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    try: item = service.create_suppression(db, payload, actor)
    except PermissionError as exc: raise HTTPException(403, str(exc)) from exc
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_suppression_created", "suppression_create", "analytics_suppression", item.id, {"broad_scope": item.broad_scope, "ends_at": item.ends_at.isoformat()}); return service.row(item)


@router.get("/suppressions/{suppression_id}")
def suppression(suppression_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsSuppression, suppression_id, "Suppression"))


@router.patch("/suppressions/{suppression_id}")
def patch_suppression(suppression_id: int, payload: SuppressionPatch, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.patch_suppression(db, _get(db, AnalyticsSuppression, suppression_id, "Suppression"), payload, actor); _audit(db, request, actor, "analytics_suppression_updated", "suppression_update", "analytics_suppression", item.id); return service.row(item)


@router.post("/suppressions/{suppression_id}/disable")
def disable_suppression(suppression_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.disable_suppression(db, _get(db, AnalyticsSuppression, suppression_id, "Suppression"), actor); _audit(db, request, actor, "analytics_suppression_disabled", "suppression_disable", "analytics_suppression", item.id); return service.row(item)


@router.get("/drift")
def drift_records(page: int = 1, page_size: int = 50, status: str | None = None, detector_version_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(AnalyticsDriftRecord).order_by(AnalyticsDriftRecord.detected_at.desc()); query = query.filter_by(status=status) if status else query; query = query.filter_by(detector_version_id=detector_version_id) if detector_version_id else query; return service.page(query, page, page_size)


@router.get("/drift/{drift_id}")
def drift_record(drift_id: int, db: Session = Depends(get_db)): return service.row(_get(db, AnalyticsDriftRecord, drift_id, "Drift record"))


@router.post("/drift/evaluate", status_code=201)
def evaluate_drift(payload: DriftEvaluate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _rate_limit(db, request, actor, "drift_evaluation", 10)
    try: item = service.evaluate_drift(db, payload, actor)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_drift_evaluated", "drift_evaluate", "analytics_drift", item.id, {"status": item.status, "automatic_retraining": False}); return service.row(item)


@router.post("/drift/{drift_id}/acknowledge")
def acknowledge_drift(drift_id: int, payload: DriftAcknowledge, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = service.acknowledge_drift(db, _get(db, AnalyticsDriftRecord, drift_id, "Drift record"), payload, actor); _audit(db, request, actor, "analytics_drift_acknowledged", "drift_acknowledge", "analytics_drift", item.id, {"reason": payload.reason}); return service.row(item)


@router.get("/reports")
def reports(page: int = 1, page_size: int = 50, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    query = db.query(AnalyticsReport)
    if "analytics:view" not in effective_permissions(db, actor): query = query.filter(AnalyticsReport.report_type == "executive_summary")
    return service.page(query.order_by(AnalyticsReport.created_at.desc()), page, page_size)


@router.post("/reports", status_code=201)
def create_report(payload: ReportCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    if not db.query(AnalyticsReport).filter_by(idempotency_key=payload.idempotency_key).first(): _rate_limit(db, request, actor, "report_generation", 10)
    try: item = service.generate_report(db, payload, actor)
    except ValueError as exc: raise HTTPException(422, str(exc)) from exc
    _audit(db, request, actor, "analytics_report_generated", "report_generation", "analytics_report", item.id, {"report_type": item.report_type, "content_sha256": item.content_sha256}); return service.row(item)


@router.get("/reports/{report_id}")
def report(report_id: int, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = _get(db, AnalyticsReport, report_id, "Analytics report")
    if "analytics:view" not in effective_permissions(db, actor) and item.report_type != "executive_summary": raise HTTPException(403, "Executive analytics access is aggregate-only")
    return service.row(item)


@router.get("/reports/{report_id}/html", response_class=HTMLResponse)
def report_html(report_id: int, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = _get(db, AnalyticsReport, report_id, "Analytics report")
    if "analytics:view" not in effective_permissions(db, actor) and item.report_type != "executive_summary": raise HTTPException(403, "Executive analytics access is aggregate-only")
    return item.html_content


@router.get("/reports/{report_id}/export")
def report_export(report_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = _get(db, AnalyticsReport, report_id, "Analytics report")
    if "analytics:view" not in effective_permissions(db, actor) and item.report_type != "executive_summary": raise HTTPException(403, "Executive analytics access is aggregate-only")
    _audit(db, request, actor, "analytics_report_exported", "report_export", "analytics_report", item.id, {"content_sha256": item.content_sha256}); return Response(item.html_content, media_type="text/html", headers={"Content-Disposition": f'attachment; filename="analytics-report-{item.id}.html"', "X-Content-Type-Options": "nosniff"})
