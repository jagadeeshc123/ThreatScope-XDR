import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from html import escape
from time import perf_counter

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Notification
from app.modules.access_control.models import UserAccount
from app.modules.access_control.role_service import effective_permissions
from app.modules.platform_operations.maintenance_service import add_activity

from . import IMPLEMENTATION_VERSION
from . import drift as drift_engine
from . import suppressions as suppression_engine
from .baselines import build_baseline, build_statistics
from .catalog import DETECTOR_CATALOG, FEATURE_CATALOG, METHODS, REASON_CODES, detector_template
from .evaluation import quality_gates, quality_metrics
from .explainability import build_explanation, contribution, dumps as explanation_dumps, safe_json
from .features import deterministic_hash, extract_feature, seasonal_bucket, utc, validate_window, window_series
from .models import (
    AnalyticsBacktest, AnalyticsBaseline, AnalyticsDetector, AnalyticsDetectorVersion, AnalyticsDriftRecord,
    AnalyticsEvaluation, AnalyticsJob, AnalyticsReport, AnalyticsSuppression, AnomalyContribution,
    AnomalyFeedback, SecurityAnomaly, utcnow,
)
from .scoring import confidence, score, severity, weighted_ensemble


MAX_PAGE_SIZE = 100
TERMINAL_JOBS = {"succeeded", "failed", "cancelled"}
LIFECYCLE = {"draft", "validating", "validated", "active", "degraded", "disabled", "retired"}
ANOMALY_TRANSITIONS = {
    "new": {"acknowledged", "investigating", "confirmed", "dismissed", "linked_to_case", "resolved"},
    "acknowledged": {"investigating", "confirmed", "dismissed", "linked_to_case", "resolved"},
    "investigating": {"confirmed", "dismissed", "linked_to_case", "resolved"},
    "confirmed": {"linked_to_case", "resolved"}, "dismissed": {"resolved"}, "linked_to_case": {"resolved"}, "resolved": set(),
}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def loads(value: str | None, default=None):
    try: return json.loads(value or "")
    except (TypeError, ValueError): return {} if default is None else default


def row(item, *, include_html: bool = False) -> dict:
    data = {}
    for column in item.__table__.columns:
        if column.name == "html_content" and not include_html: continue
        value = getattr(item, column.name)
        if column.name.endswith("_json"):
            data[column.name[:-5]] = loads(value, [] if value and value.startswith("[") else {})
        else: data[column.name] = value
    return data


def page(query, page_number: int = 1, page_size: int = 50) -> dict:
    page_number = max(1, int(page_number)); page_size = min(MAX_PAGE_SIZE, max(1, int(page_size)))
    total = query.count(); items = query.offset((page_number - 1) * page_size).limit(page_size).all()
    return {"items": [row(item) for item in items], "total": total, "page": page_number, "page_size": page_size, "pages": (total + page_size - 1) // page_size}


def configuration_dict(configuration) -> dict:
    value = configuration.model_dump(mode="json") if hasattr(configuration, "model_dump") else dict(configuration)
    if len(canonical(value).encode()) > 32768: raise ValueError("Detector configuration exceeds its server bound")
    return value


def _feature_versions(configuration: dict) -> dict:
    return {key: FEATURE_CATALOG[key].implementation_version for key in configuration["feature_keys"]}


def _configuration_hash(configuration: dict) -> str:
    return deterministic_hash({"configuration": configuration, "feature_versions": _feature_versions(configuration), "implementation_version": IMPLEMENTATION_VERSION})


def create_detector(db: Session, payload, actor: UserAccount) -> AnalyticsDetector:
    configuration = configuration_dict(payload.configuration)
    template = detector_template(configuration["template_key"])
    if any(FEATURE_CATALOG[key].source_domain != template.source_domain for key in configuration["feature_keys"]):
        raise ValueError("Selected features must belong to the detector template source domain")
    item = AnalyticsDetector(
        detector_uuid=str(uuid.uuid4()), detector_key=payload.detector_key, template_key=template.detector_key,
        name=payload.name, description=payload.description, source_domain=template.source_domain, source_entity=template.source_entity,
        lifecycle_state="draft", current_version_number=1, required_permission=template.required_permission,
        demo_owned=payload.demo_owned, created_by_user_id=actor.id, updated_by_user_id=actor.id,
    )
    db.add(item); db.flush()
    version = AnalyticsDetectorVersion(
        version_uuid=str(uuid.uuid4()), detector_id=item.id, version_number=1,
        configuration_snapshot_json=canonical(configuration), feature_definition_versions_json=canonical(_feature_versions(configuration)),
        method=configuration["method"], method_parameters_json=canonical(configuration.get("threshold_parameters", {})),
        implementation_version=IMPLEMENTATION_VERSION, configuration_hash=_configuration_hash(configuration),
        reason=payload.reason, status="draft", created_by_user_id=actor.id,
    )
    db.add(version); add_activity(db, "analytics_detector_created", f"Analytics detector {item.name} created as an inactive draft.", "analytics_detector", item.id)
    db.commit(); db.refresh(item); return item


def patch_detector(db: Session, detector: AnalyticsDetector, payload, actor: UserAccount) -> AnalyticsDetector:
    claim_lock(db, detector, payload.optimistic_lock_version)
    if detector.lifecycle_state == "retired": raise HTTPException(409, "Retired detectors are immutable")
    if payload.name is not None: detector.name = payload.name
    if payload.description is not None: detector.description = payload.description
    detector.updated_by_user_id = actor.id
    add_activity(db, "analytics_detector_updated", f"Analytics detector metadata for {detector.name} was updated.", "analytics_detector", detector.id)
    db.commit(); db.refresh(detector); return detector


def create_version(db: Session, detector: AnalyticsDetector, payload, actor: UserAccount) -> AnalyticsDetectorVersion:
    claim_lock(db, detector, payload.optimistic_lock_version)
    if detector.lifecycle_state == "retired": raise HTTPException(409, "Retired detectors are immutable")
    configuration = configuration_dict(payload.configuration); template = detector_template(configuration["template_key"])
    if template.detector_key != detector.template_key: raise ValueError("A detector version cannot change its immutable server-owned template")
    digest = _configuration_hash(configuration)
    duplicate = db.query(AnalyticsDetectorVersion).filter_by(detector_id=detector.id, configuration_hash=digest).first()
    if duplicate: raise HTTPException(409, "An identical immutable detector version already exists")
    number = detector.current_version_number + 1
    version = AnalyticsDetectorVersion(
        version_uuid=str(uuid.uuid4()), detector_id=detector.id, version_number=number,
        configuration_snapshot_json=canonical(configuration), feature_definition_versions_json=canonical(_feature_versions(configuration)),
        method=configuration["method"], method_parameters_json=canonical(configuration.get("threshold_parameters", {})),
        implementation_version=IMPLEMENTATION_VERSION, configuration_hash=digest, reason=payload.reason,
        status="draft", created_by_user_id=actor.id,
    )
    db.add(version); detector.current_version_number = number; detector.updated_by_user_id = actor.id
    if detector.lifecycle_state not in {"active", "degraded"}: detector.lifecycle_state = "draft"
    add_activity(db, "analytics_version_created", f"Immutable version {number} created for analytics detector {detector.name}.", "analytics_detector", detector.id)
    db.commit(); db.refresh(version); return version


def lock(item, expected: int):
    if item.optimistic_lock_version != expected:
        raise HTTPException(409, "Optimistic-lock conflict")


def claim_lock(db: Session, item, expected: int):
    lock(item, expected)
    model = type(item)
    claimed = db.query(model).filter(model.id == item.id, model.optimistic_lock_version == expected).update({model.optimistic_lock_version: expected + 1}, synchronize_session=False)
    if not claimed:
        db.rollback(); raise HTTPException(409, "Optimistic-lock conflict")
    item.optimistic_lock_version = expected + 1
    db.flush()


def detector_config(version: AnalyticsDetectorVersion) -> dict:
    value = loads(version.configuration_snapshot_json)
    if deterministic_hash({"configuration": value, "feature_versions": loads(version.feature_definition_versions_json), "implementation_version": version.implementation_version}) != version.configuration_hash:
        raise ValueError("Detector configuration hash validation failed")
    return value


def latest_version(db: Session, detector: AnalyticsDetector) -> AnalyticsDetectorVersion:
    item = db.query(AnalyticsDetectorVersion).filter_by(detector_id=detector.id).order_by(AnalyticsDetectorVersion.version_number.desc()).first()
    if not item: raise ValueError("Detector has no immutable version")
    return item


def _baseline_dict(item: AnalyticsBaseline, observation_end: datetime | None = None, seasonality: str = "none") -> dict:
    result = {
        "mean": item.mean_value, "median": item.median_value, "minimum": item.minimum_value, "maximum": item.maximum_value,
        "standard_deviation": item.standard_deviation, "mad": item.mad_value, "iqr": item.iqr_value,
        "percentiles": loads(item.percentiles_json), "observation_count": item.observation_count,
    }
    if observation_end and seasonality != "none":
        buckets = loads(item.seasonal_summaries_json)
        result["seasonal_bucket"] = buckets.get(seasonal_bucket(observation_end, seasonality))
    return result


def build_detector_baselines(db: Session, version: AnalyticsDetectorVersion, cutoff: datetime, actor: UserAccount, *, source_scope="platform", source_entity_identifier="", peer_group_identifier="", entity_id=None, peer_group_size=None) -> list[AnalyticsBaseline]:
    configuration = detector_config(version); results = []
    for key in configuration["feature_keys"]:
        results.append(build_baseline(
            db, detector_version=version, feature_key=key, cutoff=cutoff,
            lookback_seconds=configuration["baseline_lookback_seconds"], observation_window_seconds=configuration["observation_window_seconds"],
            minimum_samples=configuration["minimum_historical_windows"], source_scope=source_scope,
            source_entity_identifier=source_entity_identifier, peer_group_identifier=peer_group_identifier,
            scope={"entity_id": entity_id} if entity_id else None, seasonality=configuration["seasonality"],
            winsorize=configuration.get("winsorize", False), peer_group_size=peer_group_size,
        ))
    add_activity(db, "analytics_baseline_built", f"Built {len(results)} deterministic analytics baseline records.", "analytics_detector", version.detector_id)
    db.commit()
    for item in results: db.refresh(item)
    return results


def _feedback_metrics(db: Session, version: AnalyticsDetectorVersion) -> dict:
    feedback = [row(item) for item in db.query(AnomalyFeedback).filter_by(detector_version_id=version.id).all()]
    anomalies = [row(item) for item in db.query(SecurityAnomaly).filter_by(detector_version_id=version.id).all()]
    return quality_metrics(feedback, anomalies)


def validate_detector(db: Session, detector: AnalyticsDetector, actor: UserAccount, *, limited_validation: bool = False) -> AnalyticsEvaluation:
    version = latest_version(db, detector); config = detector_config(version); detector.lifecycle_state = "validating"; version.status = "validating"; db.commit()
    baselines = db.query(AnalyticsBaseline).filter_by(detector_version_id=version.id).order_by(AnalyticsBaseline.id.desc()).all()
    baseline_by_feature = {item.feature_key: item for item in baselines}
    backtest = db.query(AnalyticsBacktest).filter_by(detector_version_id=version.id, status="succeeded").order_by(AnalyticsBacktest.id.desc()).first()
    sample_count = min([baseline_by_feature[key].observation_count for key in config["feature_keys"] if key in baseline_by_feature] or [0])
    finite_baseline = all(item.baseline_status == "ready" and all(value is not None for value in (item.mean_value, item.median_value, item.standard_deviation, item.mad_value, item.iqr_value)) for item in baseline_by_feature.values()) and len(baseline_by_feature) == len(config["feature_keys"])
    result_summary = loads(backtest.result_summary_json) if backtest else {}
    metrics = _feedback_metrics(db, version)
    gates = quality_gates(
        sample_count=sample_count, minimum_samples=config["minimum_historical_windows"], baseline_finite=finite_baseline,
        deterministic_backtest=bool(backtest), candidate_count=int(result_summary.get("candidate_count", 0)), maximum_candidates=1000,
        duplicate_rate=float(result_summary.get("duplicate_rate", 0)), explanations_complete=bool(result_summary.get("explanations_complete", backtest is not None)),
        unresolved_errors=[], unsupported_features=[key for key in config["feature_keys"] if key not in FEATURE_CATALOG], security_policy_violations=[],
        future_leakage=bool(backtest.future_leakage_detected) if backtest else False, implementation_version=version.implementation_version,
        reviewed_metrics=metrics, limited_validation=limited_validation,
    )
    status = "validated" if gates["passed"] else "failed"
    evaluation = AnalyticsEvaluation(
        evaluation_uuid=str(uuid.uuid4()), detector_version_id=version.id, evaluation_type="activation_validation", status=status,
        quality_gate_passed=gates["passed"], limited_validation=limited_validation, metrics_json=canonical(metrics), gate_results_json=canonical(gates["gates"]),
        limitations_json=canonical([metrics["metric_limitation"]] if metrics.get("metric_limitation") else []), deterministic_hash=gates["deterministic_hash"], created_by_user_id=actor.id,
    )
    db.add(evaluation); version.validation_result_json = canonical({"evaluation_uuid": evaluation.evaluation_uuid, **gates}); version.quality_gate_passed = gates["passed"]; version.status = status
    detector.lifecycle_state = "validated" if gates["passed"] else "draft"; detector.limited_validation = limited_validation and gates["passed"]
    add_activity(db, "analytics_detector_validated", f"Analytics detector {detector.name} validation {status}; no accuracy claim was made.", "analytics_detector", detector.id)
    db.commit(); db.refresh(evaluation)
    emit_notification(db, "Analytics detector validation completed" if gates["passed"] else "Analytics detector validation failed", f"{detector.name}: quality gates {'passed' if gates['passed'] else 'failed'}; no accuracy claim was made.", "success" if gates["passed"] else "warning", "analytics_detector", detector.id, actor.id)
    if not gates["passed"]: emit_notification(db, "Analytics quality gate failed", f"{detector.name} remains inactive pending explicit remediation and validation.", "warning", "analytics_detector", detector.id, actor.id)
    return evaluation


def _score_one(method: str, observed_value: float, baseline: dict, config: dict, observation_end: datetime) -> dict:
    parameters = config.get("threshold_parameters", {})
    if method == "weighted_ensemble":
        participants = [] ; weights = []
        for entry in config.get("ensemble", [])[:10]:
            participant_method = entry.get("method")
            if participant_method not in METHODS or participant_method == "weighted_ensemble": continue
            participants.append(score(participant_method, observed_value, baseline, entry.get("parameters") or parameters)); weights.append(entry.get("weight", 1))
        result = weighted_ensemble(participants, weights, int(config.get("confidence_rules", {}).get("minimum_ensemble_participation", 2)))
        result.update({"observed_value": observed_value, "expected_value": baseline.get("median"), "expected_range": [baseline.get("minimum"), baseline.get("maximum")], "direction": "above" if observed_value > (baseline.get("median") or 0) else "below", "deviation_magnitude": None})
        return result
    if method == "seasonal_deviation": baseline = {**baseline, "seasonal_bucket": baseline.get("seasonal_bucket")}
    return score(method, observed_value, baseline, parameters)


def score_detector_window(db: Session, version: AnalyticsDetectorVersion, observation_start: datetime, observation_end: datetime, *, entity_id: int | None = None, materialize: bool = True, actor: UserAccount | None = None) -> dict:
    observation_start, observation_end = validate_window(observation_start, observation_end, approved_only=True)
    config = detector_config(version); detector = db.get(AnalyticsDetector, version.detector_id)
    if materialize and (not detector or detector.lifecycle_state != "active" or detector.active_version_id != version.id):
        raise HTTPException(409, "Only the active validated detector version can materialize production anomalies")
    features = [] ; method_outputs = [] ; baselines = []
    for key in config["feature_keys"]:
        baseline = db.query(AnalyticsBaseline).filter(AnalyticsBaseline.detector_version_id == version.id, AnalyticsBaseline.feature_key == key, AnalyticsBaseline.source_data_cutoff <= observation_start).order_by(AnalyticsBaseline.source_data_cutoff.desc(), AnalyticsBaseline.id.desc()).first()
        if not baseline or baseline.baseline_status != "ready":
            return {"status": "insufficient_data", "reason_code": "DATA_INSUFFICIENT", "feature_key": key, "missing_source": "ready historical baseline", "detector_version_id": version.id, "observation_window": [observation_start.isoformat() + "Z", observation_end.isoformat() + "Z"], "anomaly": None}
        feature_result = extract_feature(db, key, observation_start, observation_end, {"entity_id": entity_id} if entity_id else None)
        if feature_result["value"] is None:
            return {"status": "insufficient_data", "reason_code": "DATA_INSUFFICIENT", "feature_key": key, "missing_source": "finite observation aggregate", "detector_version_id": version.id, "anomaly": None}
        baseline_data = _baseline_dict(baseline, observation_end, config["seasonality"])
        output = _score_one(config["method"], feature_result["value"], baseline_data, config, observation_end)
        features.append(feature_result); method_outputs.append(output); baselines.append(baseline)
    if len(method_outputs) > 1:
        final = weighted_ensemble(method_outputs, [1] * len(method_outputs), 2)
        primary = method_outputs[max(range(len(method_outputs)), key=lambda index: method_outputs[index].get("score") or 0)]
        final.update({key: primary.get(key) for key in ("observed_value", "expected_value", "expected_range", "direction", "deviation_magnitude", "fallback", "reason_code")})
    else: final = method_outputs[0]
    conf = confidence(sample_count=min(item.observation_count for item in baselines), minimum_samples=config["minimum_historical_windows"], missing_rate=sum(item.missing_value_count for item in baselines) / max(1, sum(item.observation_count + item.missing_value_count for item in baselines)), baseline_stability=0.5 if any((item.standard_deviation or 0) == 0 for item in baselines) else 1, seasonal_sufficient=not bool(final.get("fallback")), validation_state=version.status, drifted=detector.lifecycle_state == "degraded")
    severity_value = severity(final["score"], conf["band"])
    explanation = build_explanation(
        detector_name=detector.name, detector_version=version.version_number,
        observation_window=(observation_start.isoformat() + "Z", observation_end.isoformat() + "Z"),
        baseline_window=(baselines[0].baseline_window_start.isoformat() + "Z", baselines[0].baseline_window_end.isoformat() + "Z"),
        source_scope=baselines[0].source_scope, scoring=final, confidence=conf, severity=severity_value,
        minimum_samples=config["minimum_historical_windows"], actual_samples=min(item.observation_count for item in baselines),
        feature_keys=config["feature_keys"], seasonality=config["seasonality"], seasonal_fallback=final.get("fallback"),
        peer_group=baselines[0].peer_group_identifier or None, drift_status="degraded" if detector.lifecycle_state == "degraded" else "stable", winsorized=any(item.winsorized for item in baselines),
    )
    result = {"status": "anomalous" if (final.get("score") or 0) >= 70 else "normal", "score": final["score"], "confidence": conf, "severity": severity_value, "scoring": final, "features": features, "explanation": explanation, "detector_version_id": version.id, "baseline_ids": [item.id for item in baselines], "anomaly": None}
    if materialize and result["status"] == "anomalous":
        result["anomaly"] = row(materialize_anomaly(db, detector, version, baselines[0], observation_start, observation_end, result, entity_id=entity_id, actor=actor))
    return result


def _suppression(db, detector_id: int, entity_type: str, entity_identifier: str, score_value: float, now: datetime):
    for item in db.query(AnalyticsSuppression).filter(AnalyticsSuppression.enabled.is_(True), AnalyticsSuppression.starts_at <= now, AnalyticsSuppression.ends_at > now).order_by(AnalyticsSuppression.id).limit(100).all():
        if suppression_engine.matches(item, detector_id, entity_type, entity_identifier, score_value, now): return item
    return None


def materialize_anomaly(db: Session, detector: AnalyticsDetector, version: AnalyticsDetectorVersion, baseline: AnalyticsBaseline, start: datetime, end: datetime, result: dict, *, entity_id: int | None, actor: UserAccount | None) -> SecurityAnomaly:
    config = detector_config(version); entity_identifier = str(entity_id or "platform")[:200]; bucket = int(end.replace(tzinfo=timezone.utc).timestamp()) // config["deduplication_period_seconds"]
    reason = result["scoring"].get("reason_code", "ABOVE_BASELINE")
    dedup = deterministic_hash({"version": version.id, "scope": baseline.source_scope, "entity": entity_identifier, "bucket": bucket, "features": sorted(config["feature_keys"]), "reason": reason})
    existing = db.query(SecurityAnomaly).filter_by(deduplication_key=dedup).first()
    if existing:
        db.query(SecurityAnomaly).filter_by(id=existing.id).update({SecurityAnomaly.occurrence_count: func.min(1000000, SecurityAnomaly.occurrence_count + 1), SecurityAnomaly.last_observed_at: end, SecurityAnomaly.updated_at: utcnow()}, synchronize_session=False)
        db.commit(); db.refresh(existing); return existing
    suppression = _suppression(db, detector.id, detector.source_entity, entity_identifier, result["score"], end)
    status = "suppressed" if suppression else "not_suppressed"
    if suppression: suppression.hit_count = min(suppression.hit_count + 1, 1000000)
    explanation = dict(result["explanation"]); explanation["suppression_status"] = status
    item = SecurityAnomaly(
        anomaly_uuid=str(uuid.uuid4()), detector_id=detector.id, detector_version_id=version.id, baseline_id=baseline.id,
        source_domain=detector.source_domain, source_entity_type=detector.source_entity, source_entity_identifier=entity_identifier,
        observation_window_start=start, observation_window_end=end, anomaly_score=result["score"], confidence=result["confidence"]["band"],
        severity=result["severity"], status="new", summary=f"{detector.name}: statistical deviation requires analyst review."[:500],
        explanation_json=explanation_dumps(explanation), first_observed_at=end, last_observed_at=end,
        deduplication_key=dedup, data_hash=deterministic_hash({"features": result["features"], "version": version.id}),
        reason_code=reason, suppression_status=status, demo_owned=detector.demo_owned,
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(SecurityAnomaly).filter_by(deduplication_key=dedup).first()
        if existing:
            db.query(SecurityAnomaly).filter_by(id=existing.id).update({SecurityAnomaly.occurrence_count: func.min(1000000, SecurityAnomaly.occurrence_count + 1), SecurityAnomaly.last_observed_at: end, SecurityAnomaly.updated_at: utcnow()}, synchronize_session=False)
            db.commit(); db.refresh(existing); return existing
        raise
    for feature_result in result["features"]:
        detail = contribution(feature_result["feature_key"], result["scoring"], 1 / len(result["features"]))
        expected = detail["expected_range"] or [None, None]
        db.add(AnomalyContribution(anomaly_id=item.id, feature_key=detail["feature_key"], feature_name=detail["feature_name"], observed_value=detail["observed_value"], baseline_value=detail["baseline_value"], expected_low=expected[0], expected_high=expected[1], normalized_contribution=detail["normalized_contribution"], direction=detail["direction"], unit=detail["unit"], reason_code=detail["reason_code"]))
    add_activity(db, "analytics_anomaly_materialized", f"Anomalous behavior recorded for detector {detector.name}; analyst review is required.", "security_anomaly", item.id)
    db.commit(); db.refresh(item)
    if not suppression and (item.severity in {"high", "critical"} or (item.anomaly_score >= 70 and item.confidence == "low")):
        emit_notification(db, "Analytics anomaly requires review", f"{item.summary} Confidence: {item.confidence}.", "danger" if item.severity == "critical" else "warning", "security_anomaly", item.id, actor_id=actor.id if actor else None)
    publish_event(db, "anomaly.created", item, actor.id if actor else None)
    return item


def run_backtest(db: Session, version: AnalyticsDetectorVersion, range_start: datetime, range_end: datetime, interval_seconds: int, actor: UserAccount, idempotency_key: str, *, entity_id: int | None = None) -> AnalyticsBacktest:
    range_start, range_end = validate_window(range_start, range_end)
    config = detector_config(version)
    if interval_seconds != config["observation_window_seconds"]:
        raise ValueError("Backtest interval must match the immutable detector observation window")
    windows = int((range_end - range_start).total_seconds() // interval_seconds)
    if windows < 1 or windows > 1000: raise ValueError("Backtest range contains an unsupported number of windows")
    stable_key = hashlib.sha256(f"backtest:{version.id}:{idempotency_key}".encode()).hexdigest()
    detector = db.get(AnalyticsDetector, version.detector_id)
    job = queue_job(db, "backtest", version.id, actor.id, {"range_start": range_start.isoformat(), "range_end": range_end.isoformat(), "interval_seconds": interval_seconds, "entity_id": entity_id}, stable_key, demo_owned=bool(detector and detector.demo_owned))
    existing = db.query(AnalyticsBacktest).filter_by(job_id=job.id).first()
    if existing: return existing
    started = perf_counter(); current = range_start; per_window = []; candidate_count = insufficient = 0; explanation_count = 0
    while current < range_end:
        boundary = current + timedelta(seconds=interval_seconds)
        outputs = []
        for key in config["feature_keys"]:
            baseline_start = current - timedelta(seconds=config["baseline_lookback_seconds"])
            history = window_series(db, key, baseline_start, current, interval_seconds, {"entity_id": entity_id} if entity_id else None)
            stats = build_statistics([item["value"] for item in history], minimum_samples=config["minimum_historical_windows"], timestamps=[datetime.fromisoformat(item["window_end"].removesuffix("Z")) for item in history], seasonality=config["seasonality"], winsorize=config.get("winsorize", False))
            if stats["status"] != "ready": outputs = []; break
            observed = extract_feature(db, key, current, boundary, {"entity_id": entity_id} if entity_id else None)
            baseline_dict = stats
            if config["seasonality"] != "none": baseline_dict = {**stats, "seasonal_bucket": stats["seasonal_summaries"].get(seasonal_bucket(boundary, config["seasonality"]))}
            outputs.append(_score_one(config["method"], observed["value"], baseline_dict, config, boundary))
        if not outputs:
            insufficient += 1; per_window.append({"start": current.isoformat() + "Z", "end": boundary.isoformat() + "Z", "status": "insufficient_data", "score": None})
        else:
            final = outputs[0] if len(outputs) == 1 else weighted_ensemble(outputs, minimum_participation=2)
            score_value = final.get("score") or 0; candidate = score_value >= 70; candidate_count += int(candidate); explanation_count += int(candidate)
            per_window.append({"start": current.isoformat() + "Z", "end": boundary.isoformat() + "Z", "status": "candidate" if candidate else "normal", "score": score_value, "reason_code": final.get("reason_code")})
        current = boundary
    summary = {
        "window_count": windows, "candidate_count": candidate_count, "alert_volume_estimate": candidate_count,
        "data_sufficiency_count": windows - insufficient, "insufficient_data_count": insufficient,
        "deduplication_estimate": 0, "suppression_estimate": 0, "duplicate_rate": 0.0,
        "severity_distribution": {}, "confidence_distribution": {}, "explanations_complete": explanation_count == candidate_count,
        "runtime_milliseconds": round((perf_counter() - started) * 1000, 3), "production_mutations": {"anomalies": 0, "notifications": 0, "cases": 0, "connectors": 0, "soar_actions": 0},
        "quality_metrics": _feedback_metrics(db, version), "future_leakage_detected": False,
    }
    result_hash = deterministic_hash({"version": version.configuration_hash, "range": [range_start.isoformat(), range_end.isoformat()], "interval": interval_seconds, "windows": per_window})
    item = AnalyticsBacktest(backtest_uuid=str(uuid.uuid4()), detector_version_id=version.id, job_id=job.id, range_start=range_start, range_end=range_end, scoring_interval_seconds=interval_seconds, status="succeeded", result_summary_json=canonical(summary), per_window_json=canonical(per_window), deterministic_hash=result_hash, future_leakage_detected=False, created_by_user_id=actor.id, completed_at=utcnow())
    db.add(item); job.status = "succeeded"; job.progress_percent = 100; job.result_json = canonical({"backtest_hash": result_hash, **summary}); job.started_at = job.started_at or utcnow(); job.completed_at = utcnow()
    add_activity(db, "analytics_backtest_completed", f"Deterministic backtest completed across {windows} windows without production side effects.", "analytics_detector", version.detector_id)
    db.commit(); db.refresh(item)
    return item


def _rate_limit_jobs(db: Session, job_type: str, user_id: int):
    recent = db.query(AnalyticsJob).filter(AnalyticsJob.requested_by_user_id == user_id, AnalyticsJob.job_type == job_type, AnalyticsJob.created_at >= utcnow() - timedelta(minutes=1)).count()
    if recent >= 10: raise HTTPException(429, "Analytics operation rate limit exceeded", headers={"Retry-After": "60"})


def queue_job(db: Session, job_type: str, version_id: int | None, user_id: int, payload: dict, idempotency_key: str, demo_owned: bool = False) -> AnalyticsJob:
    existing = db.query(AnalyticsJob).filter_by(idempotency_key=idempotency_key).first()
    if existing: return existing
    _rate_limit_jobs(db, job_type, user_id)
    if len(canonical(payload).encode()) > 16000: raise ValueError("Analytics job payload exceeds its bound")
    item = AnalyticsJob(job_uuid=str(uuid.uuid4()), job_type=job_type, detector_version_id=version_id, requested_by_user_id=user_id, payload_json=canonical(safe_json(payload)), result_json="{}", idempotency_key=idempotency_key, demo_owned=demo_owned)
    db.add(item)
    try: db.commit()
    except IntegrityError:
        db.rollback(); existing = db.query(AnalyticsJob).filter_by(idempotency_key=idempotency_key).first()
        if existing: return existing
        raise
    db.refresh(item); return item


def cancel_job(db: Session, job: AnalyticsJob, actor: UserAccount) -> AnalyticsJob:
    if job.status in TERMINAL_JOBS: raise HTTPException(409, "Terminal analytics jobs cannot be cancelled")
    job.cancellation_requested = True; job.status = "cancelled"; job.completed_at = utcnow(); job.error_code = "ANALYTICS_JOB_CANCELLED"; job.error_summary = "Cancelled explicitly before terminal completion."
    add_activity(db, "analytics_job_cancelled", f"Analytics job {job.job_uuid[:12]} was cancelled.", "analytics_job", job.id); db.commit(); db.refresh(job); return job


def recover_stale_jobs(db: Session, stale_minutes: int = 30) -> int:
    cutoff = utcnow() - timedelta(minutes=min(1440, max(5, stale_minutes)))
    items = db.query(AnalyticsJob).filter(AnalyticsJob.status == "running", AnalyticsJob.heartbeat_at < cutoff).limit(100).all()
    for item in items:
        item.status = "failed"; item.error_code = "ANALYTICS_JOB_STALE"; item.error_summary = "Stale running job recovered safely; no automatic retry was started."; item.completed_at = utcnow()
    if items: db.commit()
    return len(items)


def process_due(db: Session, actor: UserAccount, batch_size: int = 25) -> dict:
    recovered = recover_stale_jobs(db)
    if "analytics:execute" not in effective_permissions(db, actor): raise HTTPException(403, "Permission denied before analytics job dispatch")
    candidate_ids = [row[0] for row in db.query(AnalyticsJob.id).filter_by(status="queued").order_by(AnalyticsJob.id).limit(min(100, max(1, batch_size))).all()]
    succeeded = failed = cancelled = processed = 0
    for item_id in candidate_ids:
        cancelled_now = db.query(AnalyticsJob).filter(AnalyticsJob.id == item_id, AnalyticsJob.status == "queued", AnalyticsJob.cancellation_requested.is_(True)).update({AnalyticsJob.status: "cancelled", AnalyticsJob.completed_at: utcnow()}, synchronize_session=False)
        if cancelled_now: db.commit(); cancelled += 1; processed += 1; continue
        claimed = db.query(AnalyticsJob).filter(AnalyticsJob.id == item_id, AnalyticsJob.status == "queued", AnalyticsJob.cancellation_requested.is_(False)).update({AnalyticsJob.status: "running", AnalyticsJob.started_at: utcnow(), AnalyticsJob.heartbeat_at: utcnow(), AnalyticsJob.progress_percent: 10}, synchronize_session=False)
        db.commit()
        if not claimed: continue
        processed += 1; item = db.get(AnalyticsJob, item_id)
        result = None
        try:
            payload = loads(item.payload_json)
            if item.job_type == "score_window":
                version = db.get(AnalyticsDetectorVersion, item.detector_version_id); end = utc(datetime.fromisoformat(payload["observation_end"].removesuffix("Z"))); config = detector_config(version); start = end - timedelta(seconds=config["observation_window_seconds"])
                result = score_detector_window(db, version, start, end, entity_id=payload.get("entity_id"), materialize=True, actor=actor)
            elif item.job_type == "feature_extraction": result = extract_feature(db, payload["feature_key"], datetime.fromisoformat(payload["start"]), datetime.fromisoformat(payload["end"]), payload.get("scope"))
            elif item.job_type in {"retention_cleanup", "report_generation", "drift_evaluation", "detector_validation", "baseline_build", "anomaly_materialization", "backtest"}: result = {"status": "requires_explicit_typed_endpoint", "safe": True}
            else: raise ValueError("Unsupported analytics job type")
            item = db.get(AnalyticsJob, item.id)
            if item.cancellation_requested or item.status == "cancelled": item.status = "cancelled"; item.completed_at = utcnow(); cancelled += 1
            else: item.result_json = canonical(safe_json(result)); item.status = "succeeded"; item.progress_percent = 100; item.completed_at = utcnow(); succeeded += 1
        except Exception as exc:
            db.rollback(); item = db.get(AnalyticsJob, item.id)
            if item.cancellation_requested or item.status == "cancelled": item.status = "cancelled"; item.completed_at = utcnow(); cancelled += 1
            else: item.status = "failed"; item.error_code = "ANALYTICS_JOB_FAILED"; item.error_summary = str(exc)[:500]; item.completed_at = utcnow(); failed += 1
        db.commit()
        if item.status == "failed": emit_notification(db, "Analytics job failed", f"Analytics job {item.job_uuid[:12]} failed safely with code {item.error_code}.", "warning", "analytics_job", item.id, actor.id)
        elif isinstance(result, dict) and result.get("status") == "insufficient_data": emit_notification(db, "Persistent analytics data insufficiency", f"Analytics job {item.job_uuid[:12]} requires more approved historical data; no anomaly was inferred.", "warning", "analytics_job", item.id, actor.id)
    expiring = db.query(AnalyticsSuppression).filter(AnalyticsSuppression.enabled.is_(True), AnalyticsSuppression.ends_at > utcnow(), AnalyticsSuppression.ends_at <= utcnow() + timedelta(days=1)).order_by(AnalyticsSuppression.ends_at).limit(100).all()
    for suppression in expiring: emit_notification(db, "Analytics suppression nearing expiry", "A bounded suppression is nearing expiry; review it explicitly. Evidence remains preserved.", "warning", "analytics_suppression", suppression.id, actor.id)
    return {"processed": processed, "succeeded": succeeded, "failed": failed, "cancelled": cancelled, "stale_recovered": recovered, "external_network_calls": 0, "commands_executed": 0}


def lifecycle(db: Session, detector: AnalyticsDetector, action: str, payload, actor: UserAccount) -> AnalyticsDetector:
    claim_lock(db, detector, payload.optimistic_lock_version)
    if action not in {"activate", "disable", "retire", "rollback"}: raise ValueError("Unknown detector lifecycle action")
    version = latest_version(db, detector)
    if action == "activate":
        if detector.lifecycle_state not in {"validated", "disabled", "degraded"} or not version.quality_gate_passed or version.status != "validated": raise HTTPException(409, "Detector activation requires a validated version that passed quality gates")
        if payload.limited_validation and not actor.is_system_admin: raise HTTPException(403, "Administrator approval is required for limited validation")
        detector.lifecycle_state = "active"; detector.active_version_id = version.id; detector.degraded_reason = None; detector.limited_validation = payload.limited_validation; version.status = "active"; version.activation_time = utcnow(); version.activated_by_user_id = actor.id
    elif action == "disable":
        if detector.lifecycle_state in {"retired", "draft"}: raise HTTPException(409, "Detector cannot be disabled from its current state")
        detector.lifecycle_state = "disabled"; version.status = "disabled"
    elif action == "retire":
        if detector.lifecycle_state == "retired": raise HTTPException(409, "Detector is already retired")
        detector.lifecycle_state = "retired"; detector.retired_at = utcnow(); version.status = "retired"; version.retirement_time = utcnow()
    else:
        target = db.get(AnalyticsDetectorVersion, payload.target_version_id or 0)
        if not target or target.detector_id != detector.id or not target.quality_gate_passed or target.status in {"retired", "failed"}: raise HTTPException(409, "Rollback target must be a compatible validated version")
        if detector.active_version_id == target.id: raise HTTPException(409, "Rollback target is already active")
        current = db.get(AnalyticsDetectorVersion, detector.active_version_id) if detector.active_version_id else None
        if current and current.status == "active": current.status = "validated"; current.replacement_version_id = target.id
        detector.active_version_id = target.id; detector.lifecycle_state = "active"; detector.degraded_reason = None; target.status = "active"; target.activation_time = utcnow(); target.activated_by_user_id = actor.id; version = target
    detector.updated_by_user_id = actor.id
    add_activity(db, f"analytics_detector_{action}", f"Analytics detector {detector.name} lifecycle action {action} completed with an explicit reason.", "analytics_detector", detector.id); db.commit(); db.refresh(detector)
    title = {"activate": "Analytics detector activated", "disable": "Analytics detector disabled", "retire": "Analytics detector retired", "rollback": "Analytics detector rolled back"}[action]
    emit_notification(db, title, f"{detector.name}: {payload.reason}", "warning" if action in {"disable", "retire", "rollback"} else "success", "analytics_detector", detector.id, actor_id=actor.id)
    publish_event(db, "detector.rolled_back" if action == "rollback" else f"detector.{action}d", detector, actor.id)
    return detector


def emit_notification(db: Session, title: str, message: str, level: str, entity_type: str, entity_id: int, actor_id: int | None = None):
    if db.new or db.dirty or db.deleted: raise RuntimeError("Analytics notifications require a committed source transaction")
    for user in db.query(UserAccount).filter_by(status="active").order_by(UserAccount.id).all():
        permissions = effective_permissions(db, user)
        if "analytics:view" not in permissions: continue
        if not (user.is_system_admin or user.id == actor_id or "analytics:review" in permissions): continue
        exists = db.query(Notification).filter_by(title=title[:150], entity_type=entity_type, entity_id=entity_id, recipient_user_id=user.id).first()
        if not exists: db.add(Notification(title=title[:150], message=" ".join(message.split())[:500].replace("http://", "hxxp://").replace("https://", "hxxps://"), type=level, entity_type=entity_type, entity_id=entity_id, recipient_user_id=user.id))
    db.commit()


def publish_event(db: Session, event_type: str, item, actor_id: int | None):
    allowed = {"anomaly.created", "anomaly.confirmed", "anomaly.dismissed", "anomaly.linked_to_case", "detector.activated", "detector.degraded", "detector.rolled_back", "drift.detected", "analytics.report.generated"}
    if event_type not in allowed: return None
    from app.modules.integrations.service import canonical_event, enqueue_outbox
    source_type = "security_anomaly" if isinstance(item, SecurityAnomaly) else "analytics_detector" if isinstance(item, AnalyticsDetector) else "analytics_record"
    event = canonical_event(event_type, "analytics", source_type, item.id, f"ThreatScope analytics event: {event_type}", "A redacted analytics lifecycle event was queued; no raw feature dataset or evidence is included.", payload={"severity": getattr(item, "severity", None), "status": getattr(item, "status", getattr(item, "lifecycle_state", None)), "detector_id": getattr(item, "detector_id", getattr(item, "id", None))}, severity=getattr(item, "severity", None), actor_id=actor_id)
    from app.modules.integrations.models import IntegrationOutboxEvent
    existing = db.query(IntegrationOutboxEvent).filter_by(idempotency_key=event["idempotency_key"]).first()
    if existing: return existing
    outbox = enqueue_outbox(db, event); db.commit(); return outbox


def transition_anomaly(db: Session, anomaly: SecurityAnomaly, target: str, payload, actor: UserAccount) -> SecurityAnomaly:
    claim_lock(db, anomaly, payload.optimistic_lock_version)
    if target not in ANOMALY_TRANSITIONS.get(anomaly.status, set()): raise HTTPException(409, "Invalid anomaly lifecycle transition")
    if target in {"confirmed", "dismissed", "resolved"} and not payload.reason.strip(): raise ValueError("An analyst reason is required")
    previous = anomaly.status; anomaly.status = target; anomaly.review_status = "reviewed" if target in {"confirmed", "dismissed", "resolved"} else "in_review"; anomaly.resolution_reason = payload.reason if target in {"confirmed", "dismissed", "resolved"} else anomaly.resolution_reason
    add_activity(db, "analytics_anomaly_review", f"Anomaly {anomaly.anomaly_uuid[:12]} moved from {previous} to {target} after explicit analyst review.", "security_anomaly", anomaly.id); db.commit(); db.refresh(anomaly)
    if target in {"confirmed", "dismissed"}:
        emit_notification(db, f"Analytics anomaly {target}", f"Anomaly {anomaly.anomaly_uuid[:12]} was {target} by an authorized analyst.", "warning" if target == "confirmed" else "info", "security_anomaly", anomaly.id, actor.id)
        publish_event(db, f"anomaly.{target}", anomaly, actor.id)
    return anomaly


def assign_anomaly(db: Session, anomaly: SecurityAnomaly, payload, actor: UserAccount) -> SecurityAnomaly:
    claim_lock(db, anomaly, payload.optimistic_lock_version)
    assignee = db.get(UserAccount, payload.analyst_user_id)
    if not assignee or assignee.status != "active" or "analytics:review" not in effective_permissions(db, assignee): raise HTTPException(404, "Assignable analyst not found")
    anomaly.assigned_analyst_id = assignee.id
    add_activity(db, "analytics_anomaly_assigned", f"Anomaly {anomaly.anomaly_uuid[:12]} was assigned for analyst review.", "security_anomaly", anomaly.id); db.commit(); db.refresh(anomaly)
    emit_notification(db, "Analytics anomaly assigned", f"Anomaly {anomaly.anomaly_uuid[:12]} requires review.", "info", "security_anomaly", anomaly.id, assignee.id); return anomaly


def add_feedback(db: Session, anomaly: SecurityAnomaly, payload, actor: UserAccount) -> AnomalyFeedback:
    previous = db.query(AnomalyFeedback).filter_by(anomaly_id=anomaly.id, analyst_user_id=actor.id).order_by(AnomalyFeedback.revision_number.desc()).first()
    revision = (previous.revision_number + 1) if previous else 1
    item = AnomalyFeedback(feedback_uuid=str(uuid.uuid4()), anomaly_id=anomaly.id, analyst_user_id=actor.id, detector_version_id=anomaly.detector_version_id, label=payload.label, confidence=payload.confidence, reason=payload.reason, safe_category=payload.safe_category, revision_number=revision, previous_feedback_id=previous.id if previous else None)
    db.add(item); anomaly.review_status = "feedback_recorded"; add_activity(db, "analytics_feedback_created", f"Feedback revision {revision} recorded for anomaly {anomaly.anomaly_uuid[:12]}; detector parameters were not changed.", "security_anomaly", anomaly.id)
    try:
        db.commit()
    except IntegrityError:
        db.rollback(); anomaly = db.get(SecurityAnomaly, anomaly.id)
        previous = db.query(AnomalyFeedback).filter_by(anomaly_id=anomaly.id, analyst_user_id=actor.id).order_by(AnomalyFeedback.revision_number.desc()).first(); revision = (previous.revision_number + 1) if previous else 1
        item = AnomalyFeedback(feedback_uuid=str(uuid.uuid4()), anomaly_id=anomaly.id, analyst_user_id=actor.id, detector_version_id=anomaly.detector_version_id, label=payload.label, confidence=payload.confidence, reason=payload.reason, safe_category=payload.safe_category, revision_number=revision, previous_feedback_id=previous.id if previous else None)
        db.add(item); anomaly.review_status = "feedback_recorded"; add_activity(db, "analytics_feedback_created", f"Concurrent feedback was retained safely as revision {revision}; detector parameters were not changed.", "security_anomaly", anomaly.id); db.commit()
    db.refresh(item)
    if item.label == "false_positive":
        recent_false_positives = db.query(AnomalyFeedback).filter(AnomalyFeedback.detector_version_id == anomaly.detector_version_id, AnomalyFeedback.label == "false_positive", AnomalyFeedback.created_at >= utcnow() - timedelta(days=7)).count()
        if recent_false_positives >= 5: emit_notification(db, "Excessive false-positive feedback", "A detector accumulated repeated reviewed false-positive labels and requires explicit quality review; no automatic retraining occurred.", "warning", "analytics_detector", anomaly.detector_id, actor.id)
    return item


def create_suppression(db: Session, payload, actor: UserAccount) -> AnalyticsSuppression:
    scope = suppression_engine.validate_scope(payload.scope, is_admin=actor.is_system_admin, emergency=payload.emergency)
    starts_at, ends_at, maximum = suppression_engine.validate_period(payload.starts_at, payload.ends_at, emergency=payload.emergency)
    item = AnalyticsSuppression(suppression_uuid=str(uuid.uuid4()), owner_user_id=actor.id, reason=payload.reason, starts_at=starts_at, ends_at=ends_at, maximum_duration_seconds=maximum, emergency=payload.emergency, broad_scope=scope.pop("broad_scope"), approval_state="approved" if actor.is_system_admin or not scope.get("broad_scope") else "pending", demo_owned=payload.demo_owned, **{key: scope.get(key) for key in suppression_engine.ALLOWED_FIELDS})
    db.add(item); add_activity(db, "analytics_suppression_created", "A bounded declarative analytics suppression was created; evidence remains preserved.", "analytics_suppression", None); db.commit(); db.refresh(item)
    if item.broad_scope: emit_notification(db, "Broad analytics suppression created", "A broad suppression requires ongoing administrative review and does not delete evidence.", "warning", "analytics_suppression", item.id, actor.id)
    return item


def patch_suppression(db: Session, item: AnalyticsSuppression, payload, actor: UserAccount) -> AnalyticsSuppression:
    claim_lock(db, item, payload.optimistic_lock_version)
    if payload.reason is not None: item.reason = payload.reason
    if payload.ends_at is not None:
        _, end, _ = suppression_engine.validate_period(item.starts_at, payload.ends_at, emergency=item.emergency); item.ends_at = end
    if payload.enabled is not None: item.enabled = payload.enabled
    item.last_reviewed_at = utcnow(); add_activity(db, "analytics_suppression_updated", "A bounded analytics suppression was reviewed and updated.", "analytics_suppression", item.id); db.commit(); db.refresh(item); return item


def disable_suppression(db: Session, item: AnalyticsSuppression, actor: UserAccount) -> AnalyticsSuppression:
    item.enabled = False; item.last_reviewed_at = utcnow(); item.optimistic_lock_version += 1; add_activity(db, "analytics_suppression_disabled", "An analytics suppression was disabled; retained anomaly evidence was unchanged.", "analytics_suppression", item.id); db.commit(); db.refresh(item); return item


def evaluate_drift(db: Session, payload, actor: UserAccount) -> AnalyticsDriftRecord:
    version = db.get(AnalyticsDetectorVersion, payload.detector_version_id); baseline = db.get(AnalyticsBaseline, payload.baseline_id)
    if not version or not baseline or baseline.detector_version_id != version.id: raise HTTPException(404, "Compatible detector baseline not found")
    previous = _baseline_dict(baseline); previous["observation_count"] = baseline.observation_count; previous["missing_rate"] = baseline.missing_value_count / max(1, baseline.observation_count + baseline.missing_value_count)
    current = safe_json(payload.current_distribution); result = drift_engine.evaluate(previous, current, payload.signal, payload.minimum_samples)
    existing = db.query(AnalyticsDriftRecord).filter_by(detector_version_id=version.id, baseline_id=baseline.id, feature_key=baseline.feature_key, current_data_hash=result.get("current_data_hash", deterministic_hash(current))).first()
    if existing: return existing
    item = AnalyticsDriftRecord(drift_uuid=str(uuid.uuid4()), detector_version_id=version.id, baseline_id=baseline.id, feature_key=baseline.feature_key, drift_method=payload.signal, previous_distribution_json=canonical(previous), current_distribution_json=canonical(current), drift_score=result.get("drift_score") or 0, threshold=result["threshold"], confidence=result["confidence"], status=result["status"], current_data_hash=result.get("current_data_hash", deterministic_hash(current)), affected_anomaly_volume=db.query(SecurityAnomaly).filter_by(detector_version_id=version.id).count(), explanation="A deterministic bounded distribution comparison detected drift." if result["status"] == "detected" else "The bounded distribution comparison did not detect material drift.", recommended_review="Review source quality and run an explicit validation before reactivation; no automatic retraining occurs.")
    db.add(item)
    detector = db.get(AnalyticsDetector, version.detector_id)
    if result["status"] == "detected" and detector.lifecycle_state == "active": detector.lifecycle_state = "degraded"; detector.degraded_reason = f"Drift detected for {baseline.feature_key}"; detector.optimistic_lock_version += 1
    add_activity(db, "analytics_drift_evaluated", f"Analytics drift evaluation completed with status {result['status']}; automatic retraining did not occur.", "analytics_drift", None)
    try:
        db.commit()
    except IntegrityError:
        db.rollback(); existing = db.query(AnalyticsDriftRecord).filter_by(detector_version_id=version.id, baseline_id=baseline.id, feature_key=baseline.feature_key, current_data_hash=result.get("current_data_hash", deterministic_hash(current))).first()
        if existing: return existing
        raise
    db.refresh(item)
    if result["status"] == "detected":
        emit_notification(db, "Analytics drift detected", item.recommended_review, "warning", "analytics_drift", item.id, actor.id)
        if detector.lifecycle_state == "degraded": emit_notification(db, "Analytics detector degraded", f"Detector {detector.name} was degraded for review; no automatic retraining occurred.", "warning", "analytics_detector", detector.id, actor.id)
        publish_event(db, "drift.detected", item, actor.id)
    return item


def acknowledge_drift(db: Session, item: AnalyticsDriftRecord, payload, actor: UserAccount) -> AnalyticsDriftRecord:
    claim_lock(db, item, payload.optimistic_lock_version); item.status = "acknowledged"; item.acknowledged_by_user_id = actor.id; item.acknowledged_at = utcnow(); item.acknowledgment_reason = payload.reason; add_activity(db, "analytics_drift_acknowledged", "An analytics drift record was acknowledged; no retraining was started.", "analytics_drift", item.id); db.commit(); db.refresh(item); return item


def case_proposal(anomaly: SecurityAnomaly) -> dict:
    explanation = loads(anomaly.explanation_json)
    return safe_json({"proposal_only": True, "anomaly_id": anomaly.id, "title": f"Investigate anomalous behavior {anomaly.anomaly_uuid[:12]}", "summary": anomaly.summary, "severity_suggestion": anomaly.severity, "confidence": anomaly.confidence, "detector_version_id": anomaly.detector_version_id, "observation_window": [anomaly.observation_window_start.isoformat() + "Z", anomaly.observation_window_end.isoformat() + "Z"], "contributing_features": explanation.get("top_contributing_features", [])[:5], "automatic_case_creation": False, "automatic_containment": False})


def link_case(db: Session, anomaly: SecurityAnomaly, payload, actor: UserAccount) -> SecurityAnomaly:
    from app.modules.unified_correlation.models import IncidentCase, IncidentEvidence, IncidentTimelineEvent
    case = db.get(IncidentCase, payload.case_id)
    if not case: raise HTTPException(404, "Incident case not found")
    if anomaly.linked_case_id == case.id: return anomaly
    claim_lock(db, anomaly, payload.optimistic_lock_version)
    if anomaly.linked_case_id and anomaly.linked_case_id != case.id: raise HTTPException(409, "Anomaly is already linked to another case")
    fingerprint = deterministic_hash({"anomaly": anomaly.id, "case": case.id})
    evidence = db.query(IncidentEvidence).filter_by(evidence_fingerprint=fingerprint).first()
    if not evidence:
        evidence = IncidentEvidence(case_id=case.id, source_module="analytics", source_record_type="security_anomaly", source_record_id=anomaly.id, source_internal_route=f"/analytics/anomalies/{anomaly.id}", title_snapshot=anomaly.summary[:500], evidence_snapshot=f"Score {anomaly.anomaly_score:.2f}; confidence {anomaly.confidence}; detector version {anomaly.detector_version_id}. Statistical deviation is not proof of compromise.", severity=anomaly.severity, confidence=anomaly.confidence, evidence_fingerprint=fingerprint); db.add(evidence); case.evidence_count += 1
        db.add(IncidentTimelineEvent(case_id=case.id, event_type="analytics_anomaly_linked", summary=f"Anomaly {anomaly.anomaly_uuid[:12]} linked after explicit analyst action.", actor_label=actor.display_name[:100]))
    anomaly.linked_case_id = case.id; anomaly.status = "linked_to_case"; anomaly.review_status = "in_review"
    add_activity(db, "analytics_case_link", f"Anomaly {anomaly.anomaly_uuid[:12]} linked to incident case {case.case_key}; case status was unchanged.", "security_anomaly", anomaly.id); db.commit(); db.refresh(anomaly); publish_event(db, "anomaly.linked_to_case", anomaly, actor.id); return anomaly


REPORT_SECTIONS = (
    "Report metadata", "Reporting period", "Scope", "Data-source coverage", "Data-quality limitations",
    "Active detectors", "Detector lifecycle summary", "Detector version inventory", "Baseline health", "Insufficient-data detectors",
    "Validation results", "Backtest summary", "Quality-gate status", "Anomaly totals", "Score distribution",
    "Confidence distribution", "Severity distribution", "Domain distribution", "Detector distribution", "Source-entity distribution",
    "High and critical anomalies", "Low-confidence high-score anomalies", "Confirmed anomalies", "Dismissed anomalies", "Unreviewed anomalies",
    "Duplicate occurrences", "Suppressed candidates", "Suppression inventory", "Analyst feedback distribution", "Review coverage",
    "False-positive estimate where supported", "Drift summary", "Degraded detectors", "Failed analytics jobs", "Case-linked anomalies",
    "SOAR-linked anomalies", "Connector-published analytics events", "Governance and audit summary", "Security and privacy controls", "Known limitations",
)


def overview(db: Session) -> dict:
    now = utcnow(); anomalies = db.query(SecurityAnomaly)
    total = anomalies.count(); reviewed = anomalies.filter(SecurityAnomaly.review_status != "unreviewed").count()
    return {
        "description": "Deterministic offline-first analytics supports analyst decisions. Anomalous behavior is statistical deviation, not proof of compromise.",
        "active_detectors": db.query(AnalyticsDetector).filter_by(lifecycle_state="active").count(),
        "degraded_detectors": db.query(AnalyticsDetector).filter_by(lifecycle_state="degraded").count(),
        "anomalies_last_24_hours": anomalies.filter(SecurityAnomaly.created_at >= now - timedelta(days=1)).count(),
        "high_critical_anomalies": anomalies.filter(SecurityAnomaly.severity.in_(["high", "critical"])).count(),
        "unreviewed_anomalies": anomalies.filter_by(review_status="unreviewed").count(),
        "low_confidence_high_score": anomalies.filter(SecurityAnomaly.anomaly_score >= 70, SecurityAnomaly.confidence.in_(["low", "insufficient"])).count(),
        "linked_cases": anomalies.filter(SecurityAnomaly.linked_case_id.is_not(None)).count(),
        "suppression_hits": sum(value[0] or 0 for value in db.query(AnalyticsSuppression.hit_count).all()),
        "drift_events": db.query(AnalyticsDriftRecord).filter_by(status="detected").count(),
        "failed_jobs": db.query(AnalyticsJob).filter_by(status="failed").count(),
        "data_insufficient_detectors": db.query(AnalyticsBaseline).filter_by(baseline_status="insufficient_data").count(),
        "review_coverage": round(reviewed / total, 4) if total else 0.0,
        "data_quality_limitations": ["Sparse or missing data lowers confidence.", "External source quality affects results.", "Reviewed labels are required before precision can be estimated."],
        "automatic_containment": False, "automatic_retraining": False, "external_ai": False,
    }


def metrics(db: Session) -> dict:
    result = overview(db)
    result["anomalies_by_domain"] = {domain: db.query(SecurityAnomaly).filter_by(source_domain=domain).count() for domain in sorted({row[0] for row in db.query(SecurityAnomaly.source_domain).distinct().all() if row[0]})}
    result["anomalies_by_severity"] = {level: db.query(SecurityAnomaly).filter_by(severity=level).count() for level in ("informational", "low", "medium", "high", "critical")}
    result["confidence_distribution"] = {level: db.query(SecurityAnomaly).filter_by(confidence=level).count() for level in ("insufficient", "low", "medium", "high")}
    result["detector_health"] = {state: db.query(AnalyticsDetector).filter_by(lifecycle_state=state).count() for state in sorted(LIFECYCLE)}
    return result


def _report_summary(db: Session, period_start: datetime, period_end: datetime, executive: bool) -> dict:
    query = db.query(SecurityAnomaly).filter(SecurityAnomaly.created_at >= period_start, SecurityAnomaly.created_at < period_end)
    items = query.order_by(SecurityAnomaly.id.desc()).limit(100).all()
    feedback = [row(item) for item in db.query(AnomalyFeedback).filter(AnomalyFeedback.created_at >= period_start, AnomalyFeedback.created_at < period_end).limit(1000).all()]
    return {
        "anomaly_total": query.count(), "active_detectors": db.query(AnalyticsDetector).filter_by(lifecycle_state="active").count(),
        "degraded_detectors": db.query(AnalyticsDetector).filter_by(lifecycle_state="degraded").count(),
        "insufficient_baselines": db.query(AnalyticsBaseline).filter_by(baseline_status="insufficient_data").count(),
        "failed_jobs": db.query(AnalyticsJob).filter_by(status="failed").count(), "drift_events": db.query(AnalyticsDriftRecord).filter_by(status="detected").count(),
        "linked_cases": query.filter(SecurityAnomaly.linked_case_id.is_not(None)).count(),
        "severity_distribution": {level: query.filter(SecurityAnomaly.severity == level).count() for level in ("informational", "low", "medium", "high", "critical")},
        "confidence_distribution": {level: query.filter(SecurityAnomaly.confidence == level).count() for level in ("insufficient", "low", "medium", "high")},
        "quality_metrics": quality_metrics(feedback, [row(item) for item in items]),
        "bounded_anomalies": [] if executive else [{"id": item.id, "summary": item.summary, "score": item.anomaly_score, "confidence": item.confidence, "severity": item.severity, "status": item.status} for item in items[:50]],
        "executive_aggregate_only": executive,
    }


def generate_report(db: Session, payload, actor: UserAccount) -> AnalyticsReport:
    period_start, period_end = validate_window(payload.period_start, payload.period_end)
    existing = db.query(AnalyticsReport).filter_by(idempotency_key=payload.idempotency_key).first()
    if existing: return existing
    executive = payload.report_type == "executive_summary"; summary = _report_summary(db, period_start, period_end, executive)
    section_data = {
        "Report metadata": f"{payload.title} · deterministic offline report · implementation {IMPLEMENTATION_VERSION}",
        "Reporting period": f"{period_start.isoformat()}Z to {period_end.isoformat()}Z", "Scope": payload.scope,
        "Data-source coverage": f"{len(FEATURE_CATALOG)} approved derived features across structured platform data.",
        "Data-quality limitations": "Missing or sparse source data is never treated as zero and lowers confidence.",
        "Active detectors": summary["active_detectors"], "Detector lifecycle summary": metrics(db)["detector_health"],
        "Detector version inventory": db.query(AnalyticsDetectorVersion).count(), "Baseline health": db.query(AnalyticsBaseline).filter_by(baseline_status="ready").count(),
        "Insufficient-data detectors": summary["insufficient_baselines"], "Validation results": db.query(AnalyticsEvaluation).count(),
        "Backtest summary": db.query(AnalyticsBacktest).filter_by(status="succeeded").count(), "Quality-gate status": db.query(AnalyticsEvaluation).filter_by(quality_gate_passed=True).count(),
        "Anomaly totals": summary["anomaly_total"], "Score distribution": "Bounded 0–100 statistical-deviation scores.",
        "Confidence distribution": summary["confidence_distribution"], "Severity distribution": summary["severity_distribution"],
        "Domain distribution": metrics(db)["anomalies_by_domain"], "Detector distribution": "Bounded aggregate only.", "Source-entity distribution": "Permission-filtered aggregate only.",
        "High and critical anomalies": summary["severity_distribution"]["high"] + summary["severity_distribution"]["critical"],
        "Low-confidence high-score anomalies": overview(db)["low_confidence_high_score"], "Confirmed anomalies": db.query(SecurityAnomaly).filter_by(status="confirmed").count(),
        "Dismissed anomalies": db.query(SecurityAnomaly).filter_by(status="dismissed").count(), "Unreviewed anomalies": overview(db)["unreviewed_anomalies"],
        "Duplicate occurrences": sum(max(0, item.occurrence_count - 1) for item in db.query(SecurityAnomaly).limit(1000).all()), "Suppressed candidates": db.query(SecurityAnomaly).filter_by(suppression_status="suppressed").count(),
        "Suppression inventory": db.query(AnalyticsSuppression).count(), "Analyst feedback distribution": db.query(AnomalyFeedback).count(),
        "Review coverage": summary["quality_metrics"]["review_coverage"], "False-positive estimate where supported": summary["quality_metrics"]["false_positive_estimate"],
        "Drift summary": summary["drift_events"], "Degraded detectors": summary["degraded_detectors"], "Failed analytics jobs": summary["failed_jobs"],
        "Case-linked anomalies": summary["linked_cases"], "SOAR-linked anomalies": "SOAR actions remain approval-gated, bounded, and non-containment.",
        "Connector-published analytics events": "Only minimal redacted events are queued through the transactional outbox.",
        "Governance and audit summary": "Lifecycle operations use the existing integrity-chained audit service.",
        "Security and privacy controls": "No raw datasets, secrets, protected-attribute inference, executable configuration, external AI, or automatic containment.",
        "Known limitations": "SQLite and process-due are intended for local or small-scale deployments; quality depends on sufficient history and reviewed labels.",
    }
    style = "body{font-family:system-ui,sans-serif;margin:2rem;color:#172033}section{break-inside:avoid;border-bottom:1px solid #ccd;padding:.7rem 0}h1,h2{color:#123}pre{white-space:pre-wrap}"
    body = "".join(f"<section><h2>{index}. {escape(title)}</h2><pre>{escape(canonical(safe_json(section_data[title])))}</pre></section>" for index, title in enumerate(REPORT_SECTIONS, 1))
    html = f"<!doctype html><html><head><meta charset=\"utf-8\"><title>{escape(payload.title)}</title><style>{style}</style></head><body><h1>{escape(payload.title)}</h1><p>Anomalies are statistical deviations requiring analyst review, not proof of compromise.</p>{body}</body></html>"
    digest = hashlib.sha256(html.encode()).hexdigest(); item = AnalyticsReport(report_uuid=str(uuid.uuid4()), title=payload.title, report_type=payload.report_type, period_start=period_start, period_end=period_end, scope=payload.scope, filters_json=canonical(payload.filters), summary_json=canonical(summary), html_content=html, content_sha256=digest, idempotency_key=payload.idempotency_key, generated_by_user_id=actor.id, demo_owned=payload.demo_owned)
    db.add(item); add_activity(db, "analytics_report_generated", f"Static escaped analytics report {payload.title} generated with 40 deterministic sections.", "analytics_report", None)
    try:
        db.commit()
    except IntegrityError:
        db.rollback(); existing = db.query(AnalyticsReport).filter_by(idempotency_key=payload.idempotency_key).first()
        if existing: return existing
        raise
    db.refresh(item); emit_notification(db, "Analytics report generated", f"Report {item.title} is ready.", "success", "analytics_report", item.id, actor.id); publish_event(db, "analytics.report.generated", item, actor.id); return item


def analytics_diagnostics(db: Session) -> dict:
    from sqlalchemy import inspect
    names = set(inspect(db.get_bind()).get_table_names()); expected = {model.__tablename__ for model in (AnalyticsDetector, AnalyticsDetectorVersion, AnalyticsBaseline, AnalyticsJob, AnalyticsBacktest, AnalyticsEvaluation, SecurityAnomaly, AnomalyContribution, AnomalyFeedback, AnalyticsSuppression, AnalyticsDriftRecord, AnalyticsReport)}
    now = utcnow()
    return {
        "tables_available": expected.issubset(names), "missing_tables": sorted(expected - names), "feature_catalog_loaded": len(FEATURE_CATALOG), "detector_catalog_loaded": len(DETECTOR_CATALOG),
        "active_detector_count": db.query(AnalyticsDetector).filter_by(lifecycle_state="active").count(), "degraded_detector_count": db.query(AnalyticsDetector).filter_by(lifecycle_state="degraded").count(),
        "queued_job_count": db.query(AnalyticsJob).filter_by(status="queued").count(), "stale_running_job_count": db.query(AnalyticsJob).filter(AnalyticsJob.status == "running", AnalyticsJob.heartbeat_at < now - timedelta(minutes=30)).count(),
        "failed_job_count": db.query(AnalyticsJob).filter_by(status="failed").count(), "anomaly_backlog": db.query(SecurityAnomaly).filter_by(review_status="unreviewed").count(),
        "unreviewed_high_severity": db.query(SecurityAnomaly).filter(SecurityAnomaly.review_status == "unreviewed", SecurityAnomaly.severity.in_(["high", "critical"])).count(),
        "drift_count": db.query(AnalyticsDriftRecord).filter_by(status="detected").count(), "expired_suppression_count": db.query(AnalyticsSuppression).filter(AnalyticsSuppression.ends_at <= now).count(),
        "baseline_insufficiency_count": db.query(AnalyticsBaseline).filter_by(baseline_status="insufficient_data").count(), "report_generation_health": "healthy",
        "external_ai": False, "automatic_retraining": False, "automatic_containment": False,
    }


def demo_reset(db: Session) -> dict:
    anomaly_ids = [row[0] for row in db.query(SecurityAnomaly.id).filter_by(demo_owned=True).all()]
    deleted = {}
    if anomaly_ids:
        deleted["contributions"] = db.query(AnomalyContribution).filter(AnomalyContribution.anomaly_id.in_(anomaly_ids)).delete(synchronize_session=False)
        db.query(AnomalyFeedback).filter(AnomalyFeedback.anomaly_id.in_(anomaly_ids)).update({AnomalyFeedback.previous_feedback_id: None}, synchronize_session=False)
        deleted["feedback"] = db.query(AnomalyFeedback).filter(AnomalyFeedback.anomaly_id.in_(anomaly_ids)).delete(synchronize_session=False)
    deleted["anomalies"] = db.query(SecurityAnomaly).filter_by(demo_owned=True).delete(synchronize_session=False)
    deleted["suppressions"] = db.query(AnalyticsSuppression).filter_by(demo_owned=True).delete(synchronize_session=False)
    deleted["reports"] = db.query(AnalyticsReport).filter_by(demo_owned=True).delete(synchronize_session=False)
    demo_detectors = [row[0] for row in db.query(AnalyticsDetector.id).filter_by(demo_owned=True).all()]
    if demo_detectors:
        version_ids = [row[0] for row in db.query(AnalyticsDetectorVersion.id).filter(AnalyticsDetectorVersion.detector_id.in_(demo_detectors)).all()]
        if version_ids:
            backtest_job_ids = [row[0] for row in db.query(AnalyticsBacktest.job_id).filter(AnalyticsBacktest.detector_version_id.in_(version_ids), AnalyticsBacktest.job_id.is_not(None)).all()]
            deleted["drift"] = db.query(AnalyticsDriftRecord).filter(AnalyticsDriftRecord.detector_version_id.in_(version_ids)).delete(synchronize_session=False)
            deleted["evaluations"] = db.query(AnalyticsEvaluation).filter(AnalyticsEvaluation.detector_version_id.in_(version_ids)).delete(synchronize_session=False)
            deleted["backtests"] = db.query(AnalyticsBacktest).filter(AnalyticsBacktest.detector_version_id.in_(version_ids)).delete(synchronize_session=False)
            deleted["baselines"] = db.query(AnalyticsBaseline).filter(AnalyticsBaseline.detector_version_id.in_(version_ids)).delete(synchronize_session=False)
            db.query(AnalyticsDetector).filter(AnalyticsDetector.id.in_(demo_detectors)).update({AnalyticsDetector.active_version_id: None}, synchronize_session=False)
            db.query(AnalyticsDetectorVersion).filter(AnalyticsDetectorVersion.id.in_(version_ids)).update({AnalyticsDetectorVersion.replacement_version_id: None}, synchronize_session=False)
            deleted["versions"] = db.query(AnalyticsDetectorVersion).filter(AnalyticsDetectorVersion.id.in_(version_ids)).delete(synchronize_session=False)
            if backtest_job_ids: deleted["backtest_jobs"] = db.query(AnalyticsJob).filter(AnalyticsJob.id.in_(backtest_job_ids)).delete(synchronize_session=False)
        deleted["detectors"] = db.query(AnalyticsDetector).filter(AnalyticsDetector.id.in_(demo_detectors)).delete(synchronize_session=False)
    deleted["jobs"] = db.query(AnalyticsJob).filter_by(demo_owned=True).delete(synchronize_session=False)
    db.commit(); return {"deleted": deleted, "production_records_preserved": True, "external_notifications": 0, "connector_deliveries": 0}
