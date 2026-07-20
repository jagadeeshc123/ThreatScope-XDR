from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AnalyticsDetector(Base):
    __tablename__ = "analytics_detectors"
    id = Column(Integer, primary_key=True)
    detector_uuid = Column(String(36), nullable=False, unique=True, index=True)
    detector_key = Column(String(120), nullable=False, unique=True, index=True)
    template_key = Column(String(120), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    source_domain = Column(String(80), nullable=False, index=True)
    source_entity = Column(String(80), nullable=False)
    lifecycle_state = Column(String(24), nullable=False, default="draft", index=True)
    degraded_reason = Column(String(1000))
    current_version_number = Column(Integer, nullable=False, default=1)
    active_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id", use_alter=True, name="fk_analytics_detector_active_version"))
    required_permission = Column(String(80), nullable=False, default="analytics:execute")
    limited_validation = Column(Boolean, nullable=False, default=False)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    updated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    retired_at = Column(DateTime)


class AnalyticsDetectorVersion(Base):
    __tablename__ = "analytics_detector_versions"
    __table_args__ = (
        UniqueConstraint("detector_id", "version_number", name="uq_analytics_detector_version"),
        UniqueConstraint("detector_id", "configuration_hash", name="uq_analytics_detector_config_hash"),
    )
    id = Column(Integer, primary_key=True)
    version_uuid = Column(String(36), nullable=False, unique=True)
    detector_id = Column(Integer, ForeignKey("analytics_detectors.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    configuration_snapshot_json = Column(Text, nullable=False)
    feature_definition_versions_json = Column(Text, nullable=False)
    method = Column(String(40), nullable=False)
    method_parameters_json = Column(Text, nullable=False)
    implementation_version = Column(String(40), nullable=False)
    configuration_hash = Column(String(64), nullable=False, index=True)
    reason = Column(String(1000), nullable=False)
    status = Column(String(24), nullable=False, default="draft", index=True)
    validation_result_json = Column(Text)
    quality_gate_passed = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    activated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_at = Column(DateTime, nullable=False, default=utcnow)
    activation_time = Column(DateTime)
    retirement_time = Column(DateTime)
    replacement_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"))


class AnalyticsBaseline(Base):
    __tablename__ = "analytics_baselines"
    __table_args__ = (
        UniqueConstraint("detector_version_id", "feature_key", "source_scope", "source_entity_identifier", "peer_group_identifier", "source_data_cutoff", "data_hash", name="uq_analytics_baseline_idempotency"),
        Index("ix_analytics_baseline_lookup", "detector_version_id", "feature_key", "source_data_cutoff"),
    )
    id = Column(Integer, primary_key=True)
    baseline_uuid = Column(String(36), nullable=False, unique=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False, index=True)
    feature_key = Column(String(120), nullable=False, index=True)
    source_scope = Column(String(120), nullable=False, default="platform")
    source_entity_identifier = Column(String(200), nullable=False, default="")
    peer_group_identifier = Column(String(120), nullable=False, default="")
    baseline_window_start = Column(DateTime, nullable=False)
    baseline_window_end = Column(DateTime, nullable=False)
    observation_count = Column(Integer, nullable=False)
    missing_value_count = Column(Integer, nullable=False, default=0)
    median_value = Column(Float)
    mean_value = Column(Float)
    minimum_value = Column(Float)
    maximum_value = Column(Float)
    standard_deviation = Column(Float)
    mad_value = Column(Float)
    iqr_value = Column(Float)
    percentiles_json = Column(Text, nullable=False, default="{}")
    seasonal_summaries_json = Column(Text, nullable=False, default="{}")
    original_summary_json = Column(Text, nullable=False, default="{}")
    winsorized = Column(Boolean, nullable=False, default=False)
    source_data_cutoff = Column(DateTime, nullable=False)
    data_hash = Column(String(64), nullable=False)
    baseline_status = Column(String(30), nullable=False, index=True)
    insufficiency_reason = Column(String(1000))
    implementation_version = Column(String(40), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AnalyticsJob(Base):
    __tablename__ = "analytics_jobs"
    id = Column(Integer, primary_key=True)
    job_uuid = Column(String(36), nullable=False, unique=True)
    job_type = Column(String(40), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="queued", index=True)
    idempotency_key = Column(String(160), nullable=False, unique=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), index=True)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    payload_json = Column(Text, nullable=False, default="{}")
    result_json = Column(Text, nullable=False, default="{}")
    progress_percent = Column(Integer, nullable=False, default=0)
    error_code = Column(String(80))
    error_summary = Column(String(1000))
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    started_at = Column(DateTime)
    heartbeat_at = Column(DateTime)
    completed_at = Column(DateTime)


class AnalyticsBacktest(Base):
    __tablename__ = "analytics_backtests"
    id = Column(Integer, primary_key=True)
    backtest_uuid = Column(String(36), nullable=False, unique=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analytics_jobs.id"), unique=True)
    range_start = Column(DateTime, nullable=False)
    range_end = Column(DateTime, nullable=False)
    scoring_interval_seconds = Column(Integer, nullable=False)
    status = Column(String(24), nullable=False, default="queued", index=True)
    result_summary_json = Column(Text, nullable=False, default="{}")
    per_window_json = Column(Text, nullable=False, default="[]")
    deterministic_hash = Column(String(64), nullable=False)
    future_leakage_detected = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)


class AnalyticsEvaluation(Base):
    __tablename__ = "analytics_evaluations"
    id = Column(Integer, primary_key=True)
    evaluation_uuid = Column(String(36), nullable=False, unique=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False, index=True)
    evaluation_type = Column(String(40), nullable=False)
    status = Column(String(24), nullable=False, index=True)
    quality_gate_passed = Column(Boolean, nullable=False, default=False)
    limited_validation = Column(Boolean, nullable=False, default=False)
    metrics_json = Column(Text, nullable=False, default="{}")
    gate_results_json = Column(Text, nullable=False, default="[]")
    limitations_json = Column(Text, nullable=False, default="[]")
    deterministic_hash = Column(String(64), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SecurityAnomaly(Base):
    __tablename__ = "security_anomalies"
    __table_args__ = (
        UniqueConstraint("deduplication_key", name="uq_security_anomaly_deduplication"),
        Index("ix_security_anomaly_queue", "status", "severity", "anomaly_score"),
    )
    id = Column(Integer, primary_key=True)
    anomaly_uuid = Column(String(36), nullable=False, unique=True)
    detector_id = Column(Integer, ForeignKey("analytics_detectors.id"), nullable=False, index=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False, index=True)
    baseline_id = Column(Integer, ForeignKey("analytics_baselines.id"))
    source_domain = Column(String(80), nullable=False, index=True)
    source_entity_type = Column(String(80), nullable=False, index=True)
    source_entity_identifier = Column(String(200), nullable=False, default="")
    observation_window_start = Column(DateTime, nullable=False)
    observation_window_end = Column(DateTime, nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False, index=True)
    confidence = Column(String(20), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="new", index=True)
    summary = Column(String(500), nullable=False)
    explanation_json = Column(Text, nullable=False)
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_observed_at = Column(DateTime, nullable=False)
    last_observed_at = Column(DateTime, nullable=False)
    deduplication_key = Column(String(64), nullable=False)
    data_hash = Column(String(64), nullable=False)
    reason_code = Column(String(80), nullable=False)
    assigned_analyst_id = Column(Integer, ForeignKey("user_accounts.id"), index=True)
    linked_case_id = Column(Integer, ForeignKey("incident_cases.id"), index=True)
    suppression_status = Column(String(24), nullable=False, default="not_suppressed")
    review_status = Column(String(24), nullable=False, default="unreviewed")
    resolution_reason = Column(String(2000))
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class AnomalyContribution(Base):
    __tablename__ = "anomaly_contributions"
    __table_args__ = (UniqueConstraint("anomaly_id", "feature_key", name="uq_anomaly_contribution_feature"),)
    id = Column(Integer, primary_key=True)
    anomaly_id = Column(Integer, ForeignKey("security_anomalies.id", ondelete="CASCADE"), nullable=False, index=True)
    feature_key = Column(String(120), nullable=False)
    feature_name = Column(String(200), nullable=False)
    observed_value = Column(Float, nullable=False)
    baseline_value = Column(Float)
    expected_low = Column(Float)
    expected_high = Column(Float)
    normalized_contribution = Column(Float, nullable=False)
    direction = Column(String(20), nullable=False)
    unit = Column(String(40), nullable=False)
    reason_code = Column(String(80), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AnomalyFeedback(Base):
    __tablename__ = "anomaly_feedback"
    __table_args__ = (UniqueConstraint("anomaly_id", "analyst_user_id", "revision_number", name="uq_anomaly_feedback_revision"),)
    id = Column(Integer, primary_key=True)
    feedback_uuid = Column(String(36), nullable=False, unique=True)
    anomaly_id = Column(Integer, ForeignKey("security_anomalies.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False, index=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False)
    label = Column(String(40), nullable=False, index=True)
    confidence = Column(String(20), nullable=False)
    reason = Column(String(2000), nullable=False)
    safe_category = Column(String(80))
    revision_number = Column(Integer, nullable=False, default=1)
    previous_feedback_id = Column(Integer, ForeignKey("anomaly_feedback.id"))
    created_at = Column(DateTime, nullable=False, default=utcnow)


class AnalyticsSuppression(Base):
    __tablename__ = "analytics_suppressions"
    id = Column(Integer, primary_key=True)
    suppression_uuid = Column(String(36), nullable=False, unique=True)
    detector_id = Column(Integer, ForeignKey("analytics_detectors.id"), index=True)
    source_entity_type = Column(String(80))
    source_entity_identifier = Column(String(200))
    approved_tag = Column(String(80))
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"))
    asset_id = Column(Integer, ForeignKey("vm_assets.id"))
    api_endpoint_id = Column(Integer, ForeignKey("api_endpoints.id"))
    alert_source = Column(String(100))
    minimum_score = Column(Float)
    maximum_score = Column(Float)
    owner_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    reason = Column(String(2000), nullable=False)
    approval_state = Column(String(24), nullable=False, default="approved")
    broad_scope = Column(Boolean, nullable=False, default=False)
    emergency = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    starts_at = Column(DateTime, nullable=False)
    ends_at = Column(DateTime, nullable=False, index=True)
    maximum_duration_seconds = Column(Integer, nullable=False)
    hit_count = Column(Integer, nullable=False, default=0)
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    last_reviewed_at = Column(DateTime, nullable=False, default=utcnow)


class AnalyticsDriftRecord(Base):
    __tablename__ = "analytics_drift_records"
    __table_args__ = (UniqueConstraint("detector_version_id", "baseline_id", "feature_key", "current_data_hash", name="uq_analytics_drift_idempotency"),)
    id = Column(Integer, primary_key=True)
    drift_uuid = Column(String(36), nullable=False, unique=True)
    detector_version_id = Column(Integer, ForeignKey("analytics_detector_versions.id"), nullable=False, index=True)
    baseline_id = Column(Integer, ForeignKey("analytics_baselines.id"), nullable=False)
    feature_key = Column(String(120), nullable=False, index=True)
    drift_method = Column(String(40), nullable=False)
    previous_distribution_json = Column(Text, nullable=False)
    current_distribution_json = Column(Text, nullable=False)
    drift_score = Column(Float, nullable=False)
    threshold = Column(Float, nullable=False)
    confidence = Column(String(20), nullable=False)
    status = Column(String(24), nullable=False, index=True)
    current_data_hash = Column(String(64), nullable=False)
    affected_anomaly_volume = Column(Integer, nullable=False, default=0)
    explanation = Column(String(2000), nullable=False)
    recommended_review = Column(String(1000), nullable=False)
    acknowledged_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    acknowledged_at = Column(DateTime)
    acknowledgment_reason = Column(String(1000))
    linked_evaluation_id = Column(Integer, ForeignKey("analytics_evaluations.id"))
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    detected_at = Column(DateTime, nullable=False, default=utcnow)


class AnalyticsReport(Base):
    __tablename__ = "analytics_reports"
    id = Column(Integer, primary_key=True)
    report_uuid = Column(String(36), nullable=False, unique=True)
    title = Column(String(200), nullable=False)
    report_type = Column(String(60), nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    scope = Column(String(120), nullable=False, default="platform")
    filters_json = Column(Text, nullable=False, default="{}")
    summary_json = Column(Text, nullable=False, default="{}")
    html_content = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    idempotency_key = Column(String(160), nullable=False, unique=True)
    generated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
