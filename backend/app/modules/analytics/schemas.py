from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .catalog import FEATURE_CATALOG, METHODS, PEER_GROUP_KEYS, SEASONALITIES, WINDOWS, detector_template


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DetectorConfiguration(StrictModel):
    template_key: str = Field(min_length=1, max_length=120)
    feature_keys: list[str] = Field(min_length=1, max_length=10)
    method: str
    observation_window_seconds: int
    baseline_lookback_seconds: int = Field(ge=3600, le=366 * 86400)
    minimum_historical_windows: int = Field(ge=2, le=1000)
    seasonality: str = "none"
    threshold_parameters: dict[str, Any] = Field(default_factory=dict)
    severity_mapping: dict[str, int] = Field(default_factory=lambda: {"informational": 25, "low": 40, "medium": 55, "high": 70, "critical": 85})
    confidence_rules: dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=3600, ge=0, le=30 * 86400)
    deduplication_period_seconds: int = Field(default=3600, ge=900, le=30 * 86400)
    maximum_late_arrival_seconds: int = Field(default=900, ge=0, le=86400)
    scoring_frequency_seconds: int = Field(default=3600)
    source_scope: Literal["platform", "entity", "approved_peer_group"] = "platform"
    peer_group_key: str | None = None
    winsorize: bool = False
    ensemble: list[dict[str, Any]] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def server_owned(self):
        template = detector_template(self.template_key)
        if not template.available: raise ValueError(template.unavailable_reason or "Detector template is unavailable")
        if self.method not in METHODS: raise ValueError("Unknown server-owned detector method")
        if self.observation_window_seconds not in WINDOWS or self.scoring_frequency_seconds not in WINDOWS:
            raise ValueError("Observation and scoring windows must be server-approved")
        if self.baseline_lookback_seconds < self.observation_window_seconds * self.minimum_historical_windows:
            raise ValueError("Baseline lookback cannot satisfy the minimum historical windows")
        if self.seasonality not in SEASONALITIES: raise ValueError("Unknown server-owned seasonality")
        if self.peer_group_key is not None and self.peer_group_key not in PEER_GROUP_KEYS: raise ValueError("Unknown server-owned peer group")
        if self.source_scope == "approved_peer_group" and not self.peer_group_key: raise ValueError("Approved peer-group scope requires a peer-group key")
        if len(set(self.feature_keys)) != len(self.feature_keys): raise ValueError("Duplicate feature keys are prohibited")
        for key in self.feature_keys:
            definition = FEATURE_CATALOG.get(key)
            if not definition: raise ValueError("Unknown server-owned feature key")
            if self.method not in definition.allowed_detector_methods: raise ValueError("Selected method is not approved for a feature")
            if self.observation_window_seconds not in definition.supported_window_sizes: raise ValueError("Feature does not support the selected window")
            if self.seasonality != "none" and not definition.seasonal_baseline_allowed: raise ValueError("Feature does not support seasonality")
            if self.source_scope == "approved_peer_group" and not definition.peer_group_allowed: raise ValueError("Feature does not support peer grouping")
        if self.method == "weighted_ensemble" and len(self.ensemble) < 2: raise ValueError("Weighted ensembles require at least two approved participants")
        if len(str(self.threshold_parameters)) > 4000 or len(str(self.confidence_rules)) > 4000 or len(str(self.severity_mapping)) > 2000: raise ValueError("Detector configuration exceeds its bound")
        if set(self.threshold_parameters) - {"threshold", "value", "threshold_value", "direction", "multiplier", "low_percentile", "high_percentile", "distance_threshold", "change_threshold", "count_threshold", "alpha"}: raise ValueError("Unknown threshold parameter")
        return self


class DetectorCreate(StrictModel):
    detector_key: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,119}$")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    configuration: DetectorConfiguration
    reason: str = Field(min_length=3, max_length=1000)
    demo_owned: bool = False


class DetectorPatch(StrictModel):
    optimistic_lock_version: int = Field(ge=1)
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, min_length=1, max_length=2000)


class VersionCreate(StrictModel):
    configuration: DetectorConfiguration
    reason: str = Field(min_length=3, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)


class LifecycleAction(StrictModel):
    optimistic_lock_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=1000)
    limited_validation: bool = False
    target_version_id: int | None = Field(None, ge=1)


class BaselineBuild(StrictModel):
    detector_version_id: int = Field(ge=1)
    cutoff: datetime
    source_scope: str = Field(default="platform", max_length=120)
    source_entity_identifier: str = Field(default="", max_length=200)
    peer_group_identifier: str = Field(default="", max_length=120)
    entity_id: int | None = Field(None, ge=1)
    peer_group_size: int | None = Field(None, ge=0, le=10000)
    idempotency_key: str = Field(min_length=8, max_length=160)


class BacktestCreate(StrictModel):
    detector_version_id: int = Field(ge=1)
    range_start: datetime
    range_end: datetime
    scoring_interval_seconds: int
    entity_id: int | None = Field(None, ge=1)
    idempotency_key: str = Field(min_length=8, max_length=160)

    @field_validator("scoring_interval_seconds")
    @classmethod
    def approved_interval(cls, value: int):
        if value not in WINDOWS: raise ValueError("Scoring interval is not server-approved")
        return value


class JobCreate(StrictModel):
    job_type: Literal["feature_extraction", "baseline_build", "detector_validation", "backtest", "score_window", "anomaly_materialization", "drift_evaluation", "report_generation", "retention_cleanup"]
    detector_version_id: int | None = Field(None, ge=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=160)
    demo_owned: bool = False

    @field_validator("payload")
    @classmethod
    def bounded_payload(cls, value):
        if len(str(value)) > 16000: raise ValueError("Job payload exceeds its server bound")
        return value


class ProcessDue(StrictModel):
    batch_size: int = Field(default=25, ge=1, le=100)


class ReasonAction(StrictModel):
    reason: str = Field(min_length=3, max_length=2000)
    optimistic_lock_version: int = Field(ge=1)


class AssignAction(StrictModel):
    analyst_user_id: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)


class LinkCaseAction(StrictModel):
    case_id: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)
    idempotency_key: str = Field(min_length=8, max_length=160)


class FeedbackCreate(StrictModel):
    label: Literal["confirmed_true_positive", "likely_true_positive", "uncertain", "benign_expected_behavior", "false_positive", "duplicate", "insufficient_context"]
    confidence: Literal["low", "medium", "high"]
    reason: str = Field(min_length=3, max_length=2000)
    safe_category: str | None = Field(None, max_length=80)


class SuppressionCreate(StrictModel):
    scope: dict[str, Any]
    reason: str = Field(min_length=3, max_length=2000)
    starts_at: datetime
    ends_at: datetime
    emergency: bool = False
    demo_owned: bool = False


class SuppressionPatch(StrictModel):
    optimistic_lock_version: int = Field(ge=1)
    reason: str | None = Field(None, min_length=3, max_length=2000)
    ends_at: datetime | None = None
    enabled: bool | None = None


class DriftEvaluate(StrictModel):
    detector_version_id: int = Field(ge=1)
    baseline_id: int = Field(ge=1)
    signal: Literal["mean_shift", "median_shift", "variance_change", "mad_change", "percentile_shift", "missing_data_increase", "cardinality_increase", "anomaly_volume_change", "score_distribution_change", "confidence_distribution_change", "false_positive_change", "freshness_degradation", "schema_version_change"] = "mean_shift"
    current_distribution: dict[str, Any]
    minimum_samples: int = Field(default=10, ge=5, le=10000)


class DriftAcknowledge(StrictModel):
    reason: str = Field(min_length=3, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)


class ReportCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    report_type: Literal["analytics_summary", "executive_summary"] = "analytics_summary"
    period_start: datetime
    period_end: datetime
    scope: str = Field(default="platform", max_length=120)
    filters: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=160)
    demo_owned: bool = False

    @field_validator("filters")
    @classmethod
    def safe_filters(cls, value):
        if set(value) - {"detector_id", "source_domain", "severity", "confidence", "status"}: raise ValueError("Unknown report filter")
        if len(str(value)) > 4000: raise ValueError("Report filters exceed their bound")
        return value
