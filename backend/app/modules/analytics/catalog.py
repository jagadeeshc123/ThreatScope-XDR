from dataclasses import asdict, dataclass

from . import IMPLEMENTATION_VERSION


WINDOWS = (900, 3600, 21600, 86400, 604800, 2592000)
METHODS = (
    "static_threshold", "z_score", "robust_z_score", "iqr_deviation", "percentile_deviation",
    "ewma_deviation", "rate_of_change", "consecutive_failures", "seasonal_deviation", "weighted_ensemble",
)
SEASONALITIES = ("none", "hour_of_day", "day_of_week", "weekday_weekend", "fixed_utc_bucket", "source_periodic_bucket")
PEER_GROUP_KEYS = ("application_module", "connector_type", "asset_category", "alert_source", "api_classification", "severity_category", "assigned_team", "system_role_category")
REASON_CODES = (
    "ABOVE_BASELINE", "BELOW_BASELINE", "RATE_SPIKE", "FAILURE_BURST", "SEASONAL_DEVIATION",
    "PEER_GROUP_DEVIATION", "RAPID_GROWTH", "CONSECUTIVE_FAILURES", "DISTRIBUTION_SHIFT",
    "VOLUME_SURGE", "LATENCY_DEVIATION", "BACKLOG_GROWTH", "SLA_OVERDUE_GROWTH",
    "REPLAY_ATTEMPT_SURGE", "SIGNATURE_FAILURE_SURGE", "CIRCUIT_OPENED", "DATA_INSUFFICIENT",
    "BASELINE_UNSTABLE", "DATA_STALE", "DETECTOR_DRIFTED",
)


@dataclass(frozen=True)
class FeatureDefinition:
    feature_key: str
    display_name: str
    source_domain: str
    source_entity: str
    value_type: str
    aggregation_type: str
    supported_window_sizes: tuple[int, ...]
    minimum_sample_requirement: int
    missing_value_policy: str
    unit: str
    sensitivity_classification: str
    allowed_detector_methods: tuple[str, ...]
    explanation_wording: str
    peer_group_allowed: bool
    seasonal_baseline_allowed: bool
    maximum_retained_precision: int
    implementation_version: str = IMPLEMENTATION_VERSION

    def public(self) -> dict:
        value = asdict(self)
        value["key"] = self.feature_key
        return value


def _feature(key: str, name: str, domain: str, entity: str, aggregation: str = "count", unit: str = "events", *, minimum: int = 5, peer: bool = False, seasonal: bool = True, methods: tuple[str, ...] = METHODS) -> FeatureDefinition:
    return FeatureDefinition(key, name, domain, entity, "finite_number", aggregation, WINDOWS, minimum, "explicit_missing", unit, "derived_operational_aggregate", methods, f"{name} compared with its approved historical behavior baseline.", peer, seasonal, 6)


FEATURE_CATALOG: dict[str, FeatureDefinition] = {
    item.feature_key: item for item in (
        _feature("auth.failure_count", "Authentication failures", "authentication", "security_audit_event"),
        _feature("auth.success_count", "Successful authentications", "authentication", "security_audit_event"),
        _feature("auth.access_denial_count", "Access-control denials", "authentication", "security_audit_event"),
        _feature("auth.permission_change_count", "Permission changes", "authentication", "security_audit_event"),
        _feature("auth.role_assignment_count", "Role assignments", "authentication", "security_audit_event"),
        _feature("auth.mfa_failure_count", "MFA failures", "authentication", "security_audit_event"),
        _feature("auth.session_creation_count", "Sessions created", "authentication", "auth_session"),
        _feature("auth.session_invalidation_count", "Sessions invalidated", "authentication", "auth_session"),
        _feature("web.finding_count", "Web exposure findings", "web_exposure", "finding", peer=True),
        _feature("api.endpoint_count", "API endpoints", "api_security", "api_endpoint", peer=True),
        _feature("api.finding_count", "API findings", "api_security", "api_finding", peer=True),
        _feature("api.high_severity_finding_count", "High-severity API findings", "api_security", "api_finding", peer=True),
        _feature("soc.alert_count", "SOC alerts", "soc_monitor", "soc_alert", peer=True),
        _feature("soc.high_severity_alert_count", "High-severity SOC alerts", "soc_monitor", "soc_alert", peer=True),
        _feature("document.finding_count", "Document threat findings", "document_threats", "document_finding"),
        _feature("document.analysis_failure_count", "Document analysis failures", "document_threats", "document_analysis"),
        _feature("phishing.finding_count", "Phishing findings", "phishing_defense", "phishing_finding"),
        _feature("case.creation_count", "Incident cases created", "cases", "incident_case", peer=True),
        _feature("threat_intel.match_count", "Threat-intelligence matches", "threat_intelligence", "indicator_match"),
        _feature("threat_intel.stale_indicator_count", "Stale threat indicators", "threat_intelligence", "threat_indicator"),
        _feature("detections.match_count", "Detection rule matches", "detection_engineering", "detection_match", peer=True),
        _feature("detections.execution_failure_count", "Detection execution failures", "detection_engineering", "detection_execution"),
        _feature("vulnerability.new_count", "New vulnerabilities", "vulnerability_management", "vulnerability", peer=True),
        _feature("vulnerability.critical_count", "Critical vulnerabilities", "vulnerability_management", "vulnerability", peer=True),
        _feature("vulnerability.remediation_backlog_count", "Remediation backlog", "vulnerability_management", "remediation_task", peer=True),
        _feature("vulnerability.overdue_count", "Overdue remediation items", "vulnerability_management", "vulnerability", peer=True),
        _feature("soar.execution_failure_count", "SOAR execution failures", "soar", "soar_execution"),
        _feature("soar.approval_rejection_count", "SOAR approval rejections", "soar", "soar_approval"),
        _feature("integration.delivery_failure_count", "Connector delivery failures", "integrations", "connector_delivery", peer=True),
        _feature("integration.delivery_latency_ms", "Connector delivery latency", "integrations", "connector_delivery", "mean", "milliseconds", peer=True),
        _feature("integration.retry_count", "Connector delivery retries", "integrations", "connector_delivery", peer=True),
        _feature("integration.circuit_open_count", "Connector circuit-open events", "integrations", "connector"),
        _feature("integration.dead_letter_count", "Connector dead letters", "integrations", "connector_dead_letter", peer=True),
        _feature("integration.signature_failure_count", "Inbound signature failures", "integrations", "connector_inbound_event"),
        _feature("integration.replay_attempt_count", "Inbound replay attempts", "integrations", "connector_inbound_event"),
        _feature("integration.health_degradation_count", "Connector health degradations", "integrations", "connector_health_check", peer=True),
        _feature("operations.diagnostic_failure_count", "Diagnostic failures", "platform_operations", "operational_job"),
        _feature("operations.backup_failure_count", "Backup failures", "platform_operations", "backup_record"),
        _feature("operations.restore_failure_count", "Restore validation failures", "platform_operations", "restore_record"),
        _feature("operations.report_failure_count", "Report generation failures", "platform_operations", "operational_job"),
        _feature("audit.integrity_warning_count", "Audit-integrity warnings", "platform_operations", "security_audit_event"),
        _feature("platform.rate_limit_count", "Rate-limit events", "platform_operations", "security_audit_event"),
    )
}


@dataclass(frozen=True)
class DetectorTemplate:
    detector_key: str
    name: str
    description: str
    source_domain: str
    source_entity: str
    selected_feature_keys: tuple[str, ...]
    approved_method: str
    observation_window: int
    baseline_window: int
    minimum_samples: int
    seasonality: str
    threshold_parameters: dict
    severity_mapping: dict
    confidence_rules: dict
    cooldown_seconds: int
    deduplication_period_seconds: int
    maximum_late_arrival_seconds: int
    scoring_frequency_seconds: int
    suppression_compatible: bool
    quality_gates: tuple[str, ...]
    default_enabled: bool
    required_permission: str
    supported_scope: tuple[str, ...]
    implementation_version: str
    lifecycle_state: str
    available: bool
    unavailable_reason: str | None

    def public(self) -> dict:
        value = asdict(self)
        value["template_key"] = self.detector_key
        value["display_name"] = self.name
        return value


def _template(key: str, name: str, domain: str, entity: str, feature: str | None, method: str = "robust_z_score") -> DetectorTemplate:
    available = feature in FEATURE_CATALOG
    return DetectorTemplate(
        key, name, f"Detects a bounded statistical deviation in {name.lower()}; it is evidence for analyst review, not proof of compromise.",
        domain, entity, (feature,) if available and feature else (), method, 3600, 2592000, 5, "none",
        {"threshold": 3.0, "direction": "above", "winsorize": False},
        {"informational": 25, "low": 40, "medium": 55, "high": 70, "critical": 85},
        {"minimum_high_samples": 20, "maximum_missing_rate": 0.2}, 3600, 3600, 900, 3600, True,
        ("sufficient_history", "finite_baseline", "deterministic_backtest", "bounded_volume", "explanations", "no_future_leakage"),
        False, "analytics:execute", ("platform", "entity", "approved_peer_group"), IMPLEMENTATION_VERSION,
        "draft" if available else "disabled", available, None if available else "No approved structured source feature is available in this repository.",
    )


_TEMPLATE_ROWS = (
    ("authentication_failure_burst", "Authentication failure burst", "authentication", "security_audit_event", "auth.failure_count", "consecutive_failures"),
    ("successful_login_after_failures", "Successful login after repeated failures", "authentication", "security_audit_event", None, "weighted_ensemble"),
    ("unusual_login_hour", "Unusual login-hour deviation", "authentication", "security_audit_event", "auth.success_count", "seasonal_deviation"),
    ("session_creation_spike", "Session creation spike", "authentication", "auth_session", "auth.session_creation_count", "z_score"),
    ("session_invalidation_spike", "Session invalidation spike", "authentication", "auth_session", "auth.session_invalidation_count", "z_score"),
    ("access_denial_burst", "Access-denial burst", "authentication", "security_audit_event", "auth.access_denial_count", "consecutive_failures"),
    ("permission_change_burst", "Permission-change burst", "authentication", "security_audit_event", "auth.permission_change_count", "rate_of_change"),
    ("role_assignment_spike", "Role-assignment spike", "authentication", "security_audit_event", "auth.role_assignment_count", "z_score"),
    ("mfa_failure_spike", "MFA failure spike", "authentication", "security_audit_event", "auth.mfa_failure_count", "robust_z_score"),
    ("account_lockout_spike", "Account-lockout spike", "authentication", "user_account", None, "z_score"),
    ("web_finding_surge", "Web-exposure finding surge", "web_exposure", "finding", "web.finding_count", "robust_z_score"),
    ("api_finding_surge", "API finding surge", "api_security", "api_finding", "api.finding_count", "robust_z_score"),
    ("api_high_severity_increase", "API high-severity finding increase", "api_security", "api_finding", "api.high_severity_finding_count", "rate_of_change"),
    ("endpoint_inventory_growth", "Endpoint inventory growth anomaly", "api_security", "api_endpoint", "api.endpoint_count", "rate_of_change"),
    ("api_authorization_failure_increase", "API authorization failure increase", "api_security", "authorization_review", None, "rate_of_change"),
    ("api_validation_failure_increase", "API validation failure increase", "api_security", "api_assessment", None, "rate_of_change"),
    ("unsafe_configuration_pattern", "Repeated unsafe-configuration pattern", "api_security", "api_finding", None, "consecutive_failures"),
    ("endpoint_risk_increase", "Unusual endpoint risk-score increase", "api_security", "api_endpoint", None, "rate_of_change"),
    ("alert_volume_spike", "Alert volume spike", "soc_monitor", "soc_alert", "soc.alert_count", "z_score"),
    ("high_severity_alert_spike", "High-severity alert spike", "soc_monitor", "soc_alert", "soc.high_severity_alert_count", "robust_z_score"),
    ("alert_source_failure", "Alert-source failure", "soc_monitor", "soc_log_source", None, "consecutive_failures"),
    ("rule_match_spike", "Rule-match spike", "detection_engineering", "detection_match", "detections.match_count", "z_score"),
    ("detection_rule_error_spike", "Detection-rule error spike", "detection_engineering", "detection_execution", "detections.execution_failure_count", "consecutive_failures"),
    ("false_positive_feedback_surge", "False-positive feedback surge", "analytics", "anomaly_feedback", None, "rate_of_change"),
    ("alert_case_conversion_deviation", "Alert-to-case conversion deviation", "cases", "incident_case", None, "percentile_deviation"),
    ("phishing_finding_cluster", "Phishing finding cluster", "phishing_defense", "phishing_finding", "phishing.finding_count", "robust_z_score"),
    ("sender_domain_pattern", "Repeated sender/domain pattern", "phishing_defense", "phishing_indicator", None, "consecutive_failures"),
    ("attachment_type_spike", "Suspicious attachment-type spike", "phishing_defense", "phishing_attachment", None, "z_score"),
    ("document_threat_score_increase", "Document threat-score increase", "document_threats", "document_analysis", None, "rate_of_change"),
    ("document_analysis_failure_spike", "Document analysis failure spike", "document_threats", "document_analysis", "document.analysis_failure_count", "consecutive_failures"),
    ("ioc_match_volume_spike", "IOC match-volume spike", "threat_intelligence", "indicator_match", "threat_intel.match_count", "robust_z_score"),
    ("ioc_source_concentration", "Repeated IOC source concentration", "threat_intelligence", "indicator_match", None, "percentile_deviation"),
    ("stale_intelligence_growth", "Stale intelligence growth", "threat_intelligence", "threat_indicator", "threat_intel.stale_indicator_count", "rate_of_change"),
    ("confidence_distribution_shift", "Confidence-distribution shift", "threat_intelligence", "threat_indicator", None, "percentile_deviation"),
    ("intelligence_ingestion_failure", "Ingestion failure increase", "threat_intelligence", "threat_intel_import", None, "consecutive_failures"),
    ("new_vulnerability_spike", "Newly discovered vulnerability spike", "vulnerability_management", "vulnerability", "vulnerability.new_count", "robust_z_score"),
    ("critical_vulnerability_growth", "Critical vulnerability growth", "vulnerability_management", "vulnerability", "vulnerability.critical_count", "rate_of_change"),
    ("remediation_backlog_growth", "Remediation backlog growth", "vulnerability_management", "remediation_task", "vulnerability.remediation_backlog_count", "rate_of_change"),
    ("overdue_remediation_increase", "Overdue remediation increase", "vulnerability_management", "vulnerability", "vulnerability.overdue_count", "rate_of_change"),
    ("vulnerability_reopen_rate", "Reopen-rate increase", "vulnerability_management", "vulnerability", None, "rate_of_change"),
    ("asset_risk_growth", "Asset risk-growth anomaly", "vulnerability_management", "asset", None, "rate_of_change"),
    ("scanner_import_failure", "Scanner/import failure increase", "vulnerability_management", "ingestion_run", None, "consecutive_failures"),
    ("playbook_failure_spike", "Playbook execution failure spike", "soar", "soar_execution", "soar.execution_failure_count", "consecutive_failures"),
    ("approval_rejection_spike", "Approval rejection spike", "soar", "soar_approval", "soar.approval_rejection_count", "robust_z_score"),
    ("action_timeout_spike", "Action timeout spike", "soar", "soar_step_execution", None, "consecutive_failures"),
    ("soar_dead_letter_spike", "Dead-letter creation spike", "integrations", "connector_dead_letter", "integration.dead_letter_count", "z_score"),
    ("simulation_failure_repeat", "Repeated simulation failure", "soar", "soar_execution", "soar.execution_failure_count", "consecutive_failures"),
    ("queue_depth_increase", "Unusual queue-depth increase", "soar", "soar_execution", None, "rate_of_change"),
    ("connector_failure_spike", "Connector delivery failure spike", "integrations", "connector_delivery", "integration.delivery_failure_count", "robust_z_score"),
    ("connector_latency_deviation", "Connector latency deviation", "integrations", "connector_delivery", "integration.delivery_latency_ms", "iqr_deviation"),
    ("retry_volume_spike", "Retry-volume spike", "integrations", "connector_delivery", "integration.retry_count", "z_score"),
    ("circuit_open_event", "Circuit-open event", "integrations", "connector", "integration.circuit_open_count", "static_threshold"),
    ("dead_letter_growth", "Dead-letter growth", "integrations", "connector_dead_letter", "integration.dead_letter_count", "rate_of_change"),
    ("signature_failure_spike", "Inbound signature-failure spike", "integrations", "connector_inbound_event", "integration.signature_failure_count", "consecutive_failures"),
    ("replay_attempt_spike", "Inbound replay-attempt spike", "integrations", "connector_inbound_event", "integration.replay_attempt_count", "consecutive_failures"),
    ("taxii_sync_failure", "TAXII synchronization failure", "integrations", "connector_sync_cursor", None, "consecutive_failures"),
    ("connector_health_degradation", "Connector health degradation", "integrations", "connector_health_check", "integration.health_degradation_count", "robust_z_score"),
    ("ticket_sync_conflict", "External-ticket synchronization conflict", "integrations", "connector_delivery", None, "consecutive_failures"),
    ("diagnostic_failure_increase", "Diagnostic failure increase", "platform_operations", "operational_job", "operations.diagnostic_failure_count", "robust_z_score"),
    ("backup_failure_pattern", "Backup failure pattern", "platform_operations", "backup_record", "operations.backup_failure_count", "consecutive_failures"),
    ("restore_validation_failure", "Restore validation failure", "platform_operations", "restore_record", "operations.restore_failure_count", "consecutive_failures"),
    ("audit_integrity_warning", "Audit-integrity warning", "platform_operations", "security_audit_event", "audit.integrity_warning_count", "static_threshold"),
    ("rate_limit_event_repeat", "Repeated rate-limit event", "platform_operations", "security_audit_event", "platform.rate_limit_count", "consecutive_failures"),
    ("report_failure_spike", "Report-generation failure spike", "platform_operations", "operational_job", "operations.report_failure_count", "consecutive_failures"),
)

DETECTOR_CATALOG = {row[0]: _template(*row) for row in _TEMPLATE_ROWS}


def feature(key: str) -> FeatureDefinition:
    try:
        return FEATURE_CATALOG[key]
    except KeyError as exc:
        raise ValueError("Unknown server-owned feature key") from exc


def detector_template(key: str) -> DetectorTemplate:
    try:
        return DETECTOR_CATALOG[key]
    except KeyError as exc:
        raise ValueError("Unknown server-owned detector template") from exc


def method_catalog() -> list[dict]:
    descriptions = {
        "static_threshold": "Compares the observation with an immutable threshold.",
        "z_score": "Measures standard deviations from the historical mean.",
        "robust_z_score": "Measures deviation from the median using median absolute deviation.",
        "iqr_deviation": "Measures distance beyond the historical interquartile range.",
        "percentile_deviation": "Compares the observation with bounded historical percentiles.",
        "ewma_deviation": "Compares the observation with a deterministic exponentially weighted mean.",
        "rate_of_change": "Measures bounded change from the previous observation window.",
        "consecutive_failures": "Scores a bounded consecutive-failure run.",
        "seasonal_deviation": "Compares with an approved UTC seasonal bucket and reports fallback.",
        "weighted_ensemble": "Combines at least two approved finite method outputs with normalized bounded weights.",
    }
    return [{"method": key, "key": key, "display_name": key.replace("_", " ").title(), "description": descriptions[key], "server_owned": True, "deterministic": True, "score_range": [0, 100]} for key in METHODS]
