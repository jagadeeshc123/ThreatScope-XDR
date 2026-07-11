from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


SourceType = Literal["simulator", "jsonl", "csv", "access_log", "auth_log", "key_value"]
ParserType = Literal["jsonl", "csv", "access_log", "auth_log", "key_value", "simulator"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Outcome = Literal["success", "failure", "denied", "blocked", "unknown"]
EventType = Literal["authentication", "authorization", "web_request", "api_request", "administrative_action", "security_control", "system", "unknown"]
AlertStatus = Literal["open", "investigating", "contained", "resolved", "false_positive"]
IndicatorType = Literal["ip", "domain", "username"]


class SourceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: SourceType
    parser_type: ParserType
    enabled: bool = True


class SourceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: Optional[SourceType] = None
    parser_type: Optional[ParserType] = None
    enabled: Optional[bool] = None


class SourceRead(SourceCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    event_count: int
    last_ingested_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class ImportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source_id: int
    filename: Optional[str]
    file_hash: Optional[str]
    total_lines: int
    accepted_events: int
    rejected_events: int
    status: Literal["pending", "processing", "completed", "failed"]
    error_summary: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]


class EventRead(BaseModel):
    id: int
    source_id: int
    import_id: Optional[int]
    event_time: datetime
    received_at: datetime
    event_type: EventType
    action: Optional[str]
    outcome: Optional[Outcome]
    severity: Severity
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    http_method: Optional[str]
    request_path: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    message: Optional[str]
    normalized_json: Dict[str, Any]
    raw_event_hash: str
    raw_preview_redacted: Optional[str]
    created_at: datetime


class EventPage(BaseModel):
    items: List[EventRead]
    total: int
    page: int
    page_size: int


APPROVED_GROUP_BY = {"source_ip", "username", "event_type", "outcome", "status_code", "source_id"}


class RuleCreate(BaseModel):
    rule_code: str = Field(..., min_length=3, max_length=40, pattern=r"^[A-Z0-9_-]+$")
    name: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=3, max_length=4000)
    rule_type: str = Field(..., min_length=3, max_length=80, pattern=r"^[a-z0-9_]+$")
    enabled: bool = True
    severity: Severity
    confidence: Confidence
    window_seconds: int = Field(..., ge=10, le=86400)
    threshold: int = Field(..., gt=0, le=10000)
    group_by: str
    conditions_json: Dict[str, Any] = Field(default_factory=dict)
    remediation: str = Field(..., min_length=3, max_length=4000)

    @field_validator("group_by")
    @classmethod
    def approved_group(cls, value: str):
        if value not in APPROVED_GROUP_BY:
            raise ValueError("group_by is not approved")
        return value

    @field_validator("conditions_json")
    @classmethod
    def safe_conditions(cls, value: Dict[str, Any]):
        allowed = {"event_types", "outcomes", "status_codes", "path_contains", "distinct_field", "blocklist_match"}
        if set(value) - allowed:
            raise ValueError("Unsupported condition key")
        if len(str(value)) > 8000:
            raise ValueError("Conditions are too large")
        return value


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, min_length=3, max_length=4000)
    enabled: Optional[bool] = None
    severity: Optional[Severity] = None
    confidence: Optional[Confidence] = None
    window_seconds: Optional[int] = Field(default=None, ge=10, le=86400)
    threshold: Optional[int] = Field(default=None, gt=0, le=10000)
    group_by: Optional[str] = None
    conditions_json: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = Field(default=None, min_length=3, max_length=4000)

    @field_validator("group_by")
    @classmethod
    def approved_group(cls, value: Optional[str]):
        if value is not None and value not in APPROVED_GROUP_BY:
            raise ValueError("group_by is not approved")
        return value

    @field_validator("conditions_json")
    @classmethod
    def safe_conditions(cls, value: Optional[Dict[str, Any]]):
        if value is None:
            return value
        allowed = {"event_types", "outcomes", "status_codes", "path_contains", "distinct_field", "blocklist_match"}
        if set(value) - allowed or len(str(value)) > 8000:
            raise ValueError("Unsupported or oversized condition structure")
        return value


class RuleRead(BaseModel):
    id: int
    rule_code: str
    name: str
    description: str
    rule_type: str
    enabled: bool
    severity: Severity
    confidence: Confidence
    window_seconds: int
    threshold: int
    group_by: str
    conditions_json: Dict[str, Any]
    remediation: str
    is_default: bool
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    analyst_notes: Optional[str] = Field(default=None, max_length=8000)


class AlertRead(BaseModel):
    id: int
    rule_id: int
    rule_code: str
    rule_name: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    event_count: int
    correlation_key: str
    source_ip: Optional[str]
    username: Optional[str]
    evidence_summary: str
    fingerprint: str
    analyst_notes: Optional[str]
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertRead):
    events: List[EventRead]
    enrichments: List[Dict[str, Any]]
    blocklist_entries: List[Dict[str, Any]]


class AlertPage(BaseModel):
    items: List[AlertRead]
    total: int
    page: int
    page_size: int


class DetectionRunRequest(BaseModel):
    rule_ids: Optional[List[int]] = None
    source_id: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class DetectionRunResult(BaseModel):
    rules_processed: int
    events_processed: int
    alerts_created: int
    alerts_updated: int
    duplicate_alerts_skipped: int
    disclaimer: str


Scenario = Literal["normal_activity", "single_source_brute_force", "distributed_password_spray", "repeated_401_403", "suspicious_admin_access", "path_probing", "blocked_indicator_activity", "mixed_demo"]


class SimulatorRequest(BaseModel):
    scenario: Scenario
    number_of_events: int = Field(..., ge=1, le=10000)
    seed: int = Field(default=42, ge=0, le=2_147_483_647)
    start_time: Optional[datetime] = None
    source_id: Optional[int] = None


class SimulatorResult(BaseModel):
    events_created: int
    events_skipped_as_duplicates: int
    source_id: int
    start_time: datetime
    end_time: datetime
    disclaimer: str


class EnrichmentRequest(BaseModel):
    alert_id: Optional[int] = None
    indicator_type: IndicatorType
    indicator_value: str = Field(..., min_length=1, max_length=500)


class EnrichmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    alert_id: Optional[int]
    indicator_type: IndicatorType
    indicator_value: str
    reputation: Literal["unknown", "benign", "suspicious", "malicious"]
    confidence: Confidence
    tags_json: List[str]
    source_name: str
    explanation: str
    created_at: datetime
    disclaimer: str = "This enrichment uses local demonstration intelligence and is not live reputation data."


class BlocklistCreate(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str = Field(..., min_length=1, max_length=500)
    reason: str = Field(..., min_length=3, max_length=2000)
    source_alert_id: Optional[int] = None
    expires_at: Optional[datetime] = None


class BlocklistUpdate(BaseModel):
    reason: Optional[str] = Field(default=None, min_length=3, max_length=2000)
    status: Optional[Literal["active", "expired", "removed"]] = None
    expires_at: Optional[datetime] = None


class BlocklistRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    indicator_type: IndicatorType
    indicator_value: str
    reason: str
    source_alert_id: Optional[int]
    status: Literal["active", "expired", "removed"]
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    disclaimer: str = "Local simulation only — this does not modify any real firewall or network control."


class ReportCreate(BaseModel):
    report_type: str = Field(default="soc_summary", pattern=r"^[a-z0-9_]+$")


class ReportRead(BaseModel):
    id: int
    title: str
    report_type: str
    html_content: str
    summary_json: Dict[str, Any]
    created_at: datetime


class ActivityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    action: str
    message: str
    entity_type: str
    entity_id: Optional[int]
    created_at: datetime


class Overview(BaseModel):
    total_events: int
    events_last_24_hours: int
    open_alerts: int
    high_alerts: int
    critical_alerts: int
    total_sources: int
    enabled_sources: int
    active_rules: int
    active_blocklist_entries: int
    events_by_type: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    alerts_by_status: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    top_usernames: List[Dict[str, Any]]
    recent_alerts: List[AlertRead]
    recent_imports: List[ImportRead]
    recent_activity: List[ActivityRead]
