from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ConnectorCreate(StrictModel):
    connector_type: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(None, max_length=2000)
    configuration: dict[str, Any] = Field(default_factory=dict)
    payload_profile: Literal["minimal", "standard", "extended"] = "minimal"
    timeout_seconds: int | None = Field(None, ge=1, le=60)
    retry_limit: int | None = Field(None, ge=0, le=7)
    owner_user_id: int | None = None
    demo_owned: bool = False


class ConnectorUpdate(StrictModel):
    optimistic_lock_version: int = Field(ge=1)
    name: str | None = Field(None, min_length=1, max_length=160)
    description: str | None = Field(None, max_length=2000)
    configuration: dict[str, Any] | None = None
    payload_profile: Literal["minimal", "standard", "extended"] | None = None
    timeout_seconds: int | None = Field(None, ge=1, le=60)
    retry_limit: int | None = Field(None, ge=0, le=7)
    owner_user_id: int | None = None


class LockAction(StrictModel):
    optimistic_lock_version: int = Field(ge=1)
    reason: str | None = Field(None, max_length=1000)
    confirmation: str | None = Field(None, max_length=100)


class CredentialWrite(StrictModel):
    credential_type: str = Field(min_length=1, max_length=40)
    secret: dict[str, Any]
    confirmation: str | None = Field(None, max_length=100)


class NetworkPolicyUpdate(StrictModel):
    network_scope: Literal["public_https", "approved_private", "local_test_only"]
    allowed_hosts: list[str] = Field(default_factory=list, max_length=25)
    allowed_ports: list[int] = Field(default_factory=lambda:[443], max_length=10)
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=20)
    redirect_policy: Literal["deny", "one_hop_revalidate"] = "deny"
    maximum_response_bytes: int = Field(default=524288, ge=1024, le=5242880)
    maximum_request_bytes: int = Field(default=262144, ge=1024, le=5242880)
    reason: str | None = Field(None, max_length=1000)
    confirmation: str | None = Field(None, max_length=100)


class SubscriptionWrite(StrictModel):
    connector_id: int
    name: str = Field(min_length=1, max_length=160)
    event_type: str = Field(min_length=1, max_length=100)
    source_module: str | None = Field(None, max_length=80)
    filter: dict[str, Any] = Field(default_factory=dict)
    mapping_id: int | None = None
    enabled: bool = True
    delivery_mode: Literal["immediate_queue", "digest", "manual_only"] = "immediate_queue"
    digest_window_minutes: int | None = Field(None, ge=1, le=1440)
    minimum_severity: Literal["info", "low", "medium", "high", "critical"] | None = None


class MappingWrite(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    direction: Literal["inbound", "outbound"]
    source_schema: str = Field(min_length=1, max_length=80)
    target_schema: str = Field(min_length=1, max_length=80)
    mapping: list[dict[str, Any]] = Field(max_length=100)


class DeliveryWrite(StrictModel):
    connector_id: int
    event_type: str
    external_operation: Literal["notify", "publish_event", "create_ticket", "update_ticket", "health_test", "pull"]
    payload: dict[str, Any]
    idempotency_key: str = Field(min_length=8, max_length=180)
    soar_execution_id: int | None = None


class ReasonAction(StrictModel):
    reason: str = Field(min_length=3, max_length=1000)
    confirmation: str | None = Field(None, max_length=100)


class EndpointWrite(StrictModel):
    connector_id: int
    name: str = Field(min_length=1, max_length=160)
    schema_version: str = Field(default="1.0", max_length=20)
    trusted_source: bool = False
    maximum_body_bytes: int = Field(default=524288, ge=1024, le=524288)
    timestamp_tolerance_seconds: int = Field(default=300, ge=30, le=900)
    replay_window_seconds: int = Field(default=900, ge=60, le=3600)
    allowed_event_types: list[str] = Field(default_factory=list, max_length=30)
    mapping_id: int | None = None
    secret: str = Field(min_length=16, max_length=500)


class Promotion(StrictModel):
    target_type: Literal["soc_alert", "threat_intelligence", "case_evidence_proposal", "vulnerability_evidence_proposal", "analyst_review_task"]
    confirmation: str = Field(min_length=3, max_length=100)


class ReportWrite(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    report_type: str = Field(default="integration_summary", max_length=60)
    filters: dict[str, Any] = Field(default_factory=dict)
