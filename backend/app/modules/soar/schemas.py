from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionPolicyUpdate(StrictModel):
    enabled: bool | None = None
    automatic_local_allowed: bool | None = None
    approval_required_override: bool | None = None
    requester_approver_separation_required: bool | None = None
    maximum_retries_override: int | None = Field(default=None, ge=0, le=3)
    notes: str | None = Field(default=None, max_length=2000)


class PlaybookCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    category: str = Field(default="general", min_length=1, max_length=80)
    trigger_mode: Literal["manual", "proposal_only", "automatic_local"] = "manual"
    severity_threshold: Literal["informational", "low", "medium", "high", "critical"] | None = None
    owner_user_id: int | None = Field(default=None, ge=1)
    definition: dict[str, Any]
    change_summary: str = Field(min_length=1, max_length=1000)
    demo_owned: bool = False


class PlaybookUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=8000)
    category: str | None = Field(default=None, min_length=1, max_length=80)
    trigger_mode: Literal["manual", "proposal_only", "automatic_local"] | None = None
    severity_threshold: Literal["informational", "low", "medium", "high", "critical"] | None = None
    owner_user_id: int | None = Field(default=None, ge=1)
    definition: dict[str, Any] | None = None
    change_summary: str = Field(min_length=1, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)


class LifecycleRequest(StrictModel):
    optimistic_lock_version: int = Field(ge=1)


class CloneRequest(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    change_summary: str = Field(default="Cloned from protected template", min_length=1, max_length=1000)


class VersionRollbackRequest(StrictModel):
    version_number: int = Field(ge=1)
    change_summary: str = Field(min_length=1, max_length=1000)
    optimistic_lock_version: int = Field(ge=1)


class TriggerCreate(StrictModel):
    playbook_id: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=200)
    source_type: Literal["soc_alert", "incident_case", "detection_match", "threat_intel_match", "vulnerability", "phishing_analysis", "document_analysis", "security_anomaly", "analytics_drift", "manual"]
    conditions: dict[str, Any]
    proposal_only: bool = True
    automatic_local: bool = False
    cooldown_minutes: int = Field(default=60, ge=0, le=10080)
    maximum_proposals_per_hour: int = Field(default=20, ge=1, le=100)
    enabled: bool = True

    @model_validator(mode="after")
    def mode(self):
        if self.proposal_only and self.automatic_local:
            raise ValueError("A trigger cannot be proposal-only and automatic-local")
        return self


class TriggerUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    conditions: dict[str, Any] | None = None
    proposal_only: bool | None = None
    automatic_local: bool | None = None
    cooldown_minutes: int | None = Field(default=None, ge=0, le=10080)
    maximum_proposals_per_hour: int | None = Field(default=None, ge=1, le=100)
    enabled: bool | None = None


class TriggerEvaluateRequest(StrictModel):
    source_type: Literal["soc_alert", "incident_case", "detection_match", "threat_intel_match", "vulnerability", "phishing_analysis", "document_analysis", "security_anomaly", "analytics_drift"]
    source_entity_id: int = Field(ge=1)
    source_context: dict[str, Any] = Field(default_factory=dict)


class ExecutionCreate(StrictModel):
    playbook_id: int = Field(ge=1)
    mode: Literal["dry_run", "simulation", "live_local"]
    trigger_source_type: Literal["soc_alert", "incident_case", "detection_match", "threat_intel_match", "vulnerability", "phishing_analysis", "document_analysis", "security_anomaly", "analytics_drift", "manual"] = "manual"
    trigger_source_id: int | None = Field(default=None, ge=1)
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    input_context: dict[str, Any] = Field(default_factory=dict)


class ReasonRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=2000)
    optimistic_lock_version: int | None = Field(default=None, ge=1)


class DecisionRequest(StrictModel):
    note: str = Field(min_length=1, max_length=2000)


class AnalystInputSubmit(StrictModel):
    response: dict[str, Any]


class RollbackExecute(StrictModel):
    confirmation: Literal["EXECUTE APPROVED ROLLBACK"]


class ProcessDueRequest(StrictModel):
    batch_size: int = Field(default=25, ge=1, le=100)


class ReportCreate(StrictModel):
    title: str = Field(min_length=1, max_length=240)
    report_type: Literal["soar_summary", "execution_history", "approval_governance", "rollback_history"] = "soar_summary"
    filters: dict[str, Any] = Field(default_factory=dict)
