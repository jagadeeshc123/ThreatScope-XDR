from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


Severity = Literal["informational", "low", "medium", "high", "critical"]
Lifecycle = Literal["draft", "testing", "active", "disabled", "archived"]


class RuleCreate(StrictModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=8000)
    rule_uuid: str | None = Field(default=None, max_length=64)
    rule_format: Literal["native", "sigma_yaml", "sigma_json"] = "native"
    severity: Severity = "medium"
    confidence: int = Field(default=50, ge=0, le=100)
    source_module: str | None = Field(default=None, max_length=40)
    logsource_category: str | None = Field(default=None, max_length=80)
    logsource_product: str | None = Field(default=None, max_length=80)
    logsource_service: str | None = Field(default=None, max_length=80)
    selections: dict[str, Any]
    condition: str = Field(min_length=1, max_length=500)
    false_positive_guidance: str | None = Field(default=None, max_length=8000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    technique_ids: list[str] = Field(default_factory=list, max_length=30)
    lifecycle_status: Lifecycle = "draft"


class RuleUpdate(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=8000)
    severity: Severity | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    source_module: str | None = Field(default=None, max_length=40)
    selections: dict[str, Any] | None = None
    condition: str | None = Field(default=None, max_length=500)
    false_positive_guidance: str | None = Field(default=None, max_length=8000)
    tags: list[str] | None = Field(default=None, max_length=50)
    technique_ids: list[str] | None = Field(default=None, max_length=30)
    change_summary: str = Field(default="Rule updated", min_length=1, max_length=500)


class Rollback(StrictModel):
    version_number: int = Field(ge=1)
    change_summary: str = Field(default="Rollback", min_length=1, max_length=500)


class TestCaseCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    event_payload: dict[str, Any]
    expected_match: bool
    expected_severity: Severity | None = None
    enabled: bool = True


class TestCaseUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    event_payload: dict[str, Any] | None = None
    expected_match: bool | None = None
    expected_severity: Severity | None = None
    enabled: bool | None = None


class ImportRequest(StrictModel):
    content: str = Field(min_length=1, max_length=1_048_576)
    filename: str = Field(default="rules.yaml", min_length=1, max_length=255)
    duplicate_action: Literal["skip", "new_version"] = "skip"


class PackCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    version: str = Field(default="1.0", max_length=40)
    enabled: bool = True


class PackUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    version: str | None = Field(default=None, max_length=40)
    enabled: bool | None = None


class PackRule(StrictModel):
    rule_id: int = Field(ge=1)


class ExecutionCreate(StrictModel):
    rule_ids: list[int] = Field(default_factory=list, max_length=25)
    pack_id: int | None = Field(default=None, ge=1)
    source_modules: list[Literal["soc"]] = Field(default_factory=lambda: ["soc"], min_length=1, max_length=1)
    start_at: datetime | None = None
    end_at: datetime | None = None
    maximum_records: int = Field(default=1000, ge=1, le=5000)
    include_previously_matched: bool = False
    dry_run: bool = False

    @model_validator(mode="after")
    def scope(self):
        if not self.rule_ids and not self.pack_id: raise ValueError("rule_ids or pack_id is required")
        if self.start_at and self.end_at and self.start_at > self.end_at: raise ValueError("start_at must not be after end_at")
        return self


class MatchReview(StrictModel):
    status: Literal["reviewing", "confirmed", "false_positive", "accepted_risk"]
    analyst_note: str | None = Field(default=None, max_length=4000)


class Promote(StrictModel):
    confirmed: bool
    analyst_note: str | None = Field(default=None, max_length=4000)


class Escalate(Promote):
    case_id: int | None = Field(default=None, ge=1)
    case_title: str | None = Field(default=None, max_length=240)


class SuppressionCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=4000)
    rule_id: int | None = Field(default=None, ge=1)
    field_conditions: dict[str, Any] = Field(min_length=1, max_length=12)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def dates(self):
        if self.valid_from and self.valid_until and self.valid_from > self.valid_until: raise ValueError("valid_from must not be after valid_until")
        return self


class SuppressionUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, min_length=1, max_length=4000)
    field_conditions: dict[str, Any] | None = Field(default=None, min_length=1, max_length=12)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    enabled: bool | None = None


class ReportCreate(StrictModel):
    title: str = Field(min_length=1, max_length=240)
    report_type: str = Field(default="detection_summary", max_length=40)
    filters: dict[str, Any] = Field(default_factory=dict)
