from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
Tlp = Literal["clear", "green", "amber", "amber+strict", "red"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(None, max_length=4000)
    source_type: Literal["manual", "csv", "json", "stix", "internal"] = "manual"
    reliability: int = Field(50, ge=0, le=100)
    default_confidence: int = Field(50, ge=0, le=100)
    default_tlp: Tlp = "amber"
    enabled: bool = True


class SourceUpdate(StrictModel):
    name: str | None = Field(None, min_length=1, max_length=160)
    description: str | None = Field(None, max_length=4000)
    reliability: int | None = Field(None, ge=0, le=100)
    default_confidence: int | None = Field(None, ge=0, le=100)
    default_tlp: Tlp | None = None
    enabled: bool | None = None


class IndicatorCreate(StrictModel):
    type: str = Field(min_length=1, max_length=32)
    value: str = Field(min_length=1, max_length=2048)
    title: str | None = Field(None, max_length=240)
    description: str | None = Field(None, max_length=4000)
    severity: Severity = "medium"
    confidence: int = Field(50, ge=0, le=100)
    tlp: Tlp = "amber"
    tags: list[str] = Field(default_factory=list, max_length=30)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    source_id: int | None = Field(None, ge=1)


class IndicatorUpdate(StrictModel):
    title: str | None = Field(None, max_length=240)
    description: str | None = Field(None, max_length=4000)
    severity: Severity | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    tlp: Tlp | None = None
    tags: list[str] | None = Field(None, max_length=30)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    active: bool | None = None
    false_positive: bool | None = None


class WatchlistCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(None, max_length=2000)
    enabled: bool = True
    severity_threshold: Severity | None = None


class WatchlistUpdate(StrictModel):
    name: str | None = Field(None, min_length=1, max_length=160)
    description: str | None = Field(None, max_length=2000)
    enabled: bool | None = None
    severity_threshold: Severity | None = None


class WatchlistEntryCreate(StrictModel):
    indicator_id: int = Field(ge=1)
    note: str | None = Field(None, max_length=1000)


class CampaignCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=4000)
    severity: Severity = "medium"
    confidence: int = Field(50, ge=0, le=100)
    active: bool = True
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    tags: list[str] = Field(default_factory=list, max_length=30)
    indicator_ids: list[int] = Field(default_factory=list, max_length=200)


class CampaignUpdate(StrictModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=4000)
    severity: Severity | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    active: bool | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    tags: list[str] | None = Field(None, max_length=30)
    indicator_ids: list[int] | None = Field(None, max_length=200)


class RelationshipCreate(StrictModel):
    source_indicator_id: int = Field(ge=1)
    target_indicator_id: int = Field(ge=1)
    relationship_type: str = Field(min_length=1, max_length=64)
    confidence: int = Field(50, ge=0, le=100)
    description: str | None = Field(None, max_length=2000)


class CorrelationRequest(StrictModel):
    maximum_records: int = Field(1000, ge=1, le=5000)


class MatchReview(StrictModel):
    status: Literal["reviewing", "confirmed", "false_positive", "accepted_risk", "escalated"]
    analyst_note: str | None = Field(None, max_length=4000)
    case_id: int | None = Field(None, ge=1)


class MatchEscalate(StrictModel):
    confirmed: bool
    case_id: int | None = Field(None, ge=1)
    case_title: str | None = Field(None, min_length=1, max_length=240)
    analyst_note: str | None = Field(None, max_length=4000)


class ReportCreate(StrictModel):
    title: str = Field("Threat Intelligence Report", min_length=1, max_length=240)
    report_type: str = Field("intelligence_summary", min_length=1, max_length=40)
    defanged: bool = True


class Page(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int

