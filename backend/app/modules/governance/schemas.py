from datetime import datetime
from pydantic import BaseModel, Field


class ManualRiskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=4000)
    category: str = "other"
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    residual_likelihood: int | None = Field(None, ge=1, le=5)
    residual_impact: int | None = Field(None, ge=1, le=5)
    owner_name: str | None = Field(None, max_length=200)
    confidence: str = "medium"
    due_at: datetime | None = None
    next_review_at: datetime | None = None


class SynchronizationSummary(BaseModel):
    source_records_examined: int
    candidates_generated: int
    risks_created: int
    risks_updated: int
    risks_reused: int
    sources_created: int
    sources_reused: int
    records_skipped: int
    safe_errors: list[str]
    duration_ms: float
    per_module_counts: dict[str, int]
