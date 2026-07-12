from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class ManualRiskCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=4000)
    category: Literal["web_exposure","api_security","authorization","business_flow","soc","document","phishing","correlation","incident","governance","other"] = "other"
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    residual_likelihood: int | None = Field(None, ge=1, le=5)
    residual_impact: int | None = Field(None, ge=1, le=5)
    owner_name: str | None = Field(None, max_length=200)
    confidence: Literal["low","medium","high"] = "medium"
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
