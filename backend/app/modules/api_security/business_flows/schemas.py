from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class FlowCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    description: str = Field(..., min_length=2, max_length=4000)
    business_goal: Optional[str] = Field(default=None, max_length=2000)
    actor_roles: list[str] = Field(default_factory=list, max_length=30)
    status: Literal["draft", "reviewed", "approved"] = "draft"


class FlowUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, min_length=2, max_length=4000)
    business_goal: Optional[str] = Field(default=None, max_length=2000)
    actor_roles: Optional[list[str]] = Field(default=None, max_length=30)
    status: Optional[Literal["draft", "reviewed", "approved"]] = None


class StepCreate(BaseModel):
    step_order: int = Field(..., ge=1, le=1000)
    endpoint_id: Optional[int] = None
    action_name: str = Field(..., min_length=1, max_length=200)
    expected_actor_role: Optional[str] = Field(default=None, max_length=120)
    prerequisite_description: Optional[str] = Field(default=None, max_length=2000)
    expected_state_before: Optional[str] = Field(default=None, max_length=2000)
    expected_state_after: Optional[str] = Field(default=None, max_length=2000)
    sensitive_operation: bool = False


class StepUpdate(BaseModel):
    step_order: Optional[int] = Field(default=None, ge=1, le=1000)
    endpoint_id: Optional[int] = None
    action_name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    expected_actor_role: Optional[str] = Field(default=None, max_length=120)
    prerequisite_description: Optional[str] = Field(default=None, max_length=2000)
    expected_state_before: Optional[str] = Field(default=None, max_length=2000)
    expected_state_after: Optional[str] = Field(default=None, max_length=2000)
    sensitive_operation: Optional[bool] = None


class StepRead(BaseModel):
    id: int
    flow_id: int
    step_order: int
    endpoint_id: Optional[int]
    action_name: str
    expected_actor_role: Optional[str]
    prerequisite_description: Optional[str]
    expected_state_before: Optional[str]
    expected_state_after: Optional[str]
    sensitive_operation: bool
    created_at: datetime
    updated_at: datetime


class RiskUpdate(BaseModel):
    status: Literal["open", "accepted", "resolved"]


class RiskRead(BaseModel):
    id: int
    flow_id: int
    step_id: Optional[int]
    risk_type: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    description: str
    evidence_summary: str
    remediation: str
    manual_validation_required: bool
    status: Literal["open", "accepted", "resolved"]
    owasp_category: Optional[str]
    created_at: datetime
    updated_at: datetime


class FlowRead(BaseModel):
    id: int
    assessment_id: int
    name: str
    description: str
    business_goal: Optional[str]
    actor_roles: list[str]
    status: Literal["draft", "reviewed", "approved"]
    risk_score: int
    steps: list[StepRead] = []
    risks: list[RiskRead] = []
    created_at: datetime
    updated_at: datetime


class FlowAnalysisResult(BaseModel):
    flow_id: int
    risks_created: int
    risks_total: int
    high_risk_indicators: int
    risk_score: int
    disclaimer: str
