from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


PrivilegeLevel = Literal["public", "user", "privileged", "admin", "service"]
IdentityType = Literal["anonymous", "user", "admin", "service_account", "custom"]
ExpectedAccess = Literal["allow", "deny", "conditional", "unknown"]
ObjectScope = Literal["own", "assigned", "tenant", "organization", "global", "unknown"]


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=1000)
    privilege_level: PrivilegeLevel = "user"


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=1000)
    privilege_level: Optional[PrivilegeLevel] = None


class RoleRead(RoleCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    assessment_id: int
    created_at: datetime
    updated_at: datetime


class IdentityCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=160)
    role_id: Optional[int] = None
    identity_type: IdentityType = "custom"
    notes: Optional[str] = Field(default=None, max_length=2000)


class IdentityUpdate(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=160)
    role_id: Optional[int] = None
    identity_type: Optional[IdentityType] = None
    notes: Optional[str] = Field(default=None, max_length=2000)


class IdentityRead(IdentityCreate):
    model_config = ConfigDict(from_attributes=True)
    id: int
    assessment_id: int
    created_at: datetime
    updated_at: datetime


class MatrixEntryCreate(BaseModel):
    endpoint_id: int
    role_id: int
    expected_access: ExpectedAccess = "unknown"
    object_scope: ObjectScope = "unknown"
    expected_conditions: Optional[dict[str, Any]] = None
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)
    review_status: Literal["not_reviewed", "reviewed", "requires_validation"] = "not_reviewed"


class MatrixEntryUpdate(BaseModel):
    expected_access: Optional[ExpectedAccess] = None
    object_scope: Optional[ObjectScope] = None
    expected_conditions: Optional[dict[str, Any]] = None
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)
    review_status: Optional[Literal["not_reviewed", "reviewed", "requires_validation"]] = None


class MatrixEntryRead(MatrixEntryCreate):
    id: int
    assessment_id: int
    created_at: datetime
    updated_at: datetime


class AuthorizationReviewUpdate(BaseModel):
    analyst_decision: Optional[Literal["open", "accepted", "rejected", "needs_testing"]] = None
    notes: Optional[str] = Field(default=None, max_length=4000)


class AuthorizationReviewRead(BaseModel):
    id: int
    assessment_id: int
    endpoint_id: int
    matrix_entry_id: Optional[int]
    review_type: Literal["object_level", "function_level", "property_level"]
    expected_behavior: str
    observed_metadata: str
    risk_indicator: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    manual_validation_required: bool
    analyst_decision: Literal["open", "accepted", "rejected", "needs_testing"]
    notes: Optional[str]
    validation_checklist: list[str]
    created_at: datetime
    updated_at: datetime


class AuthorizationGenerationResult(BaseModel):
    matrix_entries_created: int
    reviews_created: int
    unresolved_high_risk_reviews: int
    disclaimer: str
