from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


SourceType = Literal["openapi", "postman", "manual"]
AssessmentStatus = Literal["draft", "processing", "completed", "failed"]
RiskLevel = Literal["info", "low", "medium", "high"]


class ApiAssessmentCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    source_type: SourceType = "manual"


class ApiAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str]
    source_type: SourceType
    source_filename: Optional[str]
    status: AssessmentStatus
    base_url: Optional[str]
    api_version: Optional[str]
    endpoint_count: int
    unauthenticated_endpoint_count: int
    high_risk_endpoint_count: int
    risk_score: int
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime


class ApiImportArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    artifact_type: Literal["openapi", "postman"]
    filename: str
    parsed_summary: Dict[str, Any]
    created_at: datetime


class ApiEndpointRead(BaseModel):
    id: int
    assessment_id: int
    path: str
    method: str
    operation_id: Optional[str]
    summary: Optional[str]
    description: Optional[str]
    auth_required: bool
    auth_schemes: List[str]
    request_content_types: List[str]
    response_content_types: List[str]
    parameters: List[Dict[str, Any]]
    tags: List[str]
    folder_path: Optional[str]
    deprecated: bool
    preliminary_risk_level: RiskLevel
    preliminary_risk_reasons: List[str]
    created_at: datetime


class ApiAssessmentDetail(ApiAssessmentRead):
    artifacts: List[ApiImportArtifactRead] = []


class ApiImportResult(BaseModel):
    assessment: ApiAssessmentRead
    artifact: ApiImportArtifactRead
    endpoints_discovered: int
    unauthenticated_endpoints: int
    high_risk_endpoints: int


class ApiSecuritySummary(BaseModel):
    assessment: ApiAssessmentRead
    endpoint_count: int
    unauthenticated_endpoint_count: int
    high_risk_endpoint_count: int
    risk_distribution: Dict[str, int]
    methods: Dict[str, int]
    tags: List[str]


class ApiSecurityOverview(BaseModel):
    total_assessments: int
    endpoints_inventoried: int
    unauthenticated_endpoints: int
    high_risk_endpoints: int
    recent_assessments: List[ApiAssessmentRead]

