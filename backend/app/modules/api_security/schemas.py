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
    api_findings: int = 0
    high_risk_api_findings: int = 0
    owasp_categories_with_indicators: int = 0
    recent_assessments: List[ApiAssessmentRead]


class JwtAnalyzeRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=12000)
    assessment_id: Optional[int] = None
    expected_issuer: Optional[str] = Field(default=None, max_length=500)
    expected_audience: Optional[str] = Field(default=None, max_length=500)


class JwtAnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: Optional[int]
    token_fingerprint: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    algorithm: Optional[str]
    issuer: Optional[str]
    audience: List[str]
    issued_at: Optional[datetime]
    expires_at: Optional[datetime]
    not_before: Optional[datetime]
    expiration_status: Literal["missing", "expired", "valid", "long_lived", "unknown"]
    risk_score: int
    findings: List[Dict[str, Any]]
    disclaimer: str
    created_at: datetime


class ApiFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    endpoint_id: Optional[int]
    title: str
    owasp_category: Optional[str]
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    description: str
    evidence: str
    impact: str
    remediation: str
    source: Literal["openapi", "postman", "jwt", "response_schema", "inventory", "authorization_matrix", "object_level_review", "function_level_review", "property_level_review", "business_flow"]
    fingerprint: str
    created_at: datetime
    updated_at: datetime


class ApiOwaspCoverageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    category_id: str
    category_title: str
    status: Literal["covered", "partial", "not_observed", "not_applicable"]
    finding_count: int
    evidence_summary: str
    created_at: datetime
    updated_at: datetime
    related_findings: List[ApiFindingRead] = []


class ResponseExposureItem(BaseModel):
    endpoint_id: Optional[int]
    method: str
    path: str
    status_code: Optional[str]
    field_path: str
    exposure_type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    explanation: str
    remediation: str


class AnalyzeAssessmentResult(BaseModel):
    assessment_id: int
    findings_created: int
    findings_total: int
    high_or_critical_findings: int
    coverage_categories: int


class ApiReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    title: str
    executive_summary: str
    html_content: str
    summary: Dict[str, Any]
    created_at: datetime
