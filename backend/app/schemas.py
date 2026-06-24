from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from datetime import datetime

class TargetBase(BaseModel):
    name: str
    base_url: str
    environment: str = "local"
    authorization_confirmed: bool = False

class TargetCreate(TargetBase):
    pass

class Target(TargetBase):
    id: int
    domain: str
    created_at: datetime

    class Config:
        from_attributes = True

class FindingBase(BaseModel):
    title: str
    severity: str
    category: str
    affected_url: str
    description: str
    evidence: str
    impact: str
    remediation: str
    confidence: str
    risk_score: float

class FindingCreate(FindingBase):
    pass

class Finding(FindingBase):
    id: int
    scan_id: int
    target_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class ScanBase(BaseModel):
    profile: str

class ScanCreate(ScanBase):
    target_id: int

class Scan(ScanBase):
    id: int
    target_id: int
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    total_findings: int
    risk_score: float
    error_message: Optional[str]

    class Config:
        from_attributes = True

class ScanWithFindings(Scan):
    findings: List[Finding] = []

class ReportBase(BaseModel):
    title: str
    executive_summary: str
    html_content: str

class ReportCreate(ReportBase):
    scan_id: int
    target_id: int

class Report(ReportBase):
    id: int
    scan_id: int
    target_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class DashboardSummary(BaseModel):
    total_targets: int
    total_scans: int
    total_findings: int
    overall_risk_score: float
    severity_distribution: dict
    recent_scans: List[Scan]
    highest_risk_targets: List[Target]

class NotificationBase(BaseModel):
    title: str
    message: str
    type: str
    entity_type: str
    entity_id: Optional[int] = None
    is_read: bool = False

class NotificationCreate(NotificationBase):
    pass

class Notification(NotificationBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class UserProfileBase(BaseModel):
    full_name: str
    email: str
    organization: str
    role: str
    avatar_initials: str

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    organization: Optional[str] = None
    role: Optional[str] = None
    avatar_initials: Optional[str] = None

class UserProfile(UserProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AppSettingsBase(BaseModel):
    theme: str
    default_scan_profile: str
    request_timeout_seconds: int
    max_pages_standard: int
    max_pages_full: int
    max_depth_standard: int
    max_depth_full: int
    rate_limit_delay_ms: int
    report_company_name: str
    report_footer_text: str
    auto_generate_report: bool

class AppSettingsUpdate(BaseModel):
    theme: Optional[str] = None
    default_scan_profile: Optional[str] = None
    request_timeout_seconds: Optional[int] = None
    max_pages_standard: Optional[int] = None
    max_pages_full: Optional[int] = None
    max_depth_standard: Optional[int] = None
    max_depth_full: Optional[int] = None
    rate_limit_delay_ms: Optional[int] = None
    report_company_name: Optional[str] = None
    report_footer_text: Optional[str] = None
    auto_generate_report: Optional[bool] = None

class AppSettings(AppSettingsBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SearchResults(BaseModel):
    targets: List[Target]
    scans: List[Scan]
    findings: List[Finding]
    reports: List[Report]
