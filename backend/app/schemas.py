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

class TargetUpdate(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    environment: Optional[str] = None
    authorization_confirmed: Optional[bool] = None

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

class CrawlNodeBase(BaseModel):
    url: str
    path: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    page_title: Optional[str] = None
    depth: int
    parent_url: Optional[str] = None
    has_forms: bool = False
    has_password_field: bool = False
    finding_count: int = 0

class CrawlNode(CrawlNodeBase):
    id: int
    scan_id: int
    target_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class PostureDiffBase(BaseModel):
    new_findings_count: int
    resolved_findings_count: int
    unchanged_findings_count: int
    risk_score_delta: float
    posture_score_delta: int
    summary: Optional[str] = None

class PostureDiff(PostureDiffBase):
    id: int
    current_scan_id: int
    previous_scan_id: int
    target_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class EvidenceArtifactBase(BaseModel):
    artifact_type: str
    title: str
    file_path: Optional[str] = None
    redacted_text: Optional[str] = None
    related_url: Optional[str] = None

class EvidenceArtifact(EvidenceArtifactBase):
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
    
    overall_posture_score: int = 100
    posture_transport_security: int = 100
    posture_browser_defense: int = 100
    posture_session_safety: int = 100
    posture_exposure_hygiene: int = 100
    posture_authentication_surface: int = 100
    
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
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    overall_risk_score: float
    overall_posture_score: int
    api_assessment_count: int = 0
    api_endpoint_count: int = 0
    api_unauthenticated_endpoint_count: int = 0
    api_high_risk_endpoint_count: int = 0
    api_finding_count: int = 0
    api_high_risk_finding_count: int = 0
    api_owasp_observed_category_count: int = 0
    api_authorization_matrix_coverage: float = 0
    api_unresolved_authorization_review_count: int = 0
    api_business_flow_count: int = 0
    api_high_risk_flow_indicator_count: int = 0
    soc_total_events: int = 0
    soc_open_alerts: int = 0
    soc_high_critical_alerts: int = 0
    soc_active_rules: int = 0
    soc_active_blocklist_entries: int = 0
    document_total_analyses: int = 0
    document_suspicious_high_risk: int = 0
    document_high_critical_findings: int = 0
    document_active_content: int = 0
    phishing_total_analyses: int = 0
    phishing_suspicious_high_risk: int = 0
    phishing_high_critical_findings: int = 0
    phishing_active_watchlist_entries: int = 0
    active_correlation_matches: int = 0
    open_incident_cases: int = 0
    p1_incident_cases: int = 0
    high_critical_incident_cases: int = 0
    multi_module_entities: int = 0
    governance_open_risks: int = 0
    governance_high_critical_risks: int = 0
    governance_risks_exceeding_appetite: int = 0
    governance_control_gaps: int = 0
    governance_mappings_awaiting_review: int = 0
    governance_active_exceptions: int = 0
    threat_intel_active_indicators: int = 0
    threat_intel_high_risk_matches: int = 0
    threat_intel_recent_imports: int = 0
    threat_intel_recent_escalations: int = 0
    detection_active_rules: int = 0
    detection_high_risk_matches: int = 0
    detection_failed_validations: int = 0
    detection_attack_coverage: float = 0
    detection_recent_escalations: int = 0
    severity_distribution: dict
    recent_scans: List[Scan]
    highest_risk_targets: List[Target]
    operations: Optional[dict] = None
    vulnerability_management: Optional[dict] = None
    soar: Optional[dict] = None
    integrations: Optional[dict] = None

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
    api_assessments: List[dict] = []
    api_endpoints: List[dict] = []
    api_findings: List[dict] = []
    jwt_analyses: List[dict] = []
    api_reports: List[dict] = []
    api_roles: List[dict] = []
    authorization_reviews: List[dict] = []
    api_business_flows: List[dict] = []
    api_business_flow_risks: List[dict] = []
    soc_events: List[dict] = []
    soc_alerts: List[dict] = []
    soc_rules: List[dict] = []
    soc_reports: List[dict] = []
    soc_blocklist_entries: List[dict] = []
    document_analyses: List[dict] = []
    document_findings: List[dict] = []
    document_indicators: List[dict] = []
    document_reports: List[dict] = []
    phishing_analyses: List[dict] = []
    phishing_findings: List[dict] = []
    phishing_indicators: List[dict] = []
    phishing_watchlist_entries: List[dict] = []
    phishing_reports: List[dict] = []
    unified_entities: List[dict] = []
    correlation_matches: List[dict] = []
    incident_cases: List[dict] = []
    incident_evidence: List[dict] = []
    incident_reports: List[dict] = []
    governance_risks: List[dict] = []
    governance_frameworks: List[dict] = []
    governance_controls: List[dict] = []
    governance_mappings: List[dict] = []
    governance_treatments: List[dict] = []
    governance_exceptions: List[dict] = []
    governance_evidence_packages: List[dict] = []
    governance_reviews: List[dict] = []
    governance_reports: List[dict] = []
    threat_indicators: List[dict] = []
    threat_sources: List[dict] = []
    threat_watchlists: List[dict] = []
    threat_campaigns: List[dict] = []
    threat_matches: List[dict] = []
    threat_reports: List[dict] = []
    detection_rules: List[dict] = []
    detection_packs: List[dict] = []
    attack_techniques: List[dict] = []
    detection_matches: List[dict] = []
    detection_executions: List[dict] = []
    detection_suppressions: List[dict] = []
    detection_reports: List[dict] = []
    vm_assets: List[dict] = []
    vm_vulnerabilities: List[dict] = []
    vm_remediation_plans: List[dict] = []
    vm_remediation_tasks: List[dict] = []
    vm_sla_policies: List[dict] = []
    vm_risk_acceptances: List[dict] = []
    vm_verifications: List[dict] = []
    vm_remediation_templates: List[dict] = []
    vm_reports: List[dict] = []
    operations: List[dict] = []
    soar_playbooks: List[dict] = []
    soar_triggers: List[dict] = []
    soar_executions: List[dict] = []
    soar_approvals: List[dict] = []
    soar_analyst_inputs: List[dict] = []
    soar_actions: List[dict] = []
    soar_rollbacks: List[dict] = []
    soar_reports: List[dict] = []
    integrations: List[dict] = []
