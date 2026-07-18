from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    base_url = Column(String)
    domain = Column(String)
    authorization_confirmed = Column(Boolean, default=False)
    environment = Column(String)
    created_at = Column(DateTime, default=utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    profile = Column(String) # Passive Scan, Standard Safe Scan, Full Safe Scan
    status = Column(String) # queued, running, completed, failed
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_findings = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    
    overall_posture_score = Column(Integer, default=100)
    posture_transport_security = Column(Integer, default=100)
    posture_browser_defense = Column(Integer, default=100)
    posture_session_safety = Column(Integer, default=100)
    posture_exposure_hygiene = Column(Integer, default=100)
    posture_authentication_surface = Column(Integer, default=100)
    
    error_message = Column(Text, nullable=True)

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    title = Column(String)
    severity = Column(String) # info, low, medium, high, critical
    category = Column(String)
    affected_url = Column(String)
    description = Column(Text)
    evidence = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    confidence = Column(String)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="findings")
    target = relationship("Target", back_populates="findings")


class CrawlNode(Base):
    __tablename__ = "crawl_nodes"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    url = Column(String, index=True)
    path = Column(String)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    page_title = Column(String, nullable=True)
    depth = Column(Integer)
    parent_url = Column(String, nullable=True)
    has_forms = Column(Boolean, default=False)
    has_password_field = Column(Boolean, default=False)
    finding_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)
    
    scan = relationship("Scan", backref="crawl_nodes")
    target = relationship("Target")

class PostureDiff(Base):
    __tablename__ = "posture_diffs"
    id = Column(Integer, primary_key=True, index=True)
    current_scan_id = Column(Integer, ForeignKey("scans.id"))
    previous_scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    new_findings_count = Column(Integer, default=0)
    resolved_findings_count = Column(Integer, default=0)
    unchanged_findings_count = Column(Integer, default=0)
    risk_score_delta = Column(Float, default=0.0)
    posture_score_delta = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    
    current_scan = relationship("Scan", foreign_keys=[current_scan_id])
    previous_scan = relationship("Scan", foreign_keys=[previous_scan_id])
    target = relationship("Target")

class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    artifact_type = Column(String) # screenshot, html_snippet, header_snapshot
    title = Column(String)
    file_path = Column(String, nullable=True)
    redacted_text = Column(Text, nullable=True)
    related_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    
    scan = relationship("Scan", backref="evidence")
    target = relationship("Target")

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    title = Column(String)
    executive_summary = Column(Text)
    html_content = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="reports")
    target = relationship("Target", back_populates="reports")

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    message = Column(Text)
    type = Column(String) # info, success, warning, danger
    entity_type = Column(String) # target, scan, finding, report, system
    entity_id = Column(Integer, nullable=True)
    recipient_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"), nullable=True, index=True)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

class UserProfile(Base):
    __tablename__ = "user_profiles"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String)
    email = Column(String)
    organization = Column(String)
    role = Column(String)
    avatar_initials = Column(String)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

class AppSettings(Base):
    __tablename__ = "app_settings"
    id = Column(Integer, primary_key=True, index=True)
    theme = Column(String, default="dark") # dark, light, system
    default_scan_profile = Column(String, default="Standard Safe Scan")
    request_timeout_seconds = Column(Integer, default=10)
    max_pages_standard = Column(Integer, default=25)
    max_pages_full = Column(Integer, default=50)
    max_depth_standard = Column(Integer, default=2)
    max_depth_full = Column(Integer, default=3)
    rate_limit_delay_ms = Column(Integer, default=500)
    report_company_name = Column(String, default="VulnScope")
    report_footer_text = Column(String, default="Generated by VulnScope - Authorized Testing Only")
    auto_generate_report = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


from app.modules.api_security.models import (  # noqa: E402,F401
    ApiAssessment,
    ApiEndpoint,
    ApiFinding,
    ApiImportArtifact,
    ApiOwaspCoverage,
    ApiReport,
    JwtAnalysis,
)
from app.modules.api_security.authorization.models import (  # noqa: E402,F401
    ApiIdentity,
    ApiRole,
    AuthorizationMatrixEntry,
    AuthorizationReview,
)
from app.modules.api_security.business_flows.models import (  # noqa: E402,F401
    ApiBusinessFlow,
    ApiBusinessFlowRisk,
    ApiBusinessFlowStep,
)
from app.modules.soc_monitor.models import (  # noqa: E402,F401
    SocActivity,
    SocAlert,
    SocAlertEvent,
    SocBlocklistEntry,
    SocDetectionRule,
    SocEvent,
    SocLogImport,
    SocLogSource,
    SocReport,
    SocThreatIntelResult,
)
from app.modules.document_threats.models import (  # noqa: E402,F401
    DocumentAnalysis,
    DocumentEmbeddedArtifact,
    DocumentFinding,
    DocumentIndicator,
    DocumentReport,
)
from app.modules.phishing_defense.models import (  # noqa: E402,F401
    PhishingAnalysis,
    PhishingAttachmentMetadata,
    PhishingFinding,
    PhishingIndicator,
    PhishingReport,
    PhishingWatchlistEntry,
)
from app.modules.unified_correlation.models import (  # noqa: E402,F401
    UnifiedEntity, EntityObservation, CorrelationRule, CorrelationMatch,
    IncidentCase, IncidentEvidence, IncidentTimelineEvent, IncidentNote,
    IncidentActionItem, IncidentReport,
)
from app.modules.governance.models import (  # noqa: E402,F401
    GovernanceFramework, GovernanceControl, GovernanceRisk, GovernanceRiskSource,
    GovernanceControlMapping, RiskTreatmentPlan, RiskException,
    GovernanceEvidencePackage, GovernanceEvidenceItem, GovernanceReview,
    GovernanceSnapshot, GovernanceReport,
)
from app.modules.access_control.models import (  # noqa: E402,F401
    AccessPermission, AccessRole, AuthSession, LoginAttempt, MfaDevice,
    MfaLoginChallenge, MfaRecoveryCode, RolePermissionAssignment,
    SecurityAuditEvent, UserAccount, UserRoleAssignment,
)
from app.modules.platform_operations.models import (  # noqa: E402,F401
    BackupRecord, ExportPackage, OperationalJob, ReleaseArtifact,
    RestoreRecord, RetentionPolicy, RetentionRun,
)
from app.modules.threat_intelligence.models import (  # noqa: E402,F401
    ThreatIntelSource, ThreatIndicator, ThreatIntelImport, IndicatorSighting,
    IndicatorMatch, ThreatWatchlist, ThreatWatchlistEntry, ThreatCampaign,
    ThreatCampaignIndicator, IndicatorRelationship, ThreatCorrelationRun,
    ThreatIntelReport,
)
from app.modules.detection_engineering.models import (  # noqa: E402,F401
    DetectionRule, DetectionRuleVersion, DetectionRulePack, DetectionRulePackEntry,
    AttackTechnique, DetectionRuleTechnique, DetectionTestCase, DetectionExecution,
    DetectionMatch, DetectionSuppression, DetectionReport,
)
from app.modules.vulnerability_management.models import (  # noqa: E402,F401
    Asset, AssetAlias, AssetRelationship, VulnerabilityRecord,
    VulnerabilityOccurrence, VulnerabilityEvidence, RemediationPlan,
    RemediationTask, VulnerabilityComment, SlaPolicy, RiskAcceptance,
    VerificationRequest, RemediationTemplate, VulnerabilityReport,
    AssetSynchronizationRun, VulnerabilityIngestionRun,
    VulnerabilityStatusHistory,
)
from app.modules.soar.models import (  # noqa: E402,F401
    SoarActionPolicy, SoarPlaybook, SoarPlaybookVersion, SoarPlaybookStep,
    SoarTriggerRule, SoarTriggerEvaluationRun, SoarExecution, SoarStepExecution,
    SoarExecutionEvent, SoarApproval, SoarApprovalDecision, SoarAnalystInput,
    SoarExecutionEvidence, SoarRollbackRecord, SoarReport,
)
