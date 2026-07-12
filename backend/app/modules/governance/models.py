from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class GovernanceFramework(Base):
    __tablename__ = "governance_frameworks"
    id = Column(Integer, primary_key=True)
    framework_key = Column(String(80), unique=True, nullable=False, index=True)
    name = Column(String(240), nullable=False, index=True)
    version = Column(String(80), nullable=False, index=True)
    description = Column(Text, nullable=False)
    source_note = Column(Text, nullable=False)
    disclaimer = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    control_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    controls = relationship("GovernanceControl", cascade="all, delete-orphan", back_populates="framework")


class GovernanceControl(Base):
    __tablename__ = "governance_controls"
    __table_args__ = (UniqueConstraint("framework_id", "control_key", name="uq_governance_control"),)
    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey("governance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True)
    control_key = Column(String(80), nullable=False, index=True)
    parent_control_key = Column(String(80))
    title = Column(String(300), nullable=False)
    summary = Column(Text, nullable=False)
    control_type = Column(String(30), nullable=False, index=True)
    sort_order = Column(Integer, default=0)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    framework = relationship("GovernanceFramework", back_populates="controls")
    mappings = relationship("GovernanceControlMapping", back_populates="control")


class GovernanceRisk(Base):
    __tablename__ = "governance_risks"
    id = Column(Integer, primary_key=True)
    risk_key = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    origin = Column(String(40), nullable=False, index=True)
    category = Column(String(40), nullable=False, index=True)
    owner_name = Column(String(200), index=True)
    status = Column(String(40), default="identified", nullable=False, index=True)
    treatment_strategy = Column(String(30), default="unset", nullable=False, index=True)
    likelihood = Column(Integer, nullable=False)
    impact = Column(Integer, nullable=False)
    inherent_score = Column(Float, nullable=False)
    residual_likelihood = Column(Integer, nullable=False)
    residual_impact = Column(Integer, nullable=False)
    residual_score = Column(Float, nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    confidence = Column(String(20), default="medium", nullable=False, index=True)
    appetite_status = Column(String(30), default="not_assessed", nullable=False, index=True)
    due_at = Column(DateTime, index=True)
    next_review_at = Column(DateTime, index=True)
    source_module_count = Column(Integer, default=0)
    source_record_count = Column(Integer, default=0)
    control_mapping_count = Column(Integer, default=0)
    evidence_count = Column(Integer, default=0)
    analyst_notes = Column(Text)
    resolution_summary = Column(Text)
    acceptance_justification = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    closed_at = Column(DateTime)
    sources = relationship("GovernanceRiskSource", cascade="all, delete-orphan", back_populates="risk")
    mappings = relationship("GovernanceControlMapping", cascade="all, delete-orphan", back_populates="risk")
    treatments = relationship("RiskTreatmentPlan", cascade="all, delete-orphan", back_populates="risk")
    exceptions = relationship("RiskException", cascade="all, delete-orphan", back_populates="risk")


class GovernanceRiskSource(Base):
    __tablename__ = "governance_risk_sources"
    __table_args__ = (UniqueConstraint("risk_id", "source_fingerprint", name="uq_governance_risk_source"),)
    id = Column(Integer, primary_key=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="CASCADE"), nullable=False, index=True)
    source_module = Column(String(40), nullable=False, index=True)
    source_record_type = Column(String(60), nullable=False)
    source_record_id = Column(Integer, nullable=False)
    source_internal_route = Column(String(500))
    source_fingerprint = Column(String(64), nullable=False, index=True)
    title_snapshot = Column(String(500), nullable=False)
    evidence_snapshot = Column(Text, nullable=False)
    source_severity = Column(String(20), nullable=False)
    source_confidence = Column(String(20), nullable=False)
    observed_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    risk = relationship("GovernanceRisk", back_populates="sources")


class GovernanceControlMapping(Base):
    __tablename__ = "governance_control_mappings"
    id = Column(Integer, primary_key=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="CASCADE"), index=True)
    source_module = Column(String(40), index=True)
    source_record_type = Column(String(60))
    source_record_id = Column(Integer)
    control_id = Column(Integer, ForeignKey("governance_controls.id", ondelete="CASCADE"), nullable=False, index=True)
    mapping_status = Column(String(30), default="candidate", nullable=False, index=True)
    mapping_basis = Column(String(30), default="deterministic_rule", nullable=False)
    confidence = Column(String(20), default="medium", nullable=False)
    rationale = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    mapping_fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    analyst_notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    reviewed_at = Column(DateTime)
    risk = relationship("GovernanceRisk", back_populates="mappings")
    control = relationship("GovernanceControl", back_populates="mappings")


class RiskTreatmentPlan(Base):
    __tablename__ = "risk_treatment_plans"
    id = Column(Integer, primary_key=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    strategy = Column(String(30), nullable=False)
    status = Column(String(30), default="planned", nullable=False, index=True)
    owner_name = Column(String(200), index=True)
    priority = Column(String(20), default="medium", nullable=False)
    target_date = Column(DateTime, index=True)
    expected_residual_likelihood = Column(Integer)
    expected_residual_impact = Column(Integer)
    completion_summary = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime)
    risk = relationship("GovernanceRisk", back_populates="treatments")


class RiskException(Base):
    __tablename__ = "risk_exceptions"
    id = Column(Integer, primary_key=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="CASCADE"), nullable=False, index=True)
    exception_key = Column(String(100), unique=True, nullable=False, index=True)
    justification = Column(Text, nullable=False)
    approver_name = Column(String(200))
    status = Column(String(30), default="requested", nullable=False, index=True)
    requested_at = Column(DateTime, default=utcnow)
    approved_at = Column(DateTime)
    expires_at = Column(DateTime, index=True)
    revoked_at = Column(DateTime)
    review_notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    risk = relationship("GovernanceRisk", back_populates="exceptions")


class GovernanceReview(Base):
    __tablename__ = "governance_reviews"
    id = Column(Integer, primary_key=True)
    review_key = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    review_type = Column(String(40), nullable=False, index=True)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    owner_name = Column(String(200))
    status = Column(String(30), default="planned", nullable=False, index=True)
    scope_summary = Column(Text, nullable=False)
    conclusions = Column(Text)
    snapshot_json = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime)


class GovernanceEvidencePackage(Base):
    __tablename__ = "governance_evidence_packages"
    id = Column(Integer, primary_key=True)
    package_key = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    framework_id = Column(Integer, ForeignKey("governance_frameworks.id", ondelete="SET NULL"), index=True)
    review_id = Column(Integer, ForeignKey("governance_reviews.id", ondelete="SET NULL"), index=True)
    status = Column(String(30), default="draft", nullable=False, index=True)
    owner_name = Column(String(200))
    item_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    items = relationship("GovernanceEvidenceItem", cascade="all, delete-orphan", back_populates="package")


class GovernanceEvidenceItem(Base):
    __tablename__ = "governance_evidence_items"
    __table_args__ = (UniqueConstraint("package_id", "evidence_fingerprint", name="uq_governance_evidence_item"),)
    id = Column(Integer, primary_key=True)
    package_id = Column(Integer, ForeignKey("governance_evidence_packages.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="SET NULL"), index=True)
    control_id = Column(Integer, ForeignKey("governance_controls.id", ondelete="SET NULL"), index=True)
    source_module = Column(String(40), nullable=False)
    source_record_type = Column(String(60), nullable=False)
    source_record_id = Column(Integer, nullable=False)
    source_internal_route = Column(String(500))
    title_snapshot = Column(String(500), nullable=False)
    evidence_snapshot = Column(Text, nullable=False)
    evidence_fingerprint = Column(String(64), nullable=False, index=True)
    evidence_strength = Column(String(20), default="moderate", nullable=False)
    observed_at = Column(DateTime, nullable=False)
    added_at = Column(DateTime, default=utcnow)
    package = relationship("GovernanceEvidencePackage", back_populates="items")


class GovernanceSnapshot(Base):
    __tablename__ = "governance_snapshots"
    id = Column(Integer, primary_key=True)
    snapshot_key = Column(String(100), unique=True, nullable=False, index=True)
    snapshot_type = Column(String(30), nullable=False, index=True)
    metric_date = Column(DateTime, nullable=False, index=True)
    metrics_json = Column(Text, nullable=False)
    source_fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)


class GovernanceReport(Base):
    __tablename__ = "governance_reports"
    id = Column(Integer, primary_key=True)
    report_type = Column(String(40), nullable=False, index=True)
    risk_id = Column(Integer, ForeignKey("governance_risks.id", ondelete="SET NULL"), index=True)
    framework_id = Column(Integer, ForeignKey("governance_frameworks.id", ondelete="SET NULL"), index=True)
    package_id = Column(Integer, ForeignKey("governance_evidence_packages.id", ondelete="SET NULL"), index=True)
    review_id = Column(Integer, ForeignKey("governance_reviews.id", ondelete="SET NULL"), index=True)
    title = Column(String(300), nullable=False)
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)


Index("ix_governance_risk_due_review", GovernanceRisk.due_at, GovernanceRisk.next_review_at)
