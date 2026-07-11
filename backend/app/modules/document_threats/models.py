from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow(): return datetime.now(timezone.utc)


class DocumentAnalysis(Base):
    __tablename__ = "document_analyses"
    id = Column(Integer, primary_key=True, index=True)
    filename_sanitized = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False, unique=True, index=True)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    pdf_version = Column(String(20), nullable=True)
    page_count = Column(Integer, nullable=True)
    analysis_status = Column(String(24), nullable=False, default="pending", index=True)
    is_encrypted = Column(Boolean, nullable=False, default=False)
    encryption_limited_analysis = Column(Boolean, nullable=False, default=False)
    has_javascript = Column(Boolean, nullable=False, default=False)
    has_open_action = Column(Boolean, nullable=False, default=False)
    has_additional_actions = Column(Boolean, nullable=False, default=False)
    has_launch_action = Column(Boolean, nullable=False, default=False)
    has_acroform = Column(Boolean, nullable=False, default=False)
    has_xfa = Column(Boolean, nullable=False, default=False)
    has_embedded_files = Column(Boolean, nullable=False, default=False)
    has_external_uris = Column(Boolean, nullable=False, default=False)
    external_uri_count = Column(Integer, nullable=False, default=0)
    embedded_file_count = Column(Integer, nullable=False, default=0)
    annotation_count = Column(Integer, nullable=False, default=0)
    metadata_json_redacted = Column(Text, nullable=False, default="{}")
    feature_summary_json = Column(Text, nullable=False, default="{}")
    extracted_text_character_count = Column(Integer, nullable=False, default=0)
    risk_score = Column(Float, nullable=False, default=0, index=True)
    classification = Column(String(40), nullable=False, default="unknown", index=True)
    confidence = Column(String(16), nullable=False, default="low")
    methodology = Column(Text, nullable=False)
    error_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    findings = relationship("DocumentFinding", back_populates="analysis", cascade="all, delete-orphan")
    indicators = relationship("DocumentIndicator", back_populates="analysis", cascade="all, delete-orphan")
    embedded_artifacts = relationship("DocumentEmbeddedArtifact", back_populates="analysis", cascade="all, delete-orphan")
    reports = relationship("DocumentReport", back_populates="analysis", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_document_analysis_status_created", "analysis_status", "created_at"),)


class DocumentFinding(Base):
    __tablename__ = "document_findings"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("document_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_code = Column(String(30), nullable=False, index=True)
    title = Column(String(240), nullable=False)
    category = Column(String(100), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(String(16), nullable=False, index=True)
    description = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    technical_impact = Column(Text, nullable=False)
    possible_business_impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    manual_validation_required = Column(Boolean, nullable=False, default=True)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("DocumentAnalysis", back_populates="findings")


class DocumentIndicator(Base):
    __tablename__ = "document_indicators"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("document_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(30), nullable=False, index=True)
    normalized_value = Column(String(2000), nullable=False)
    display_value_redacted = Column(String(2000), nullable=False)
    context = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(String(16), nullable=False)
    source_object = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("DocumentAnalysis", back_populates="indicators")
    __table_args__ = (UniqueConstraint("analysis_id", "indicator_type", "normalized_value", name="uq_document_indicator"),)


class DocumentEmbeddedArtifact(Base):
    __tablename__ = "document_embedded_artifacts"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("document_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    filename_sanitized = Column(String(255), nullable=False)
    extension = Column(String(30), nullable=True)
    declared_mime_type = Column(String(100), nullable=True)
    file_size = Column(Integer, nullable=True)
    sha256 = Column(String(64), nullable=True)
    artifact_type = Column(String(60), nullable=False)
    executable_like = Column(Boolean, nullable=False, default=False)
    archive_like = Column(Boolean, nullable=False, default=False)
    script_like = Column(Boolean, nullable=False, default=False)
    office_macro_like = Column(Boolean, nullable=False, default=False)
    risk_label = Column(String(40), nullable=False)
    evidence_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("DocumentAnalysis", back_populates="embedded_artifacts")


class DocumentReport(Base):
    __tablename__ = "document_reports"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("document_analyses.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(240), nullable=False)
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("DocumentAnalysis", back_populates="reports")
