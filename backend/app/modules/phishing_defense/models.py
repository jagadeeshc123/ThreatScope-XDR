from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow(): return datetime.now(timezone.utc)


class PhishingAnalysis(Base):
    __tablename__ = "phishing_analyses"
    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String(24), nullable=False, index=True)
    source_hash = Column(String(64), nullable=False, unique=True, index=True)
    filename_sanitized = Column(String(255))
    subject_redacted = Column(String(500))
    sender_display_redacted = Column(String(300))
    sender_address_redacted = Column(String(320))
    reply_to_redacted = Column(String(320))
    return_path_redacted = Column(String(320))
    recipient_count = Column(Integer, nullable=False, default=0)
    url_count = Column(Integer, nullable=False, default=0)
    attachment_count = Column(Integer, nullable=False, default=0)
    html_present = Column(Boolean, nullable=False, default=False)
    authentication_results_present = Column(Boolean, nullable=False, default=False)
    header_summary_json = Column(Text, nullable=False, default="{}")
    feature_summary_json = Column(Text, nullable=False, default="{}")
    bounded_text_character_count = Column(Integer, nullable=False, default=0)
    model_probability = Column(Float)
    model_label = Column(String(32))
    heuristic_score = Column(Float, nullable=False, default=0)
    final_risk_score = Column(Float, nullable=False, default=0, index=True)
    classification = Column(String(32), nullable=False, default="unknown", index=True)
    confidence = Column(String(16), nullable=False, default="low")
    analyst_disposition = Column(String(24), nullable=False, default="unreviewed", index=True)
    analyst_notes = Column(Text)
    analysis_status = Column(String(24), nullable=False, default="pending", index=True)
    methodology = Column(Text, nullable=False)
    error_summary = Column(Text)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    completed_at = Column(DateTime)
    findings = relationship("PhishingFinding", back_populates="analysis", cascade="all, delete-orphan")
    indicators = relationship("PhishingIndicator", back_populates="analysis", cascade="all, delete-orphan")
    attachments = relationship("PhishingAttachmentMetadata", back_populates="analysis", cascade="all, delete-orphan")
    reports = relationship("PhishingReport", back_populates="analysis", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_phishing_status_created", "analysis_status", "created_at"), Index("ix_phishing_class_disposition", "classification", "analyst_disposition"))


class PhishingFinding(Base):
    __tablename__ = "phishing_findings"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("phishing_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_code = Column(String(24), nullable=False, index=True)
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
    analysis = relationship("PhishingAnalysis", back_populates="findings")


class PhishingIndicator(Base):
    __tablename__ = "phishing_indicators"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("phishing_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(30), nullable=False, index=True)
    normalized_value = Column(String(2000), nullable=False)
    display_value_redacted = Column(String(2000), nullable=False)
    context = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(String(16), nullable=False)
    source_location = Column(String(200))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("PhishingAnalysis", back_populates="indicators")
    __table_args__ = (UniqueConstraint("analysis_id", "indicator_type", "normalized_value", name="uq_phishing_indicator"),)


class PhishingAttachmentMetadata(Base):
    __tablename__ = "phishing_attachment_metadata"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("phishing_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    filename_sanitized = Column(String(255), nullable=False)
    extension = Column(String(30))
    declared_mime_type = Column(String(100))
    file_size = Column(Integer)
    sha256 = Column(String(64))
    executable_like = Column(Boolean, nullable=False, default=False)
    script_like = Column(Boolean, nullable=False, default=False)
    archive_like = Column(Boolean, nullable=False, default=False)
    macro_capable = Column(Boolean, nullable=False, default=False)
    double_extension = Column(Boolean, nullable=False, default=False)
    risk_label = Column(String(40), nullable=False)
    evidence_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("PhishingAnalysis", back_populates="attachments")


class PhishingWatchlistEntry(Base):
    __tablename__ = "phishing_watchlist"
    id = Column(Integer, primary_key=True)
    indicator_type = Column(String(30), nullable=False)
    normalized_value = Column(String(2000), nullable=False)
    display_value_redacted = Column(String(2000), nullable=False)
    reason = Column(Text, nullable=False)
    source_analysis_id = Column(Integer, ForeignKey("phishing_analyses.id", ondelete="SET NULL"), index=True)
    status = Column(String(16), nullable=False, default="active", index=True)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("indicator_type", "normalized_value", name="uq_phishing_watchlist_indicator"),)


class PhishingReport(Base):
    __tablename__ = "phishing_reports"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("phishing_analyses.id", ondelete="CASCADE"), index=True)
    title = Column(String(240), nullable=False)
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    analysis = relationship("PhishingAnalysis", back_populates="reports")
