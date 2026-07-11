from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class SocLogSource(Base):
    __tablename__ = "soc_log_sources"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False, index=True)
    description = Column(Text, nullable=True)
    source_type = Column(String(32), nullable=False)
    parser_type = Column(String(32), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    event_count = Column(Integer, nullable=False, default=0)
    last_ingested_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    imports = relationship("SocLogImport", back_populates="source")
    events = relationship("SocEvent", back_populates="source")


class SocLogImport(Base):
    __tablename__ = "soc_log_imports"
    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("soc_log_sources.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=True)
    file_hash = Column(String(64), nullable=True, index=True)
    total_lines = Column(Integer, nullable=False, default=0)
    accepted_events = Column(Integer, nullable=False, default=0)
    rejected_events = Column(Integer, nullable=False, default=0)
    status = Column(String(24), nullable=False, default="pending")
    error_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    source = relationship("SocLogSource", back_populates="imports")
    events = relationship("SocEvent", back_populates="log_import")


class SocEvent(Base):
    __tablename__ = "soc_events"
    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("soc_log_sources.id"), nullable=False, index=True)
    import_id = Column(Integer, ForeignKey("soc_log_imports.id"), nullable=True, index=True)
    event_time = Column(DateTime, nullable=False, index=True)
    received_at = Column(DateTime, default=utcnow, nullable=False)
    event_type = Column(String(40), nullable=False, index=True)
    action = Column(String(120), nullable=True)
    outcome = Column(String(24), nullable=True, index=True)
    severity = Column(String(16), nullable=False, default="info")
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True)
    username = Column(String(160), nullable=True, index=True)
    http_method = Column(String(16), nullable=True)
    request_path = Column(String(1000), nullable=True)
    status_code = Column(Integer, nullable=True, index=True)
    user_agent = Column(String(1000), nullable=True)
    message = Column(Text, nullable=True)
    normalized_json = Column(Text, nullable=False)
    raw_event_hash = Column(String(64), nullable=False, unique=True, index=True)
    raw_preview_redacted = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    source = relationship("SocLogSource", back_populates="events")
    log_import = relationship("SocLogImport", back_populates="events")
    alert_links = relationship("SocAlertEvent", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_soc_events_time_source", "event_time", "source_id"),
        Index("ix_soc_events_type_outcome", "event_type", "outcome"),
    )


class SocDetectionRule(Base):
    __tablename__ = "soc_detection_rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_code = Column(String(40), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    rule_type = Column(String(80), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    severity = Column(String(16), nullable=False)
    confidence = Column(String(16), nullable=False)
    window_seconds = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)
    group_by = Column(String(40), nullable=False)
    conditions_json = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    is_default = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    alerts = relationship("SocAlert", back_populates="rule")


class SocAlert(Base):
    __tablename__ = "soc_alerts"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("soc_detection_rules.id"), nullable=False, index=True)
    title = Column(String(240), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(String(16), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="open", index=True)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    event_count = Column(Integer, nullable=False)
    correlation_key = Column(String(300), nullable=False, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    username = Column(String(160), nullable=True, index=True)
    evidence_summary = Column(Text, nullable=False)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    rule = relationship("SocDetectionRule", back_populates="alerts")
    event_links = relationship("SocAlertEvent", back_populates="alert", cascade="all, delete-orphan")
    enrichments = relationship("SocThreatIntelResult", back_populates="alert", cascade="all, delete-orphan")


class SocAlertEvent(Base):
    __tablename__ = "soc_alert_events"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("soc_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("soc_events.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    alert = relationship("SocAlert", back_populates="event_links")
    event = relationship("SocEvent", back_populates="alert_links")
    __table_args__ = (UniqueConstraint("alert_id", "event_id", name="uq_soc_alert_event"),)


class SocThreatIntelResult(Base):
    __tablename__ = "soc_threat_intel_results"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("soc_alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_type = Column(String(20), nullable=False)
    indicator_value = Column(String(500), nullable=False, index=True)
    reputation = Column(String(20), nullable=False)
    confidence = Column(String(16), nullable=False)
    tags_json = Column(Text, nullable=False, default="[]")
    source_name = Column(String(80), nullable=False, default="local_mock_intelligence")
    explanation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    alert = relationship("SocAlert", back_populates="enrichments")


class SocBlocklistEntry(Base):
    __tablename__ = "soc_blocklist_entries"
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(20), nullable=False)
    indicator_value = Column(String(500), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    source_alert_id = Column(Integer, ForeignKey("soc_alerts.id"), nullable=True, index=True)
    status = Column(String(20), nullable=False, default="active", index=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    source_alert = relationship("SocAlert")
    __table_args__ = (UniqueConstraint("indicator_type", "indicator_value", name="uq_soc_blocklist_indicator"),)


class SocReport(Base):
    __tablename__ = "soc_reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(240), nullable=False)
    report_type = Column(String(40), nullable=False, default="soc_summary")
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class SocActivity(Base):
    __tablename__ = "soc_activities"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(80), nullable=False, index=True)
    message = Column(Text, nullable=False)
    entity_type = Column(String(40), nullable=False)
    entity_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)

