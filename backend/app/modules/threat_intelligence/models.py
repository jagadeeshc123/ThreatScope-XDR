from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ThreatIntelSource(Base):
    __tablename__ = "threat_intel_sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False, unique=True, index=True)
    description = Column(Text)
    source_type = Column(String(20), nullable=False, index=True)
    reliability = Column(Integer, nullable=False, default=50)
    default_confidence = Column(Integer, nullable=False, default=50)
    default_tlp = Column(String(16), nullable=False, default="amber")
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    system_owned = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    last_import_at = Column(DateTime)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("threat_intel_sources.id", ondelete="SET NULL"), index=True)
    indicator_type = Column(String(32), nullable=False, index=True)
    value = Column(String(2048), nullable=False)
    normalized_value = Column(String(2048), nullable=False)
    value_hash = Column(String(64), nullable=False, index=True)
    title = Column(String(240))
    description = Column(Text)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    confidence = Column(Integer, nullable=False, default=50, index=True)
    tlp = Column(String(16), nullable=False, default="amber", index=True)
    tags_json = Column(Text, nullable=False, default="[]")
    first_seen_at = Column(DateTime)
    last_seen_at = Column(DateTime)
    valid_from = Column(DateTime)
    valid_until = Column(DateTime, index=True)
    active = Column(Boolean, nullable=False, default=True, index=True)
    revoked = Column(Boolean, nullable=False, default=False, index=True)
    false_positive = Column(Boolean, nullable=False, default=False, index=True)
    externally_supplied = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    source = relationship("ThreatIntelSource")
    __table_args__ = (
        UniqueConstraint("indicator_type", "normalized_value", name="uq_threat_indicator_identity"),
        Index("ix_threat_indicator_lifecycle", "active", "revoked", "valid_until"),
    )


class ThreatIntelImport(Base):
    __tablename__ = "threat_intel_imports"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("threat_intel_sources.id", ondelete="RESTRICT"), nullable=False, index=True)
    filename = Column(String(255))
    format = Column(String(16), nullable=False)
    status = Column(String(24), nullable=False, default="processing", index=True)
    total_records = Column(Integer, nullable=False, default=0)
    accepted_records = Column(Integer, nullable=False, default=0)
    duplicate_records = Column(Integer, nullable=False, default=0)
    rejected_records = Column(Integer, nullable=False, default=0)
    warning_count = Column(Integer, nullable=False, default=0)
    error_summary_json = Column(Text, nullable=False, default="[]")
    file_sha256 = Column(String(64), nullable=False, index=True)
    imported_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False, index=True)
    started_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)


class IndicatorSighting(Base):
    __tablename__ = "indicator_sightings"
    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    module = Column(String(40), nullable=False, index=True)
    entity_type = Column(String(60), nullable=False)
    entity_id = Column(Integer, nullable=False)
    observed_value_hash = Column(String(64), nullable=False, index=True)
    observed_at = Column(DateTime, nullable=False)
    context_summary = Column(Text, nullable=False)
    confidence = Column(Integer, nullable=False, default=50)
    first_observed_at = Column(DateTime, nullable=False)
    last_observed_at = Column(DateTime, nullable=False)
    occurrence_count = Column(Integer, nullable=False, default=1)
    reviewed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    indicator = relationship("ThreatIndicator")
    __table_args__ = (UniqueConstraint("indicator_id", "module", "entity_type", "entity_id", "observed_value_hash", name="uq_indicator_sighting"),)


class IndicatorMatch(Base):
    __tablename__ = "indicator_matches"
    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    sighting_id = Column(Integer, ForeignKey("indicator_sightings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    match_type = Column(String(32), nullable=False)
    match_strength = Column(Integer, nullable=False)
    status = Column(String(24), nullable=False, default="new", index=True)
    risk_score = Column(Float, nullable=False, default=0, index=True)
    risk_factors_json = Column(Text, nullable=False, default="[]")
    analyst_note = Column(Text)
    reviewed_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    reviewed_at = Column(DateTime)
    case_id = Column(Integer, ForeignKey("incident_cases.id", ondelete="SET NULL"), index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    indicator = relationship("ThreatIndicator")
    sighting = relationship("IndicatorSighting")


class ThreatWatchlist(Base):
    __tablename__ = "threat_watchlists"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False, unique=True, index=True)
    description = Column(Text)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    severity_threshold = Column(String(16))
    system_owned = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    entries = relationship("ThreatWatchlistEntry", cascade="all, delete-orphan")


class ThreatWatchlistEntry(Base):
    __tablename__ = "threat_watchlist_entries"
    id = Column(Integer, primary_key=True)
    watchlist_id = Column(Integer, ForeignKey("threat_watchlists.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    added_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    added_at = Column(DateTime, nullable=False, default=utcnow)
    note = Column(Text)
    indicator = relationship("ThreatIndicator")
    __table_args__ = (UniqueConstraint("watchlist_id", "indicator_id", name="uq_threat_watchlist_entry"),)


class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, unique=True, index=True)
    description = Column(Text)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    confidence = Column(Integer, nullable=False, default=50)
    active = Column(Boolean, nullable=False, default=True, index=True)
    first_seen_at = Column(DateTime)
    last_seen_at = Column(DateTime)
    tags_json = Column(Text, nullable=False, default="[]")
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    indicators = relationship("ThreatCampaignIndicator", cascade="all, delete-orphan")


class ThreatCampaignIndicator(Base):
    __tablename__ = "threat_campaign_indicators"
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    added_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    added_at = Column(DateTime, nullable=False, default=utcnow)
    indicator = relationship("ThreatIndicator")
    __table_args__ = (UniqueConstraint("campaign_id", "indicator_id", name="uq_threat_campaign_indicator"),)


class IndicatorRelationship(Base):
    __tablename__ = "indicator_relationships"
    id = Column(Integer, primary_key=True)
    source_indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    target_indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(64), nullable=False)
    confidence = Column(Integer, nullable=False, default=50)
    description = Column(Text)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint("source_indicator_id", "target_indicator_id", "relationship_type", name="uq_indicator_relationship"),)


class ThreatCorrelationRun(Base):
    __tablename__ = "threat_correlation_runs"
    id = Column(Integer, primary_key=True)
    status = Column(String(24), nullable=False, default="running", index=True)
    records_examined = Column(Integer, nullable=False, default=0)
    sightings_created = Column(Integer, nullable=False, default=0)
    sightings_updated = Column(Integer, nullable=False, default=0)
    matches_created = Column(Integer, nullable=False, default=0)
    high_risk_matches = Column(Integer, nullable=False, default=0)
    error_summary_json = Column(Text, nullable=False, default="[]")
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    started_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)


class ThreatIntelReport(Base):
    __tablename__ = "threat_intel_reports"
    id = Column(Integer, primary_key=True)
    title = Column(String(240), nullable=False)
    report_type = Column(String(40), nullable=False, default="intelligence_summary")
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False, default="{}")
    defanged = Column(Boolean, nullable=False, default=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)

