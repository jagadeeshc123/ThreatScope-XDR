from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True)
    rule_uuid = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(240), nullable=False, index=True)
    description = Column(Text, nullable=False, default="")
    rule_format = Column(String(20), nullable=False, default="native", index=True)
    lifecycle_status = Column(String(20), nullable=False, default="draft", index=True)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    confidence = Column(Integer, nullable=False, default=50)
    source_module = Column(String(40), index=True)
    logsource_category = Column(String(80))
    logsource_product = Column(String(80))
    logsource_service = Column(String(80))
    rule_content_json = Column(Text, nullable=False)
    normalized_condition_json = Column(Text, nullable=False)
    false_positive_guidance = Column(Text)
    tags_json = Column(Text, nullable=False, default="[]")
    enabled = Column(Boolean, nullable=False, default=False, index=True)
    system_owned = Column(Boolean, nullable=False, default=False)
    current_version = Column(Integer, nullable=False, default=1)
    quality_score = Column(Float, nullable=False, default=0, index=True)
    owner_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    last_validated_at = Column(DateTime)
    last_executed_at = Column(DateTime)
    versions = relationship("DetectionRuleVersion", cascade="all, delete-orphan", order_by="DetectionRuleVersion.version_number")
    tests = relationship("DetectionTestCase", cascade="all, delete-orphan")


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    change_summary = Column(String(500), nullable=False)
    rule_content_json = Column(Text, nullable=False)
    normalized_condition_json = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint("rule_id", "version_number", name="uq_detection_rule_version"),)


class DetectionRulePack(Base):
    __tablename__ = "detection_rule_packs"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False, unique=True, index=True)
    description = Column(Text)
    version = Column(String(40), nullable=False, default="1.0")
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    system_owned = Column(Boolean, nullable=False, default=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    entries = relationship("DetectionRulePackEntry", cascade="all, delete-orphan")


class DetectionRulePackEntry(Base):
    __tablename__ = "detection_rule_pack_entries"
    id = Column(Integer, primary_key=True)
    pack_id = Column(Integer, ForeignKey("detection_rule_packs.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    added_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    added_at = Column(DateTime, nullable=False, default=utcnow)
    rule = relationship("DetectionRule")
    __table_args__ = (UniqueConstraint("pack_id", "rule_id", name="uq_detection_pack_rule"),)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    id = Column(Integer, primary_key=True)
    external_id = Column(String(20), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False)
    tactic = Column(String(80), nullable=False, index=True)
    description = Column(Text)
    platform_tags_json = Column(Text, nullable=False, default="[]")
    system_owned = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class DetectionRuleTechnique(Base):
    __tablename__ = "detection_rule_techniques"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False, index=True)
    mapping_confidence = Column(Integer, nullable=False, default=50)
    mapping_source = Column(String(20), nullable=False, default="manual")
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    created_at = Column(DateTime, nullable=False, default=utcnow)
    technique = relationship("AttackTechnique")
    __table_args__ = (UniqueConstraint("rule_id", "technique_id", name="uq_detection_rule_technique"),)


class DetectionTestCase(Base):
    __tablename__ = "detection_test_cases"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    description = Column(Text)
    event_payload_json = Column(Text, nullable=False)
    expected_match = Column(Boolean, nullable=False)
    expected_severity = Column(String(16))
    enabled = Column(Boolean, nullable=False, default=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class DetectionExecution(Base):
    __tablename__ = "detection_executions"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="SET NULL"), index=True)
    pack_id = Column(Integer, ForeignKey("detection_rule_packs.id", ondelete="SET NULL"), index=True)
    status = Column(String(20), nullable=False, default="queued", index=True)
    mode = Column(String(20), nullable=False, default="historical", index=True)
    records_scanned = Column(Integer, nullable=False, default=0)
    matches_found = Column(Integer, nullable=False, default=0)
    suppressed_matches = Column(Integer, nullable=False, default=0)
    errors_count = Column(Integer, nullable=False, default=0)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    started_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)
    error_summary = Column(Text)
    parameters_json = Column(Text, nullable=False, default="{}")


class DetectionMatch(Base):
    __tablename__ = "detection_matches"
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey("detection_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_version = Column(Integer, nullable=False)
    source_module = Column(String(40), nullable=False, index=True)
    source_entity_type = Column(String(60), nullable=False)
    source_entity_id = Column(Integer, nullable=False)
    event_timestamp = Column(DateTime, nullable=False, index=True)
    matched_fields_json = Column(Text, nullable=False, default="{}")
    evidence_summary = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    confidence = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=False, default=0, index=True)
    status = Column(String(20), nullable=False, default="new", index=True)
    reviewed_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    reviewed_at = Column(DateTime)
    analyst_note = Column(Text)
    alert_id = Column(Integer, ForeignKey("soc_alerts.id", ondelete="SET NULL"), index=True)
    case_id = Column(Integer, ForeignKey("incident_cases.id", ondelete="SET NULL"), index=True)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    rule = relationship("DetectionRule")
    execution = relationship("DetectionExecution")
    __table_args__ = (Index("ix_detection_match_source", "source_module", "source_entity_type", "source_entity_id"),)


class DetectionSuppression(Base):
    __tablename__ = "detection_suppressions"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), nullable=False)
    description = Column(Text, nullable=False)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    field_conditions_json = Column(Text, nullable=False)
    valid_from = Column(DateTime)
    valid_until = Column(DateTime, index=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class DetectionReport(Base):
    __tablename__ = "detection_reports"
    id = Column(Integer, primary_key=True)
    title = Column(String(240), nullable=False)
    report_type = Column(String(40), nullable=False, default="detection_summary")
    filters_json = Column(Text, nullable=False, default="{}")
    summary_json = Column(Text, nullable=False, default="{}")
    html_content = Column(Text, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
