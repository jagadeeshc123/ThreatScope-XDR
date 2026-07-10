from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ApiAssessment(Base):
    __tablename__ = "api_assessments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String, nullable=False, default="manual")
    source_filename = Column(String, nullable=True)
    status = Column(String, nullable=False, default="draft")
    base_url = Column(String, nullable=True)
    api_version = Column(String, nullable=True)
    endpoint_count = Column(Integer, nullable=False, default=0)
    unauthenticated_endpoint_count = Column(Integer, nullable=False, default=0)
    high_risk_endpoint_count = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    endpoints = relationship("ApiEndpoint", back_populates="assessment", cascade="all, delete-orphan")
    artifacts = relationship("ApiImportArtifact", back_populates="assessment", cascade="all, delete-orphan")
    jwt_analyses = relationship("JwtAnalysis", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("ApiFinding", back_populates="assessment", cascade="all, delete-orphan")
    owasp_coverage = relationship("ApiOwaspCoverage", back_populates="assessment", cascade="all, delete-orphan")
    api_reports = relationship("ApiReport", back_populates="assessment", cascade="all, delete-orphan")
    api_roles = relationship("ApiRole", back_populates="assessment", cascade="all, delete-orphan")
    api_identities = relationship("ApiIdentity", back_populates="assessment", cascade="all, delete-orphan")
    authorization_matrix_entries = relationship("AuthorizationMatrixEntry", back_populates="assessment", cascade="all, delete-orphan")
    authorization_reviews = relationship("AuthorizationReview", back_populates="assessment", cascade="all, delete-orphan")
    business_flows = relationship("ApiBusinessFlow", back_populates="assessment", cascade="all, delete-orphan")


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    path = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, index=True)
    operation_id = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    auth_required = Column(Boolean, nullable=False, default=False)
    auth_schemes_json = Column(Text, nullable=True)
    request_content_types_json = Column(Text, nullable=True)
    response_content_types_json = Column(Text, nullable=True)
    parameters_json = Column(Text, nullable=True)
    tags_json = Column(Text, nullable=True)
    folder_path = Column(String, nullable=True)
    deprecated = Column(Boolean, nullable=False, default=False)
    preliminary_risk_level = Column(String, nullable=False, default="info", index=True)
    preliminary_risk_reasons_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    assessment = relationship("ApiAssessment", back_populates="endpoints")


class ApiImportArtifact(Base):
    __tablename__ = "api_import_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    artifact_type = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    redacted_content = Column(Text, nullable=False)
    parsed_summary_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    assessment = relationship("ApiAssessment", back_populates="artifacts")


class JwtAnalysis(Base):
    __tablename__ = "jwt_analyses"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=True, index=True)
    token_fingerprint = Column(String, nullable=False, index=True)
    header_json_redacted = Column(Text, nullable=False)
    payload_json_redacted = Column(Text, nullable=False)
    algorithm = Column(String, nullable=True)
    issuer = Column(String, nullable=True)
    audience_json = Column(Text, nullable=True)
    issued_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    not_before = Column(DateTime, nullable=True)
    expiration_status = Column(String, nullable=False, default="unknown")
    risk_score = Column(Integer, nullable=False, default=0)
    findings_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    assessment = relationship("ApiAssessment", back_populates="jwt_analyses")


class ApiFinding(Base):
    __tablename__ = "api_findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("api_endpoints.id"), nullable=True, index=True)
    title = Column(String, nullable=False)
    owasp_category = Column(String, nullable=True)
    severity = Column(String, nullable=False, default="info")
    confidence = Column(String, nullable=False, default="medium")
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    source = Column(String, nullable=False)
    fingerprint = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="findings")
    endpoint = relationship("ApiEndpoint")


class ApiOwaspCoverage(Base):
    __tablename__ = "api_owasp_coverage"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    category_id = Column(String, nullable=False, index=True)
    category_title = Column(String, nullable=False)
    status = Column(String, nullable=False, default="not_observed")
    finding_count = Column(Integer, nullable=False, default=0)
    evidence_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="owasp_coverage")


class ApiReport(Base):
    __tablename__ = "api_reports"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    title = Column(String, nullable=False)
    executive_summary = Column(Text, nullable=False)
    html_content = Column(Text, nullable=False)
    summary_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    assessment = relationship("ApiAssessment", back_populates="api_reports")
