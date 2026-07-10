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

