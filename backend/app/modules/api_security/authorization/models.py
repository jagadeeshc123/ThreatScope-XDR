from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base
from app.modules.api_security.models import utcnow


class ApiRole(Base):
    __tablename__ = "api_roles"
    __table_args__ = (UniqueConstraint("assessment_id", "name", name="uq_api_role_assessment_name"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    privilege_level = Column(String(20), nullable=False, default="user")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="api_roles")
    identities = relationship("ApiIdentity", back_populates="role")
    matrix_entries = relationship("AuthorizationMatrixEntry", back_populates="role", cascade="all, delete-orphan")


class ApiIdentity(Base):
    __tablename__ = "api_identities"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    label = Column(String(160), nullable=False)
    role_id = Column(Integer, ForeignKey("api_roles.id", ondelete="SET NULL"), nullable=True, index=True)
    identity_type = Column(String(30), nullable=False, default="custom")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="api_identities")
    role = relationship("ApiRole", back_populates="identities")


class AuthorizationMatrixEntry(Base):
    __tablename__ = "authorization_matrix_entries"
    __table_args__ = (UniqueConstraint("assessment_id", "endpoint_id", "role_id", name="uq_authorization_matrix_cell"),)

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("api_endpoints.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("api_roles.id"), nullable=False, index=True)
    expected_access = Column(String(20), nullable=False, default="unknown")
    object_scope = Column(String(20), nullable=False, default="unknown")
    expected_conditions_json = Column(Text, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    review_status = Column(String(30), nullable=False, default="not_reviewed")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="authorization_matrix_entries")
    endpoint = relationship("ApiEndpoint")
    role = relationship("ApiRole", back_populates="matrix_entries")
    reviews = relationship("AuthorizationReview", back_populates="matrix_entry")


class AuthorizationReview(Base):
    __tablename__ = "authorization_reviews"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    endpoint_id = Column(Integer, ForeignKey("api_endpoints.id"), nullable=False, index=True)
    matrix_entry_id = Column(Integer, ForeignKey("authorization_matrix_entries.id", ondelete="SET NULL"), nullable=True, index=True)
    review_type = Column(String(30), nullable=False)
    expected_behavior = Column(Text, nullable=False)
    observed_metadata = Column(Text, nullable=False)
    risk_indicator = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    manual_validation_required = Column(Boolean, nullable=False, default=True)
    analyst_decision = Column(String(20), nullable=False, default="open")
    notes = Column(Text, nullable=True)
    validation_checklist_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="authorization_reviews")
    endpoint = relationship("ApiEndpoint")
    matrix_entry = relationship("AuthorizationMatrixEntry", back_populates="reviews")
