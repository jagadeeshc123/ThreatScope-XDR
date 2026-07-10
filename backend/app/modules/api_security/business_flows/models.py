from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base
from app.modules.api_security.models import utcnow


class ApiBusinessFlow(Base):
    __tablename__ = "api_business_flows"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("api_assessments.id"), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    description = Column(Text, nullable=False)
    business_goal = Column(Text, nullable=True)
    actor_roles_json = Column(Text, nullable=False, default="[]")
    status = Column(String(20), nullable=False, default="draft")
    risk_score = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    assessment = relationship("ApiAssessment", back_populates="business_flows")
    steps = relationship("ApiBusinessFlowStep", back_populates="flow", cascade="all, delete-orphan", order_by="ApiBusinessFlowStep.step_order")
    risks = relationship("ApiBusinessFlowRisk", back_populates="flow", cascade="all, delete-orphan")


class ApiBusinessFlowStep(Base):
    __tablename__ = "api_business_flow_steps"
    __table_args__ = (UniqueConstraint("flow_id", "step_order", name="uq_business_flow_step_order"),)

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(Integer, ForeignKey("api_business_flows.id"), nullable=False, index=True)
    step_order = Column(Integer, nullable=False)
    endpoint_id = Column(Integer, ForeignKey("api_endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    action_name = Column(String(200), nullable=False)
    expected_actor_role = Column(String(120), nullable=True)
    prerequisite_description = Column(Text, nullable=True)
    expected_state_before = Column(Text, nullable=True)
    expected_state_after = Column(Text, nullable=True)
    sensitive_operation = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    flow = relationship("ApiBusinessFlow", back_populates="steps")
    endpoint = relationship("ApiEndpoint")
    risks = relationship("ApiBusinessFlowRisk", back_populates="step")


class ApiBusinessFlowRisk(Base):
    __tablename__ = "api_business_flow_risks"
    __table_args__ = (UniqueConstraint("flow_id", "fingerprint", name="uq_business_flow_risk_fingerprint"),)

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(Integer, ForeignKey("api_business_flows.id"), nullable=False, index=True)
    step_id = Column(Integer, ForeignKey("api_business_flow_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    risk_type = Column(String(80), nullable=False)
    title = Column(String(240), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    manual_validation_required = Column(Boolean, nullable=False, default=True)
    status = Column(String(20), nullable=False, default="open")
    owasp_category = Column(String(30), nullable=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    flow = relationship("ApiBusinessFlow", back_populates="risks")
    step = relationship("ApiBusinessFlowStep", back_populates="risks")
