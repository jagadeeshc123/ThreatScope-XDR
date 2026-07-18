from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SoarActionPolicy(Base):
    __tablename__ = "soar_action_policies"
    id = Column(Integer, primary_key=True)
    action_key = Column(String(120), nullable=False, unique=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    automatic_local_allowed = Column(Boolean, nullable=False, default=False)
    approval_required_override = Column(Boolean)
    requester_approver_separation_required = Column(Boolean, nullable=False, default=False)
    maximum_retries_override = Column(Integer)
    notes = Column(String(2000))
    system_owned = Column(Boolean, nullable=False, default=True)
    updated_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id = Column(Integer, primary_key=True)
    playbook_uuid = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(200), nullable=False)
    normalized_name = Column(String(200), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=False, default="")
    category = Column(String(80), nullable=False, default="general", index=True)
    lifecycle_status = Column(String(20), nullable=False, default="draft", index=True)
    trigger_mode = Column(String(24), nullable=False, default="manual", index=True)
    severity_threshold = Column(String(16))
    enabled = Column(Boolean, nullable=False, default=True)
    system_owned = Column(Boolean, nullable=False, default=False)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    current_version = Column(Integer, nullable=False, default=1)
    owner_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"), index=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    activated_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    activated_at = Column(DateTime)
    disabled_at = Column(DateTime)
    archived_at = Column(DateTime)
    last_validated_at = Column(DateTime)
    validation_status = Column(String(20))
    validation_summary_json = Column(Text)
    last_executed_at = Column(DateTime)
    execution_count = Column(Integer, nullable=False, default=0)
    successful_execution_count = Column(Integer, nullable=False, default=0)
    failed_execution_count = Column(Integer, nullable=False, default=0)
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarPlaybookVersion(Base):
    __tablename__ = "soar_playbook_versions"
    __table_args__ = (UniqueConstraint("playbook_id", "version_number", name="uq_soar_playbook_version"),)
    id = Column(Integer, primary_key=True)
    playbook_id = Column(Integer, ForeignKey("soar_playbooks.id", ondelete="RESTRICT"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    definition_json = Column(Text, nullable=False)
    normalized_definition_json = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False, index=True)
    change_summary = Column(String(1000), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SoarPlaybookStep(Base):
    __tablename__ = "soar_playbook_steps"
    __table_args__ = (UniqueConstraint("playbook_id", "stable_step_key", name="uq_soar_playbook_step"),)
    id = Column(Integer, primary_key=True)
    playbook_id = Column(Integer, ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    stable_step_key = Column(String(100), nullable=False)
    step_type = Column(String(24), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(String(2000))
    action_key = Column(String(120))
    configuration_json = Column(Text, nullable=False, default="{}")
    input_mapping_json = Column(Text, nullable=False, default="{}")
    output_mapping_json = Column(Text, nullable=False, default="{}")
    position = Column(Integer, nullable=False)
    on_success_step_key = Column(String(100))
    on_failure_step_key = Column(String(100))
    on_timeout_step_key = Column(String(100))
    timeout_seconds = Column(Integer)
    max_retries = Column(Integer, nullable=False, default=0)
    retry_delay_seconds = Column(Integer, nullable=False, default=0)
    continue_on_failure = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarTriggerRule(Base):
    __tablename__ = "soar_trigger_rules"
    id = Column(Integer, primary_key=True)
    playbook_id = Column(Integer, ForeignKey("soar_playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    source_type = Column(String(32), nullable=False, index=True)
    conditions_json = Column(Text, nullable=False, default="{}")
    proposal_only = Column(Boolean, nullable=False, default=True)
    automatic_local = Column(Boolean, nullable=False, default=False)
    cooldown_minutes = Column(Integer, nullable=False, default=60)
    maximum_proposals_per_hour = Column(Integer, nullable=False, default=20)
    enabled = Column(Boolean, nullable=False, default=True)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarTriggerEvaluationRun(Base):
    __tablename__ = "soar_trigger_evaluation_runs"
    id = Column(Integer, primary_key=True)
    source_type = Column(String(32), nullable=False, index=True)
    source_entity_id = Column(Integer)
    status = Column(String(32), nullable=False, default="running")
    rules_evaluated = Column(Integer, nullable=False, default=0)
    rules_matched = Column(Integer, nullable=False, default=0)
    proposals_created = Column(Integer, nullable=False, default=0)
    automatic_executions_created = Column(Integer, nullable=False, default=0)
    duplicates_suppressed = Column(Integer, nullable=False, default=0)
    cooldown_suppressed = Column(Integer, nullable=False, default=0)
    errors_count = Column(Integer, nullable=False, default=0)
    error_summary_json = Column(Text, nullable=False, default="[]")
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    started_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)


class SoarExecution(Base):
    __tablename__ = "soar_executions"
    __table_args__ = (UniqueConstraint("playbook_id", "idempotency_key", name="uq_soar_execution_idempotency"), Index("ix_soar_execution_due", "status", "next_resume_at"))
    id = Column(Integer, primary_key=True)
    execution_uuid = Column(String(64), nullable=False, unique=True, index=True)
    playbook_id = Column(Integer, ForeignKey("soar_playbooks.id", ondelete="RESTRICT"), nullable=False, index=True)
    playbook_version = Column(Integer, nullable=False)
    trigger_rule_id = Column(Integer, ForeignKey("soar_trigger_rules.id", ondelete="SET NULL"))
    trigger_source_type = Column(String(32), nullable=False)
    trigger_source_id = Column(Integer)
    idempotency_key = Column(String(128), nullable=False)
    parent_execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="SET NULL"))
    mode = Column(String(20), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="queued", index=True)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    approved_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    current_step_key = Column(String(100))
    input_context_json = Column(Text, nullable=False, default="{}")
    variable_state_json = Column(Text, nullable=False, default="{}")
    output_summary_json = Column(Text, nullable=False, default="{}")
    warning_summary_json = Column(Text)
    error_code = Column(String(80))
    error_summary = Column(String(1000))
    records_created = Column(Integer, nullable=False, default=0)
    records_updated = Column(Integer, nullable=False, default=0)
    simulated_action_count = Column(Integer, nullable=False, default=0)
    retry_count = Column(Integer, nullable=False, default=0)
    optimistic_lock_version = Column(Integer, nullable=False, default=1)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    cancelled_at = Column(DateTime)
    cancellation_reason = Column(String(1000))
    expires_at = Column(DateTime, index=True)
    next_resume_at = Column(DateTime, index=True)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarStepExecution(Base):
    __tablename__ = "soar_step_executions"
    __table_args__ = (UniqueConstraint("execution_id", "idempotency_key", "attempt_number", name="uq_soar_step_attempt"),)
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_key = Column(String(100), nullable=False)
    step_name = Column(String(200), nullable=False)
    step_type = Column(String(24), nullable=False)
    action_key = Column(String(120))
    sequence_number = Column(Integer, nullable=False)
    attempt_number = Column(Integer, nullable=False, default=1)
    idempotency_key = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="pending")
    input_snapshot_json = Column(Text, nullable=False, default="{}")
    output_snapshot_json = Column(Text, nullable=False, default="{}")
    redacted_input_summary = Column(String(2000), nullable=False, default="")
    redacted_output_summary = Column(String(2000))
    error_code = Column(String(80))
    error_summary = Column(String(1000))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SoarExecutionEvent(Base):
    __tablename__ = "soar_execution_events"
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_execution_id = Column(Integer, ForeignKey("soar_step_executions.id", ondelete="SET NULL"))
    event_type = Column(String(80), nullable=False, index=True)
    previous_status = Column(String(32))
    new_status = Column(String(32))
    actor_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    summary = Column(String(1000), nullable=False)
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)


class SoarApproval(Base):
    __tablename__ = "soar_approvals"
    id = Column(Integer, primary_key=True)
    approval_uuid = Column(String(64), nullable=False, unique=True, index=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_execution_id = Column(Integer, ForeignKey("soar_step_executions.id", ondelete="SET NULL"))
    approval_type = Column(String(40), nullable=False, index=True)
    required_permission = Column(String(100), nullable=False)
    minimum_approvals = Column(Integer, nullable=False, default=1)
    requester_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    assigned_to_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    assigned_role_name = Column(String(100))
    status = Column(String(32), nullable=False, default="pending", index=True)
    request_reason = Column(String(2000), nullable=False)
    request_context_json = Column(Text, nullable=False, default="{}")
    separation_required = Column(Boolean, nullable=False, default=False)
    expires_at = Column(DateTime, index=True)
    decided_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)


class SoarApprovalDecision(Base):
    __tablename__ = "soar_approval_decisions"
    __table_args__ = (UniqueConstraint("approval_id", "decided_by_user_id", name="uq_soar_approval_decider"),)
    id = Column(Integer, primary_key=True)
    approval_id = Column(Integer, ForeignKey("soar_approvals.id", ondelete="CASCADE"), nullable=False, index=True)
    decision = Column(String(16), nullable=False)
    decided_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    decision_note = Column(String(2000), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SoarAnalystInput(Base):
    __tablename__ = "soar_analyst_inputs"
    id = Column(Integer, primary_key=True)
    input_uuid = Column(String(64), nullable=False, unique=True, index=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_execution_id = Column(Integer, ForeignKey("soar_step_executions.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=False)
    instructions = Column(String(4000), nullable=False)
    schema_json = Column(Text, nullable=False)
    response_json = Column(Text)
    required_fields_json = Column(Text, nullable=False, default="[]")
    requested_from_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    requested_from_role = Column(String(100))
    submitted_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    status = Column(String(20), nullable=False, default="pending", index=True)
    requested_at = Column(DateTime, nullable=False, default=utcnow)
    submitted_at = Column(DateTime)
    expires_at = Column(DateTime, index=True)


class SoarExecutionEvidence(Base):
    __tablename__ = "soar_execution_evidence"
    __table_args__ = (UniqueConstraint("execution_id", "content_sha256", name="uq_soar_execution_evidence"),)
    id = Column(Integer, primary_key=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_execution_id = Column(Integer, ForeignKey("soar_step_executions.id", ondelete="SET NULL"))
    evidence_type = Column(String(40), nullable=False)
    source_module = Column(String(40), nullable=False)
    source_entity_type = Column(String(60), nullable=False)
    source_entity_id = Column(Integer, nullable=False)
    summary = Column(String(2000), nullable=False)
    redacted_snapshot_json = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class SoarRollbackRecord(Base):
    __tablename__ = "soar_rollback_records"
    __table_args__ = (UniqueConstraint("source_step_execution_id", "compensating_action_key", name="uq_soar_step_compensation"),)
    id = Column(Integer, primary_key=True)
    rollback_uuid = Column(String(64), nullable=False, unique=True, index=True)
    execution_id = Column(Integer, ForeignKey("soar_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    source_step_execution_id = Column(Integer, ForeignKey("soar_step_executions.id", ondelete="RESTRICT"), nullable=False)
    compensating_action_key = Column(String(120))
    status = Column(String(32), nullable=False, default="proposed", index=True)
    before_state_json = Column(Text, nullable=False, default="{}")
    intended_after_state_json = Column(Text)
    actual_after_state_json = Column(Text)
    reason = Column(String(2000), nullable=False)
    requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    approved_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    executed_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="SET NULL"))
    error_summary = Column(String(1000))
    created_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime)


class SoarReport(Base):
    __tablename__ = "soar_reports"
    id = Column(Integer, primary_key=True)
    report_uuid = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(240), nullable=False)
    report_type = Column(String(40), nullable=False)
    filters_json = Column(Text, nullable=False, default="{}")
    summary_json = Column(Text, nullable=False, default="{}")
    html_content = Column(Text, nullable=False)
    generated_by_user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="RESTRICT"), nullable=False)
    demo_owned = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
