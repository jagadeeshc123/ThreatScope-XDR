from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Index

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ConnectorInstance(Base):
    __tablename__ = "integration_connectors"
    id = Column(Integer, primary_key=True)
    connector_uuid = Column(String(36), unique=True, nullable=False, index=True)
    connector_type = Column(String(80), nullable=False, index=True)
    name = Column(String(160), nullable=False)
    normalized_name = Column(String(160), unique=True, nullable=False)
    description = Column(Text)
    direction = Column(String(24), nullable=False)
    lifecycle_status = Column(String(24), default="draft", nullable=False, index=True)
    health_status = Column(String(24), default="unknown", nullable=False)
    configuration_json = Column(Text, default="{}", nullable=False)
    configuration_sha256 = Column(String(64), nullable=False)
    payload_profile = Column(String(20), default="minimal", nullable=False)
    timeout_seconds = Column(Integer, default=15, nullable=False)
    retry_limit = Column(Integer, default=5, nullable=False)
    enabled = Column(Boolean, default=False, nullable=False)
    system_owned = Column(Boolean, default=False, nullable=False)
    demo_owned = Column(Boolean, default=False, nullable=False)
    owner_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    activated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    last_tested_at = Column(DateTime)
    last_test_status = Column(String(24))
    last_health_check_at = Column(DateTime)
    last_success_at = Column(DateTime)
    last_failure_at = Column(DateTime)
    consecutive_failures = Column(Integer, default=0, nullable=False)
    circuit_state = Column(String(20), default="closed", nullable=False)
    circuit_opened_at = Column(DateTime)
    circuit_retry_at = Column(DateTime)
    optimistic_lock_version = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    archived_at = Column(DateTime)


class ConnectorCredential(Base):
    __tablename__ = "integration_connector_credentials"
    id = Column(Integer, primary_key=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False, unique=True)
    credential_type = Column(String(40), nullable=False)
    encrypted_payload = Column(Text, nullable=False)
    encryption_key_version = Column(String(40), default="v1", nullable=False)
    credential_version = Column(Integer, default=1, nullable=False)
    configured = Column(Boolean, default=True, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    rotated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    rotated_at = Column(DateTime)
    expires_at = Column(DateTime)
    disabled_at = Column(DateTime)


class ConnectorNetworkPolicy(Base):
    __tablename__ = "integration_network_policies"
    id = Column(Integer, primary_key=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False, unique=True)
    network_scope = Column(String(24), default="public_https", nullable=False)
    allowed_hosts_json = Column(Text, default="[]", nullable=False)
    allowed_ports_json = Column(Text, default="[443]", nullable=False)
    allowed_cidrs_json = Column(Text, default="[]", nullable=False)
    redirect_policy = Column(String(24), default="deny", nullable=False)
    maximum_response_bytes = Column(Integer, default=524288, nullable=False)
    maximum_request_bytes = Column(Integer, default=262144, nullable=False)
    reason = Column(Text)
    approved_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorFieldMapping(Base):
    __tablename__ = "integration_field_mappings"
    id = Column(Integer, primary_key=True)
    mapping_uuid = Column(String(36), unique=True, nullable=False)
    name = Column(String(160), nullable=False)
    direction = Column(String(20), nullable=False)
    source_schema = Column(String(80), nullable=False)
    target_schema = Column(String(80), nullable=False)
    mapping_json = Column(Text, nullable=False)
    validation_status = Column(String(20), default="pending", nullable=False)
    validation_summary_json = Column(Text)
    content_sha256 = Column(String(64), nullable=False)
    system_owned = Column(Boolean, default=False, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorSubscription(Base):
    __tablename__ = "integration_subscriptions"
    __table_args__ = (UniqueConstraint("connector_id", "name", "event_type", name="uq_integration_subscription"),)
    id = Column(Integer, primary_key=True)
    subscription_uuid = Column(String(36), unique=True, nullable=False)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(160), nullable=False)
    event_type = Column(String(100), nullable=False, index=True)
    source_module = Column(String(80))
    filter_json = Column(Text, default="{}", nullable=False)
    mapping_id = Column(Integer, ForeignKey("integration_field_mappings.id"))
    enabled = Column(Boolean, default=True, nullable=False)
    delivery_mode = Column(String(24), default="immediate_queue", nullable=False)
    digest_window_minutes = Column(Integer)
    minimum_severity = Column(String(20))
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class IntegrationOutboxEvent(Base):
    __tablename__ = "integration_outbox_events"
    id = Column(Integer, primary_key=True)
    event_uuid = Column(String(36), unique=True, nullable=False)
    event_type = Column(String(100), nullable=False, index=True)
    schema_version = Column(String(20), default="1.0", nullable=False)
    source_module = Column(String(80), nullable=False)
    source_entity_type = Column(String(80), nullable=False)
    source_entity_id = Column(String(100), nullable=False)
    correlation_id = Column(String(100))
    idempotency_key = Column(String(160), unique=True, nullable=False)
    canonical_event_json = Column(Text, nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    status = Column(String(24), default="pending", nullable=False, index=True)
    available_at = Column(DateTime, default=utcnow, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    processed_at = Column(DateTime)
    error_summary = Column(Text)


class ConnectorDelivery(Base):
    __tablename__ = "integration_deliveries"
    id = Column(Integer, primary_key=True)
    delivery_uuid = Column(String(36), unique=True, nullable=False)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False, index=True)
    subscription_id = Column(Integer, ForeignKey("integration_subscriptions.id"))
    outbox_event_id = Column(Integer, ForeignKey("integration_outbox_events.id"))
    soar_execution_id = Column(Integer, ForeignKey("soar_executions.id"))
    event_type = Column(String(100), nullable=False)
    external_operation = Column(String(30), nullable=False)
    idempotency_key = Column(String(180), unique=True, nullable=False)
    payload_json = Column(Text, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    payload_profile = Column(String(20), default="minimal", nullable=False)
    status = Column(String(32), default="queued", nullable=False, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    maximum_attempts = Column(Integer, default=5, nullable=False)
    next_attempt_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    external_reference = Column(String(200))
    external_reference_url = Column(Text)
    response_status_code = Column(Integer)
    response_summary = Column(Text)
    error_code = Column(String(80))
    error_summary = Column(Text)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorDeliveryAttempt(Base):
    __tablename__ = "integration_delivery_attempts"
    __table_args__ = (UniqueConstraint("delivery_id", "attempt_number", name="uq_integration_delivery_attempt"),)
    id = Column(Integer, primary_key=True)
    delivery_id = Column(Integer, ForeignKey("integration_deliveries.id", ondelete="CASCADE"), nullable=False)
    attempt_number = Column(Integer, nullable=False)
    status = Column(String(30), nullable=False)
    started_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime)
    destination_host = Column(String(253))
    resolved_address_summary = Column(String(300))
    request_size_bytes = Column(Integer, default=0, nullable=False)
    response_status_code = Column(Integer)
    response_size_bytes = Column(Integer)
    duration_ms = Column(Integer)
    error_code = Column(String(80))
    error_summary = Column(Text)
    retry_after_seconds = Column(Integer)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ConnectorDeadLetter(Base):
    __tablename__ = "integration_dead_letters"
    id = Column(Integer, primary_key=True)
    delivery_id = Column(Integer, ForeignKey("integration_deliveries.id"), nullable=False, unique=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False)
    reason_code = Column(String(80), nullable=False)
    reason_summary = Column(Text, nullable=False)
    payload_summary_json = Column(Text, nullable=False)
    final_attempt_number = Column(Integer, nullable=False)
    replay_status = Column(String(24), default="not_requested", nullable=False)
    replayed_delivery_id = Column(Integer, ForeignKey("integration_deliveries.id"))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    replay_requested_at = Column(DateTime)
    replay_requested_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))


class ConnectorInboundEndpoint(Base):
    __tablename__ = "integration_inbound_endpoints"
    id = Column(Integer, primary_key=True)
    endpoint_uuid = Column(String(36), unique=True, nullable=False, index=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False)
    name = Column(String(160), nullable=False)
    schema_version = Column(String(20), default="1.0", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    trusted_source = Column(Boolean, default=False, nullable=False)
    maximum_body_bytes = Column(Integer, default=524288, nullable=False)
    timestamp_tolerance_seconds = Column(Integer, default=300, nullable=False)
    replay_window_seconds = Column(Integer, default=900, nullable=False)
    allowed_event_types_json = Column(Text, default="[]", nullable=False)
    mapping_id = Column(Integer, ForeignKey("integration_field_mappings.id"))
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    disabled_at = Column(DateTime)


class ConnectorInboundEvent(Base):
    __tablename__ = "integration_inbound_events"
    __table_args__ = (UniqueConstraint("endpoint_id", "external_event_id", name="uq_integration_inbound_external_event"),)
    id = Column(Integer, primary_key=True)
    inbound_event_uuid = Column(String(36), unique=True, nullable=False)
    endpoint_id = Column(Integer, ForeignKey("integration_inbound_endpoints.id"), nullable=False)
    external_event_id = Column(String(160), nullable=False)
    schema_version = Column(String(20), nullable=False)
    received_at = Column(DateTime, default=utcnow, nullable=False)
    source_ip_summary = Column(String(100))
    content_type = Column(String(100), nullable=False)
    body_size_bytes = Column(Integer, nullable=False)
    signature_status = Column(String(24), nullable=False)
    replay_status = Column(String(24), nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    raw_payload_redacted_json = Column(Text, nullable=False)
    normalized_event_json = Column(Text)
    status = Column(String(24), default="quarantined", nullable=False, index=True)
    rejection_code = Column(String(80))
    rejection_summary = Column(Text)
    promoted_entity_type = Column(String(80))
    promoted_entity_id = Column(String(100))
    promoted_by_user_id = Column(Integer, ForeignKey("user_accounts.id"))
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorReplayNonce(Base):
    __tablename__ = "integration_replay_nonces"
    __table_args__ = (UniqueConstraint("endpoint_id", "nonce_hash", name="uq_integration_replay_nonce"),)
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("integration_inbound_endpoints.id", ondelete="CASCADE"), nullable=False)
    nonce_hash = Column(String(64), nullable=False)
    timestamp_bucket = Column(String(40), nullable=False)
    first_seen_at = Column(DateTime, default=utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)


class ConnectorInboundRateCounter(Base):
    __tablename__ = "integration_inbound_rate_counters"
    __table_args__ = (
        UniqueConstraint("scope", "key_hash", "bucket_start", name="uq_integration_inbound_rate_bucket"),
        Index("ix_integration_inbound_rate_expiry", "expires_at"),
    )
    id = Column(Integer, primary_key=True)
    scope = Column(String(32), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, index=True)
    bucket_start = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    request_count = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorHealthCheck(Base):
    __tablename__ = "integration_health_checks"
    id = Column(Integer, primary_key=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False)
    check_type = Column(String(24), nullable=False)
    status = Column(String(20), nullable=False)
    started_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime)
    duration_ms = Column(Integer)
    status_code = Column(Integer)
    summary = Column(Text, nullable=False)
    error_code = Column(String(80))
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ConnectorSyncCursor(Base):
    __tablename__ = "integration_sync_cursors"
    id = Column(Integer, primary_key=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False, unique=True)
    cursor_type = Column(String(40), nullable=False)
    cursor_value_encrypted_or_hashed = Column(Text, nullable=False)
    last_successful_sync_at = Column(DateTime)
    last_attempt_at = Column(DateTime)
    items_processed = Column(Integer, default=0, nullable=False)
    last_error_summary = Column(Text)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ConnectorExternalReference(Base):
    __tablename__ = "integration_external_references"
    __table_args__ = (UniqueConstraint("connector_id", "external_reference_id", name="uq_integration_external_reference"),)
    id = Column(Integer, primary_key=True)
    connector_id = Column(Integer, ForeignKey("integration_connectors.id"), nullable=False)
    external_system_type = Column(String(40), nullable=False)
    external_object_type = Column(String(40), nullable=False)
    external_reference_id = Column(String(200), nullable=False)
    safe_external_url = Column(Text)
    linked_entity_type = Column(String(80), nullable=False)
    linked_entity_id = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_synced_at = Column(DateTime)


class ConnectorReport(Base):
    __tablename__ = "integration_reports"
    id = Column(Integer, primary_key=True)
    report_uuid = Column(String(36), unique=True, nullable=False)
    title = Column(String(200), nullable=False)
    report_type = Column(String(60), nullable=False)
    filters_json = Column(Text, default="{}", nullable=False)
    summary_json = Column(Text, default="{}", nullable=False)
    html_content = Column(Text, nullable=False)
    generated_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class StixImportRun(Base):
    __tablename__ = "integration_stix_import_runs"
    id = Column(Integer, primary_key=True)
    import_uuid = Column(String(36), unique=True, nullable=False)
    status = Column(String(24), nullable=False)
    source_name = Column(String(160), nullable=False)
    content_sha256 = Column(String(64), nullable=False)
    object_count = Column(Integer, default=0, nullable=False)
    accepted_count = Column(Integer, default=0, nullable=False)
    quarantined_count = Column(Integer, default=0, nullable=False)
    preview_json = Column(Text, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("user_accounts.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    promoted_at = Column(DateTime)
