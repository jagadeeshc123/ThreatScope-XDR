from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ConnectorDefinition:
    connector_type: str
    display_name: str
    category: str
    direction: str
    description: str
    supported_capabilities: tuple[str, ...]
    configuration_schema: dict
    credential_schema: dict
    supported_authentication_methods: tuple[str, ...]
    supported_event_types: tuple[str, ...]
    supported_payload_profiles: tuple[str, ...] = ("minimal", "standard", "extended")
    supports_test: bool = True
    supports_health_check: bool = True
    supports_delivery: bool = True
    supports_pull: bool = False
    supports_inbound_webhook: bool = False
    supports_ticket_create: bool = False
    supports_ticket_update: bool = False
    supports_secret_rotation: bool = True
    supports_idempotency: bool = True
    default_timeout_seconds: int = 15
    maximum_timeout_seconds: int = 60
    default_retry_limit: int = 5
    maximum_retry_limit: int = 7
    default_payload_limit: int = 262144
    maximum_payload_limit: int = 5242880
    default_response_limit: int = 524288
    maximum_response_limit: int = 5242880
    public_https_required: bool = True
    private_network_supported: bool = True
    system_owned: bool = True
    enabled_by_default: bool = False
    warning_message: str | None = None

    def to_dict(self):
        return asdict(self)


EVENT_TYPES = (
    "soc.alert.created", "soc.alert.updated", "case.created", "case.updated", "case.escalated", "case.closed",
    "phishing.high_risk", "document.high_risk", "threat_intel.match_confirmed", "detection.match_confirmed",
    "vulnerability.created", "vulnerability.escalated", "vulnerability.sla_breached", "vulnerability.verified",
    "soar.execution.proposed", "soar.execution.waiting_approval", "soar.execution.completed", "soar.execution.failed",
    "soar.rollback.failed", "connector.unhealthy", "connector.recovered",
)


def _schema(required=(), fields=()):
    return {"type": "object", "required": list(required), "properties": {name: {"type": kind} for name, kind in fields}, "additionalProperties": False}


def _def(key, name, category, direction, capabilities, config, credential, auth, **kwargs):
    return ConnectorDefinition(key, name, category, direction, kwargs.pop("description", name), tuple(capabilities), config, credential, tuple(auth), tuple(kwargs.pop("event_types", EVENT_TYPES)), **kwargs)


CONNECTOR_CATALOG = {
    "local_test_sink": _def("local_test_sink", "TEST SINK", "testing", "outbound", ("notify", "publish_event"), _schema(), _schema(), ("none",), public_https_required=False, private_network_supported=False, warning_message="Internal deterministic test sink only; no external request or containment is performed."),
    "generic_hmac_webhook_outbound": _def("generic_hmac_webhook_outbound", "Generic signed outbound webhook", "webhook", "outbound", ("notify", "publish_event"), _schema(("url",), (("url", "string"),)), _schema(("signing_secret",), (("signing_secret", "string"),)), ("hmac_signing",)),
    "generic_hmac_webhook_inbound": _def("generic_hmac_webhook_inbound", "Generic signed inbound webhook", "webhook", "inbound", ("receive", "quarantine", "promote"), _schema(), _schema(("signing_secret",), (("signing_secret", "string"),)), ("hmac_signing",), supports_delivery=False, supports_inbound_webhook=True),
    "slack_incoming_webhook": _def("slack_incoming_webhook", "Slack incoming webhook", "collaboration", "outbound", ("notify",), _schema(("url",), (("url", "string"),)), _schema(("webhook_url",), (("webhook_url", "string"),)), ("bearer_token",), warning_message="Only bounded, redacted summaries are sent; Slack bot OAuth is not supported."),
    "microsoft_teams_webhook": _def("microsoft_teams_webhook", "Microsoft Teams webhook", "collaboration", "outbound", ("notify",), _schema(("url",), (("url", "string"),)), _schema(("webhook_url",), (("webhook_url", "string"),)), ("bearer_token",), warning_message="Delegated Microsoft Graph authorization is not supported."),
    "smtp_email": _def("smtp_email", "SMTP email", "email", "outbound", ("notify",), _schema(("host", "port", "tls_mode", "sender_address", "allowed_recipient_domains"), (("host", "string"), ("port", "integer"), ("tls_mode", "string"), ("sender_address", "string"), ("allowed_recipient_domains", "array"))), _schema(("password",), (("username", "string"), ("password", "string"))), ("smtp_username_password",), maximum_payload_limit=102400),
    "jira_issue": _def("jira_issue", "Jira issue", "ticketing", "bidirectional", ("create_ticket", "update_ticket", "comment", "transition"), _schema(("base_url", "project_key", "issue_type"), (("base_url", "string"), ("project_key", "string"), ("issue_type", "string"), ("transition_ids", "array"))), _schema(("api_token",), (("username", "string"), ("api_token", "string"))), ("bearer_token", "basic_authentication"), supports_ticket_create=True, supports_ticket_update=True),
    "servicenow_incident": _def("servicenow_incident", "ServiceNow incident", "ticketing", "bidirectional", ("create_ticket", "update_ticket", "work_note"), _schema(("base_url", "table"), (("base_url", "string"), ("table", "string"), ("assignment_groups", "array"))), _schema(("token",), (("username", "string"), ("token", "string"))), ("bearer_token", "basic_authentication"), supports_ticket_create=True, supports_ticket_update=True),
    "splunk_hec": _def("splunk_hec", "Splunk HTTP Event Collector", "siem", "outbound", ("publish_event", "batch"), _schema(("url", "index_allowlist"), (("url", "string"), ("index_allowlist", "array"), ("source", "string"), ("sourcetype", "string"), ("acknowledgements_enabled", "boolean"))), _schema(("hec_token",), (("hec_token", "string"),)), ("bearer_token",)),
    "stix_bundle_import": _def("stix_bundle_import", "STIX 2.1 bundle import", "threat_intelligence", "import", ("preview", "promote"), _schema(), _schema(), ("none",), supports_delivery=False, supports_pull=False, supports_secret_rotation=False, public_https_required=False, private_network_supported=False),
    "taxii_21_collection_pull": _def("taxii_21_collection_pull", "TAXII 2.1 collection pull", "threat_intelligence", "import", ("pull", "preview", "promote"), _schema(("api_root_url", "collection_id"), (("api_root_url", "string"), ("collection_id", "string"))), _schema(("token",), (("username", "string"), ("token", "string"))), ("bearer_token", "basic_authentication", "oauth2_client_credentials"), supports_delivery=False, supports_pull=True),
}


AUTHENTICATION_METHODS = {"none", "bearer_token", "api_key_header", "basic_authentication", "hmac_signing", "oauth2_client_credentials", "smtp_username_password"}
SAFE_API_KEY_HEADERS = {"authorization", "x-api-key", "x-auth-token", "x-splunk-request-channel"}
