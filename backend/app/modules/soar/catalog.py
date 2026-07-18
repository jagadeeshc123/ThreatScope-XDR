"""Immutable server-owned SOAR action catalog.

Only keys in ``ACTION_CATALOG`` can reach the dispatcher.  Definitions contain
data schemas, never callable/module/SQL/URL/command material.
"""
from dataclasses import asdict, dataclass


SAFETY_CLASSIFICATIONS = {"read_only", "harmless_local", "controlled_local", "sensitive_local", "simulation_only"}
EXECUTION_MODES = {"dry_run", "simulation", "live_local"}


@dataclass(frozen=True)
class ActionDefinition:
    action_key: str
    display_name: str
    category: str
    description: str
    safety_classification: str
    allowed_execution_modes: tuple[str, ...]
    required_permission: str
    approval_requirement: str
    administrator_approval_required: bool
    requester_approver_separation_required: bool
    input_schema: dict
    output_schema: dict
    timeout_seconds: int
    maximum_retries: int
    retryable_error_codes: tuple[str, ...]
    supports_idempotency: bool
    supports_compensation: bool
    compensating_action_key: str | None
    simulation_only: bool
    enabled_by_default: bool
    automatic_local_eligible: bool
    evidence_snapshot_supported: bool
    audit_event_type: str
    warning_message: str | None

    def public(self) -> dict:
        result = asdict(self)
        result["allowed_execution_modes"] = list(self.allowed_execution_modes)
        result["retryable_error_codes"] = list(self.retryable_error_codes)
        return result


ID_SCHEMA = {"type": "object", "properties": {"source_id": {"type": "integer", "minimum": 1}}, "required": ["source_id"], "additionalProperties": False}
TARGET_REASON_SCHEMA = {"type": "object", "properties": {"target": {"type": "string", "minLength": 1, "maxLength": 500}, "reason": {"type": "string", "minLength": 1, "maxLength": 2000}, "assumptions": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 500}}, "source_id": {"type": "integer", "minimum": 1}, "case_id": {"type": "integer", "minimum": 1}, "user_id": {"type": "integer", "minimum": 1}, "session_id": {"type": "integer", "minimum": 1}, "value": {}, "title": {"type": "string", "maxLength": 300}, "body": {"type": "string", "maxLength": 8000}, "owner_user_id": {"type": "integer", "minimum": 1}, "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]}, "status": {"type": "string", "maxLength": 40}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "properties": {"status": {"type": "string"}, "record_id": {"type": ["integer", "null"]}, "summary": {"type": "string"}}, "required": ["status", "summary"], "additionalProperties": True}


def _definition(key: str, name: str, category: str, safety: str, permission: str, *, compensation: str | None = None, auto: bool = False, evidence: bool = False) -> ActionDefinition:
    sensitive = safety == "sensitive_local"
    simulated = safety == "simulation_only"
    read_only = safety == "read_only"
    allowed = ("dry_run", "simulation", "live_local") if not simulated else ("dry_run", "simulation")
    approval = "administrator" if sensitive else ("explicit" if simulated else "policy")
    warning = "SIMULATION ONLY — NO EXTERNAL ACTION IS PERFORMED" if simulated else ("ADMINISTRATOR APPROVAL REQUIRED" if sensitive else None)
    return ActionDefinition(
        action_key=key, display_name=name, category=category,
        description=(f"Reads bounded, permission-filtered {name.lower()} data without mutation." if read_only else (f"Records the intended {name.lower()} operation; no external infrastructure is modified." if simulated else f"Performs the allowlisted ThreatScope-local operation: {name.lower()}.")),
        safety_classification=safety, allowed_execution_modes=allowed, required_permission=permission,
        approval_requirement=approval, administrator_approval_required=sensitive,
        requester_approver_separation_required=sensitive, input_schema=ID_SCHEMA if read_only else TARGET_REASON_SCHEMA,
        output_schema=OUTPUT_SCHEMA, timeout_seconds=30, maximum_retries=0 if sensitive or simulated else 3,
        retryable_error_codes=() if sensitive or simulated else ("SOAR_EXECUTION_CONFLICT",), supports_idempotency=True,
        supports_compensation=compensation is not None, compensating_action_key=compensation, simulation_only=simulated,
        enabled_by_default=True, automatic_local_eligible=(read_only or auto) and not sensitive and not simulated,
        evidence_snapshot_supported=evidence or read_only, audit_event_type=f"soar_action_{key}", warning_message=warning,
    )


_READ_ONLY = [
    ("load_soc_alert_context", "Load SOC alert context", "soc", "soc:read"),
    ("load_incident_case_context", "Load incident-case context", "cases", "cases:read"),
    ("load_detection_match_context", "Load detection-match context", "detections", "detections:view"),
    ("load_threat_intelligence_match_context", "Load threat-intelligence-match context", "threat_intelligence", "threat_intel:view"),
    ("load_vulnerability_context", "Load vulnerability context", "vulnerability", "vulnerabilities:view"),
    ("load_phishing_analysis_context", "Load phishing-analysis context", "phishing", "phishing:read"),
    ("load_document_analysis_context", "Load document-analysis context", "documents", "document:read"),
    ("load_user_security_context", "Load user security context", "identity", "soar:sensitive_actions"),
    ("load_session_metadata", "Load session metadata", "identity", "soar:sensitive_actions"),
    ("load_asset_context", "Load asset context", "assets", "assets:view"),
    ("calculate_workflow_risk_summary", "Calculate current workflow risk summary", "workflow", "soar:view"),
    ("check_existing_case_link", "Check existing case link", "cases", "cases:read"),
    ("check_existing_remediation_task", "Check existing remediation task", "vulnerability", "vulnerabilities:view"),
    ("check_existing_notification", "Check existing notification", "workflow", "notifications:read"),
    ("check_current_ownership", "Check current ownership", "workflow", "soar:view"),
]

_LOCAL = [
    ("create_incident_case", "Create incident case", "cases", "controlled_local", "cases:create", None, False, True),
    ("reuse_incident_case", "Reuse incident case by idempotency key", "cases", "read_only", "cases:read", None, False, False),
    ("assign_case_owner", "Assign case owner", "cases", "controlled_local", "cases:manage", "restore_case_owner", False, False),
    ("change_case_severity", "Change case severity", "cases", "controlled_local", "cases:manage", "restore_case_severity", False, False),
    ("add_case_comment", "Add case comment", "cases", "harmless_local", "cases:manage", None, True, False),
    ("add_case_evidence", "Add case evidence", "cases", "harmless_local", "cases:manage", None, True, True),
    ("add_case_tag", "Add case tag", "cases", "harmless_local", "cases:manage", "remove_case_tag", True, False),
    ("link_soc_alert_to_case", "Link SOC alert", "cases", "harmless_local", "cases:manage", None, True, True),
    ("link_detection_match_to_case", "Link detection match", "detections", "harmless_local", "detections:review", None, True, True),
    ("link_threat_intelligence_match_to_case", "Link threat-intelligence match", "threat_intelligence", "harmless_local", "threat_intel:manage", None, True, True),
    ("link_vulnerability_to_case", "Link vulnerability", "vulnerability", "harmless_local", "vulnerabilities:triage", None, True, True),
    ("link_phishing_analysis_to_case", "Link phishing analysis", "phishing", "harmless_local", "phishing:manage_disposition", None, True, True),
    ("link_document_analysis_to_case", "Link document analysis", "documents", "harmless_local", "document:analyze", None, True, True),
    ("create_investigation_checklist_item", "Create investigation checklist item", "cases", "harmless_local", "cases:manage", "cancel_case_task", True, False),
    ("create_case_follow_up_task", "Create case follow-up task", "cases", "harmless_local", "cases:manage", "cancel_case_task", True, False),
    ("transition_case_lifecycle", "Perform valid case lifecycle transition", "cases", "controlled_local", "cases:manage", "restore_case_status", False, False),
    ("mark_soc_alert_reviewing", "Mark alert as reviewing", "soc", "controlled_local", "soc:manage_alerts", None, False, False),
    ("add_soc_alert_note", "Add analyst note to alert", "soc", "harmless_local", "soc:manage_alerts", None, True, False),
    ("create_alert_review_task", "Create alert-review task", "soc", "harmless_local", "soc:manage_alerts", "cancel_case_task", True, False),
    ("create_detection_suppression_proposal", "Create detection-suppression proposal", "detections", "harmless_local", "detections:review", None, True, False),
    ("create_analyst_review_task", "Create analyst-review task", "workflow", "harmless_local", "soar:review", "cancel_case_task", True, False),
    ("add_indicator_to_watchlist", "Add indicator to existing watchlist", "threat_intelligence", "controlled_local", "threat_intel:manage", None, False, False),
    ("create_ioc_review_task", "Create IOC analyst-review task", "threat_intelligence", "harmless_local", "threat_intel:manage", "cancel_case_task", True, False),
    ("assign_vulnerability", "Assign vulnerability", "vulnerability", "controlled_local", "vulnerabilities:triage", "restore_vulnerability_owner", False, False),
    ("add_vulnerability_comment", "Add vulnerability comment", "vulnerability", "harmless_local", "vulnerabilities:triage", None, True, False),
    ("create_remediation_plan_draft", "Create remediation-plan draft", "vulnerability", "controlled_local", "vulnerabilities:remediate", None, False, False),
    ("create_remediation_task", "Create remediation task", "vulnerability", "controlled_local", "vulnerabilities:remediate", "cancel_remediation_task", False, False),
    ("request_vulnerability_verification", "Request vulnerability verification", "vulnerability", "controlled_local", "vulnerabilities:verify", None, False, False),
    ("create_risk_acceptance_proposal", "Create risk-acceptance proposal", "vulnerability", "controlled_local", "vulnerabilities:accept_risk", None, False, False),
    ("create_internal_notification", "Create internal notification", "workflow", "harmless_local", "soar:execute", None, True, False),
    ("assign_internal_task", "Assign internal task", "workflow", "controlled_local", "soar:review", None, False, False),
    ("add_supported_record_tag", "Add tag to supported record", "workflow", "harmless_local", "soar:execute", None, True, False),
    ("capture_evidence_snapshot", "Capture audit-safe evidence snapshot", "workflow", "harmless_local", "soar:execute", None, True, True),
    ("revoke_selected_session", "Revoke selected ThreatScope session", "identity", "sensitive_local", "soar:sensitive_actions", None, False, False),
    ("revoke_other_user_sessions", "Revoke all other ThreatScope sessions", "identity", "sensitive_local", "soar:sensitive_actions", None, False, False),
    ("temporarily_disable_user", "Temporarily disable ThreatScope user", "identity", "sensitive_local", "soar:sensitive_actions", "reenable_user", False, False),
    ("reenable_user", "Re-enable ThreatScope user", "identity", "sensitive_local", "soar:sensitive_actions", None, False, False),
]

_SIMULATION = [
    ("simulate_block_ip", "Simulate block IP"), ("simulate_block_domain", "Simulate block domain"),
    ("simulate_block_url", "Simulate block URL"), ("simulate_quarantine_endpoint", "Simulate quarantine endpoint"),
    ("simulate_isolate_host", "Simulate isolate host"), ("simulate_disable_external_account", "Simulate disable external account"),
    ("simulate_revoke_external_token", "Simulate revoke external token"), ("simulate_remove_malicious_email", "Simulate remove malicious email"),
    ("simulate_update_firewall_rule", "Simulate update firewall rule"), ("simulate_update_waf_rule", "Simulate update WAF rule"),
    ("simulate_update_dns_blocklist", "Simulate update DNS blocklist"), ("simulate_update_proxy_blocklist", "Simulate update proxy blocklist"),
    ("simulate_update_edr_policy", "Simulate update EDR policy"), ("simulate_terminate_malicious_process", "Simulate terminate malicious process"),
    ("simulate_quarantine_malicious_file", "Simulate quarantine malicious file"),
]

_COMPENSATIONS = [
    ("restore_case_owner", "Restore previous case owner", "cases", "cases:manage"),
    ("restore_case_severity", "Restore previous case severity", "cases", "cases:manage"),
    ("restore_case_status", "Restore previous valid case status", "cases", "cases:manage"),
    ("remove_case_tag", "Remove execution-added case tag", "cases", "cases:manage"),
    ("cancel_case_task", "Cancel execution-created case task", "cases", "cases:manage"),
    ("restore_vulnerability_owner", "Restore previous vulnerability owner", "vulnerability", "vulnerabilities:triage"),
    ("cancel_remediation_task", "Cancel execution-created remediation task", "vulnerability", "vulnerabilities:remediate"),
    ("restore_playbook_enabled_state", "Restore playbook enabled state", "soar", "soar:manage"),
]


ACTION_CATALOG: dict[str, ActionDefinition] = {}
for key, name, category, permission in _READ_ONLY:
    ACTION_CATALOG[key] = _definition(key, name, category, "read_only", permission)
for key, name, category, safety, permission, compensation, auto, evidence in _LOCAL:
    ACTION_CATALOG[key] = _definition(key, name, category, safety, permission, compensation=compensation, auto=auto, evidence=evidence)
for key, name in _SIMULATION:
    ACTION_CATALOG[key] = _definition(key, name, "simulated_containment", "simulation_only", "soar:execute")
for key, name, category, permission in _COMPENSATIONS:
    ACTION_CATALOG[key] = _definition(key, name, category, "controlled_local", permission)


def get_action(action_key: str) -> ActionDefinition | None:
    return ACTION_CATALOG.get(action_key)


def catalog_response() -> list[dict]:
    return [ACTION_CATALOG[key].public() for key in sorted(ACTION_CATALOG)]
