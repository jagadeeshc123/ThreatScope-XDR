import hashlib
import re
from typing import Any

from app.modules.api_security.business_flows.validation_catalog import MANUAL_SUFFIX, VALIDATION_GUIDANCE


IDENTIFIER_RE = re.compile(r"\{[^}]*?(?:id|key|uuid|number)[^}]*\}", re.IGNORECASE)
PRIVILEGED_TERMS = ("admin", "role", "permission", "approve", "suspend", "internal")
SENSITIVE_TERMS = ("payment", "billing", "balance", "salary", "secret", "token", "password", "export", "report", "profile")
REPLAY_TERMS = ("payment", "transfer", "submit", "approve", "purchase", "order")


def _fingerprint(flow_id: int, step_id: int | None, risk_type: str) -> str:
    return hashlib.sha256(f"flow|{flow_id}|{step_id}|{risk_type}".encode()).hexdigest()


def _risk(flow: Any, step: Any, risk_type: str, title: str, severity: str, confidence: str, evidence: str, owasp: str) -> dict[str, Any]:
    return {
        "flow_id": flow.id,
        "step_id": step.id if step else None,
        "risk_type": risk_type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": title + "." + MANUAL_SUFFIX,
        "evidence_summary": evidence,
        "remediation": VALIDATION_GUIDANCE[risk_type],
        "manual_validation_required": True,
        "status": "open",
        "owasp_category": owasp,
        "fingerprint": _fingerprint(flow.id, step.id if step else None, risk_type),
    }


def analyze_flow_metadata(flow: Any) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    steps = sorted(flow.steps, key=lambda item: item.step_order)
    for index, step in enumerate(steps):
        endpoint = step.endpoint
        text = " ".join(filter(None, [step.action_name, step.prerequisite_description, endpoint.path if endpoint else None])).lower()

        if index > 0 and not step.prerequisite_description:
            risks.append(_risk(flow, step, "missing_prerequisite", "Step may be callable outside the documented order", "medium", "high", f"Step {step.step_order} has no documented prerequisite.", "API6:2023"))
        if step.sensitive_operation and (not step.expected_state_before or not step.expected_state_after):
            risks.append(_risk(flow, step, "missing_state_validation", "Sensitive operation lacks a complete transaction-state definition", "medium", "high", f"Step {step.step_order} is sensitive but its before/after state is incomplete.", "API6:2023"))

        privileged = any(term in text for term in PRIVILEGED_TERMS) or (endpoint and endpoint.method == "DELETE")
        role = (step.expected_actor_role or "").lower()
        if privileged and not any(term in role for term in ("admin", "privileged", "service")):
            risks.append(_risk(flow, step, "insufficient_role", "Privileged action may be assigned to an insufficient role", "high", "medium", f"Step {step.step_order} appears privileged; expected actor role is '{step.expected_actor_role or 'not documented'}'.", "API5:2023"))
        if step.sensitive_operation and (not endpoint or not endpoint.auth_required) and "authoriz" not in (step.prerequisite_description or "").lower():
            risks.append(_risk(flow, step, "missing_authorization", "Sensitive operation has no documented authorization gate", "high", "medium", f"Step {step.step_order} is sensitive and has no imported or configured authorization requirement.", "API5:2023"))
        if endpoint and endpoint.method == "DELETE" and "confirm" not in text:
            risks.append(_risk(flow, step, "missing_confirmation", "Irreversible action has no documented confirmation step", "medium", "medium", f"Step {step.step_order} links DELETE {endpoint.path} without confirmation metadata.", "API6:2023"))
        if endpoint and endpoint.method in {"POST", "PUT", "PATCH"} and any(term in text for term in REPLAY_TERMS) and not any(term in text for term in ("idempot", "nonce", "replay")):
            risks.append(_risk(flow, step, "replay_sensitive", "Replay-sensitive operation lacks documented idempotency controls", "medium", "low", f"Step {step.step_order} contains transaction terms without documented replay controls.", "API6:2023"))
        if any(term in text for term in ("client state", "client-controlled", "from client", "request state")):
            risks.append(_risk(flow, step, "client_state_trust", "Flow may rely excessively on client-controlled state", "medium", "medium", f"Step {step.step_order} describes client-provided workflow state.", "API8:2023"))
        if endpoint and IDENTIFIER_RE.search(endpoint.path) and not any(term in (step.prerequisite_description or "").lower() for term in ("own", "tenant", "organization", "assigned")):
            risks.append(_risk(flow, step, "missing_ownership", "Object step lacks a documented ownership or tenant requirement", "high" if step.sensitive_operation else "medium", "high", f"Step {step.step_order} links identifiable object path {endpoint.path} without scope metadata.", "API1:2023"))
        if index == 0 and endpoint and endpoint.method == "GET" and any(term in text for term in SENSITIVE_TERMS) and not step.prerequisite_description:
            risks.append(_risk(flow, step, "early_data_exposure", "Flow may expose restricted data before authorization gates", "medium", "low", f"The first step reads a sensitive path without a documented prerequisite.", "API3:2023"))
    return risks


def risk_score(risks: list[dict[str, Any]]) -> int:
    weights = {"info": 2, "low": 5, "medium": 12, "high": 22, "critical": 30}
    return min(100, sum(weights.get(item["severity"], 0) for item in risks))
