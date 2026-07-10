import re
from typing import Any

from app.modules.api_security.inventory import loads_json
from app.modules.api_security.response_exposure import response_exposure_review
from app.modules.api_security.authorization.templates import (
    FUNCTION_LEVEL_CHECKLIST,
    OBJECT_LEVEL_CHECKLIST,
    PROPERTY_LEVEL_CHECKLIST,
)


IDENTIFIER_RE = re.compile(r"\{([^}]*?(?:id|key|uuid|number)[^}]*)\}", re.IGNORECASE)
PRIVILEGED_TERMS = ("admin", "role", "permission", "privilege", "internal", "service", "approve", "suspend")
SENSITIVE_FIELDS = ("role", "permission", "status", "balance", "salary", "internal", "secret", "token", "password", "credit", "ssn")
DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "PUT"}


def _base(endpoint: Any, review_type: str, expected: str, indicator: str, severity: str, confidence: str, checklist: list[str]) -> dict[str, Any]:
    return {
        "assessment_id": endpoint.assessment_id,
        "endpoint_id": endpoint.id,
        "review_type": review_type,
        "expected_behavior": expected,
        "observed_metadata": f"Imported metadata for {endpoint.method} {endpoint.path}.",
        "risk_indicator": indicator + " This is a potential authorization review item; runtime behavior was not tested.",
        "severity": severity,
        "confidence": confidence,
        "manual_validation_required": True,
        "analyst_decision": "open",
        "validation_checklist": checklist,
    }


def authorization_review_candidates(assessment: Any) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    exposure_by_endpoint: dict[int, list[str]] = {}
    for exposure in response_exposure_review(assessment):
        endpoint_id = exposure.get("endpoint_id")
        if endpoint_id:
            exposure_by_endpoint.setdefault(endpoint_id, []).append(exposure["field_path"])

    for endpoint in assessment.endpoints:
        identifiers = IDENTIFIER_RE.findall(endpoint.path)
        lower_path = endpoint.path.lower()
        if identifiers:
            scope = "tenant or organization" if any(term in lower_path for term in ("tenant", "organization", "org")) else "own or assigned"
            candidates.append(_base(
                endpoint,
                "object_level",
                f"Access should be constrained to the documented {scope} object scope.",
                f"Potential API1 object-level review for identifier(s): {', '.join(identifiers)}.",
                "high" if endpoint.method in DESTRUCTIVE_METHODS else "medium",
                "high",
                OBJECT_LEVEL_CHECKLIST,
            ))

        privileged = [term for term in PRIVILEGED_TERMS if term in lower_path]
        if privileged or endpoint.method == "DELETE":
            minimum_role = "admin or privileged" if any(term in lower_path for term in ("admin", "role", "permission")) else "appropriately privileged"
            candidates.append(_base(
                endpoint,
                "function_level",
                f"The API owner should confirm a minimum {minimum_role} role for this operation.",
                f"Potential API5 function-level review based on {endpoint.method} and path indicators: {', '.join(privileged) or 'destructive operation'}.",
                "high" if privileged and endpoint.method in DESTRUCTIVE_METHODS else "medium",
                "medium",
                FUNCTION_LEVEL_CHECKLIST,
            ))

        parameter_names = [str(item.get("name", "")) for item in loads_json(endpoint.parameters_json, [])]
        sensitive = sorted({name for name in parameter_names + exposure_by_endpoint.get(endpoint.id, []) if any(term in name.lower() for term in SENSITIVE_FIELDS)})
        if sensitive:
            direction = "writable request metadata" if any(name in parameter_names for name in sensitive) else "documented response exposure"
            candidates.append(_base(
                endpoint,
                "property_level",
                "Sensitive properties should be explicitly authorized by role and managed server-side where appropriate.",
                f"Potential API3 property-level review for {direction}: {', '.join(sensitive)}.",
                "medium",
                "medium",
                PROPERTY_LEVEL_CHECKLIST,
            ))
    return candidates
