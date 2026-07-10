import re
from typing import Any


IDENTIFIER_RE = re.compile(r"\{[^}]*?(?:id|key|uuid|number)[^}]*\}", re.IGNORECASE)


def suggest_cell(endpoint: Any, role: Any) -> dict[str, Any]:
    path = endpoint.path.lower()
    privileged_path = any(term in path for term in ("/admin", "/roles", "/permissions"))
    service_path = any(term in path for term in ("/internal", "/service"))
    level = role.privilege_level

    if level == "public":
        access = "allow" if not endpoint.auth_required else "deny"
    elif privileged_path:
        access = "allow" if level == "admin" else "deny"
    elif service_path:
        access = "allow" if level in {"service", "admin", "privileged"} else "deny"
    elif endpoint.auth_required:
        access = "allow" if level in {"user", "privileged", "admin", "service"} else "deny"
    else:
        access = "allow"

    if "tenant" in path:
        scope = "tenant"
    elif any(term in path for term in ("organization", "/org")):
        scope = "organization"
    elif IDENTIFIER_RE.search(endpoint.path):
        scope = "global" if level == "admin" else "own"
    else:
        scope = "global" if level in {"admin", "service"} else "unknown"

    return {
        "expected_access": access,
        "object_scope": scope,
        "expected_conditions": {
            "basis": "Suggested expected access inferred from imported metadata.",
            "analyst_confirmation_required": True,
            "runtime_validation_performed": False,
        },
        "review_status": "requires_validation",
    }
