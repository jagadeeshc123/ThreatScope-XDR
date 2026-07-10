import json
import re
from typing import Any


SENSITIVE_KEYWORDS = [
    "admin",
    "user",
    "account",
    "payment",
    "billing",
    "password",
    "token",
    "secret",
    "internal",
    "export",
    "report",
    "profile",
    "role",
    "permission",
]

HIGH_CONTEXT_KEYWORDS = {"admin", "payment", "billing", "password", "token", "secret", "internal", "export"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
RISK_WEIGHTS = {"info": 1, "low": 3, "medium": 6, "high": 9}


def dumps_json(value: Any) -> str:
    return json.dumps(value or [], ensure_ascii=True, sort_keys=True)


def loads_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def classify_endpoint(endpoint: dict[str, Any]) -> tuple[str, list[str]]:
    method = str(endpoint.get("method") or "").upper()
    path = str(endpoint.get("path") or "")
    auth_required = bool(endpoint.get("auth_required"))
    deprecated = bool(endpoint.get("deprecated"))
    responses = endpoint.get("response_content_types") or []
    summary = endpoint.get("summary")
    operation_id = endpoint.get("operation_id")

    normalized_path = path.lower()
    matched_keywords = [keyword for keyword in SENSITIVE_KEYWORDS if re.search(rf"(^|[^a-z0-9]){re.escape(keyword)}s?([^a-z0-9]|$)", normalized_path)]
    reasons: list[str] = []
    level = "info"

    def raise_to(candidate: str) -> None:
        nonlocal level
        order = ["info", "low", "medium", "high"]
        if order.index(candidate) > order.index(level):
            level = candidate

    if not auth_required and method in STATE_CHANGING_METHODS:
        raise_to("high")
        reasons.append("Unauthenticated state-changing endpoint")

    if matched_keywords and not auth_required:
        if method in STATE_CHANGING_METHODS or any(keyword in HIGH_CONTEXT_KEYWORDS for keyword in matched_keywords):
            raise_to("high")
            reasons.append(f"Sensitive unauthenticated path keyword: {', '.join(sorted(set(matched_keywords)))}")
        else:
            raise_to("medium")
            reasons.append(f"Unauthenticated sensitive GET-style path keyword: {', '.join(sorted(set(matched_keywords)))}")

    if deprecated:
        raise_to("medium")
        reasons.append("Endpoint is marked deprecated")

    if not responses:
        raise_to("low")
        reasons.append("No documented response content types")

    if re.search(r"(\*|\{proxy\+\}|\{path\}|\{.*wildcard.*\}|:[A-Za-z0-9_]*path)", path):
        raise_to("low")
        reasons.append("Wildcard or overly broad path pattern")

    if not summary and not operation_id:
        raise_to("info")
        reasons.append("No summary or operation ID documented")

    if not auth_required and method in {"GET", "HEAD", "OPTIONS"} and not matched_keywords:
        reasons.append("Unauthenticated ordinary read-only endpoint")

    return level, reasons or ["No notable passive metadata risk signals"]


def risk_score_for_levels(levels: list[str]) -> int:
    if not levels:
        return 0
    total = sum(RISK_WEIGHTS.get(level, 1) for level in levels)
    return round(total / len(levels))

