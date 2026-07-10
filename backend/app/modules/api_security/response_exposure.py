import json
import re
from typing import Any

from app import models
from app.modules.api_security.inventory import loads_json
from app.modules.api_security.remediation import remediation_for
from app.modules.api_security.rules_loader import sensitive_fields


def _matches_sensitive(name: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    for field in sensitive_fields():
        if re.sub(r"[^a-z0-9]", "", field.lower()) in normalized:
            return field
    return None


def _schema_fields(schema: Any, path: str = "", depth: int = 0) -> list[str]:
    if depth > 20:
        return []
    fields: list[str] = []
    if isinstance(schema, dict):
        if isinstance(schema.get("properties"), dict):
            for name, nested in schema["properties"].items():
                nested_path = f"{path}.{name}" if path else str(name)
                fields.append(nested_path)
                fields.extend(_schema_fields(nested, nested_path, depth + 1))
        if "items" in schema:
            fields.extend(_schema_fields(schema["items"], f"{path}[]" if path else "[]", depth + 1))
        for key in ("allOf", "oneOf", "anyOf"):
            if isinstance(schema.get(key), list):
                for nested in schema[key]:
                    fields.extend(_schema_fields(nested, path, depth + 1))
    return fields


def _resolve(document: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str) or not value["$ref"].startswith("#/"):
        return value
    current: Any = document
    for part in value["$ref"][2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict):
            return value
        current = current.get(part)
    return current if current is not None else value


def _endpoint_id(endpoints: list[models.ApiEndpoint], path: str, method: str) -> int | None:
    for endpoint in endpoints:
        if endpoint.path == path and endpoint.method == method.upper():
            return endpoint.id
    return None


def _severity(field: str) -> str:
    high = {"password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "private_key", "ssn", "national_id", "credit_card", "cvv", "bank_account", "health_record"}
    return "high" if field in high else "medium"


def response_exposure_review(assessment: models.ApiAssessment) -> list[dict[str, Any]]:
    endpoints = list(assessment.endpoints)
    items: list[dict[str, Any]] = []
    guidance = remediation_for("sensitive_response_field")
    for artifact in assessment.artifacts:
        try:
            document = json.loads(artifact.redacted_content)
        except json.JSONDecodeError:
            continue
        if artifact.artifact_type == "openapi":
            paths = document.get("paths", {}) if isinstance(document, dict) else {}
            if not isinstance(paths, dict):
                continue
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"} or not isinstance(operation, dict):
                        continue
                    responses = operation.get("responses", {})
                    if not isinstance(responses, dict):
                        continue
                    for status_code, response in responses.items():
                        response = _resolve(document, response)
                        content = response.get("content", {}) if isinstance(response, dict) else {}
                        if not isinstance(content, dict):
                            continue
                        for media in content.values():
                            schema = _resolve(document, media.get("schema")) if isinstance(media, dict) else None
                            for field_path in _schema_fields(schema):
                                exposure = _matches_sensitive(field_path.split(".")[-1])
                                if not exposure:
                                    continue
                                items.append({
                                    "endpoint_id": _endpoint_id(endpoints, path, method),
                                    "method": method.upper(),
                                    "path": path,
                                    "status_code": str(status_code),
                                    "field_path": field_path,
                                    "exposure_type": exposure,
                                    "severity": _severity(exposure),
                                    "explanation": "A response schema documents a sensitive field name. This is static metadata only; runtime exposure is not confirmed.",
                                    "remediation": guidance["remediation"],
                                })
        elif artifact.artifact_type == "postman":
            # Postman response examples vary widely; inspect only redacted JSON field names.
            for endpoint in endpoints:
                for parameter in loads_json(endpoint.parameters_json, []):
                    name = str(parameter.get("name", ""))
                    exposure = _matches_sensitive(name)
                    if exposure and parameter.get("in") == "body":
                        items.append({
                            "endpoint_id": endpoint.id,
                            "method": endpoint.method,
                            "path": endpoint.path,
                            "status_code": None,
                            "field_path": name,
                            "exposure_type": exposure,
                            "severity": _severity(exposure),
                            "explanation": "A Postman example includes a sensitive body field name. Values are redacted and requests are not executed.",
                            "remediation": guidance["remediation"],
                        })
    signatures = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        signature = (item["method"], item["path"], item.get("status_code"), item["field_path"])
        if signature not in signatures:
            signatures.add(signature)
            unique.append(item)
    return unique

