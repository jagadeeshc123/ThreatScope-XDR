import json
from pathlib import Path
from typing import Any

import yaml

from app.modules.api_security.inventory import classify_endpoint
from app.modules.api_security.parsers.redaction import redact_data


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
PATH_METADATA_KEYS = {"parameters", "summary", "description", "servers"}


class OpenApiParseError(ValueError):
    pass


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpenApiParseError("OpenAPI import must be UTF-8 encoded.") from exc


def _load_document(raw: str, filename: str) -> dict[str, Any]:
    suffix = Path(filename).suffix.lower()
    try:
        loaded = json.loads(raw) if suffix == ".json" else yaml.safe_load(raw)
    except Exception as exc:
        raise OpenApiParseError("OpenAPI document could not be parsed as JSON/YAML.") from exc
    if not _is_object(loaded):
        raise OpenApiParseError("OpenAPI document must be a JSON/YAML object.")
    version = str(loaded.get("openapi") or "")
    if not version.startswith("3."):
        raise OpenApiParseError("Only OpenAPI 3.x documents are supported in this phase.")
    if not _is_object(loaded.get("paths")):
        raise OpenApiParseError("OpenAPI document does not contain a valid paths object.")
    return loaded


def _resolve_pointer(document: dict[str, Any], ref: str, depth: int = 0) -> Any:
    if depth > 12 or not ref.startswith("#/"):
        return None
    current: Any = document
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not _is_object(current) or part not in current:
            return None
        current = current[part]
    if _is_object(current) and isinstance(current.get("$ref"), str) and current["$ref"].startswith("#/"):
        return _resolve_pointer(document, current["$ref"], depth + 1)
    return current


def _resolve_local(document: dict[str, Any], value: Any) -> Any:
    if _is_object(value) and isinstance(value.get("$ref"), str):
        resolved = _resolve_pointer(document, value["$ref"])
        return resolved if resolved is not None else value
    return value


def _content_types(value: Any, document: dict[str, Any]) -> list[str]:
    resolved = _resolve_local(document, value)
    if not _is_object(resolved) or not _is_object(resolved.get("content")):
        return []
    return sorted(str(key) for key in resolved["content"].keys())


def _response_content_types(operation: dict[str, Any], document: dict[str, Any]) -> list[str]:
    responses = operation.get("responses")
    if not _is_object(responses):
        return []
    collected: set[str] = set()
    for response in responses.values():
        for content_type in _content_types(response, document):
            collected.add(content_type)
    return sorted(collected)


def _parameters(path_item: dict[str, Any], operation: dict[str, Any], document: dict[str, Any]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for source in (path_item.get("parameters"), operation.get("parameters")):
        if not isinstance(source, list):
            continue
        for item in source:
            parameter = _resolve_local(document, item)
            if not _is_object(parameter):
                continue
            schema = _resolve_local(document, parameter.get("schema"))
            merged.append({
                "name": str(parameter.get("name") or ""),
                "in": str(parameter.get("in") or ""),
                "required": bool(parameter.get("required")),
                "schema_type": str(schema.get("type") or "") if _is_object(schema) else "",
            })
    return [item for item in merged if item["name"]]


def _security_schemes(requirements: Any) -> list[str]:
    if not isinstance(requirements, list):
        return []
    names: set[str] = set()
    for requirement in requirements:
        if _is_object(requirement):
            names.update(str(key) for key in requirement.keys() if key)
    return sorted(names)


def _auth_required(global_security: Any, operation: dict[str, Any]) -> tuple[bool, list[str]]:
    effective = operation["security"] if "security" in operation else global_security
    if not isinstance(effective, list) or len(effective) == 0:
        return False, []
    if any(_is_object(item) and len(item) == 0 for item in effective):
        return False, []
    schemes = _security_schemes(effective)
    return bool(schemes), schemes


def parse_openapi(content: bytes, filename: str) -> dict[str, Any]:
    raw = _decode(content)
    document = _load_document(raw, filename)
    info = document.get("info") if _is_object(document.get("info")) else {}
    servers = document.get("servers") if isinstance(document.get("servers"), list) else []
    server_urls = [
        str(server.get("url"))
        for server in servers
        if _is_object(server) and server.get("url")
    ]
    endpoints: list[dict[str, Any]] = []

    for path, path_item_value in document["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not _is_object(path_item_value):
            continue
        path_item = _resolve_local(document, path_item_value)
        if not _is_object(path_item):
            continue
        for key, operation_value in path_item.items():
            method = str(key).lower()
            if method not in HTTP_METHODS:
                continue
            operation = _resolve_local(document, operation_value)
            if not _is_object(operation):
                continue
            auth_required, auth_schemes = _auth_required(document.get("security"), operation)
            endpoint = {
                "path": path,
                "method": method.upper(),
                "operation_id": operation.get("operationId") if isinstance(operation.get("operationId"), str) else None,
                "summary": operation.get("summary") if isinstance(operation.get("summary"), str) else None,
                "description": operation.get("description") if isinstance(operation.get("description"), str) else None,
                "auth_required": auth_required,
                "auth_schemes": auth_schemes,
                "request_content_types": _content_types(operation.get("requestBody"), document),
                "response_content_types": _response_content_types(operation, document),
                "parameters": _parameters(path_item, operation, document),
                "tags": [str(tag) for tag in operation.get("tags", []) if isinstance(tag, str)],
                "folder_path": None,
                "deprecated": operation.get("deprecated") is True,
            }
            risk_level, reasons = classify_endpoint(endpoint)
            endpoint["preliminary_risk_level"] = risk_level
            endpoint["preliminary_risk_reasons"] = reasons
            endpoints.append(endpoint)

    if not endpoints:
        raise OpenApiParseError("No supported HTTP operations were found in the OpenAPI document.")

    return {
        "title": str(info.get("title") or "Imported API"),
        "version": str(info.get("version")) if info.get("version") is not None else None,
        "server_urls": server_urls,
        "base_url": server_urls[0] if server_urls else None,
        "endpoints": endpoints,
        "redacted_content": json.dumps(redact_data(document), ensure_ascii=True, indent=2, sort_keys=True),
        "summary": {
            "format": "openapi",
            "title": str(info.get("title") or "Imported API"),
            "version": str(info.get("version")) if info.get("version") is not None else None,
            "server_urls": server_urls,
            "endpoint_count": len(endpoints),
            "ignored_path_metadata": sorted(PATH_METADATA_KEYS),
            "remote_refs_resolved": False,
        },
    }

