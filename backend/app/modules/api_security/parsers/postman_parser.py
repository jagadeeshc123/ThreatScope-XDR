import json
import re
from typing import Any

from app.modules.api_security.inventory import classify_endpoint
from app.modules.api_security.parsers.redaction import redact_data


class PostmanParseError(ValueError):
    pass


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PostmanParseError("Postman import must be UTF-8 encoded.") from exc


def _load(raw: str) -> dict[str, Any]:
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PostmanParseError("Postman collection could not be parsed as JSON.") from exc
    if not _is_object(loaded) or not _is_object(loaded.get("info")) or not isinstance(loaded.get("item"), list):
        raise PostmanParseError("This is not a valid Postman Collection v2.1 document.")
    schema = str(loaded["info"].get("schema") or "")
    if schema and "v2.1" not in schema:
        raise PostmanParseError("Only Postman Collection v2.1 is supported in this phase.")
    return loaded


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _path_from_url(url: Any) -> str:
    if isinstance(url, str):
        raw = url
        path_parts: list[str] = []
    elif _is_object(url):
        raw = _text(url.get("raw"))
        path_parts = [str(part).strip("/") for part in url.get("path", []) if str(part).strip("/")] if isinstance(url.get("path"), list) else []
    else:
        return "/"
    if path_parts:
        return "/" + "/".join(path_parts)
    without_query = raw.split("?", 1)[0].split("#", 1)[0]
    without_host = re.sub(r"^https?://[^/]+", "", without_query, flags=re.I)
    without_variable_host = re.sub(r"^\{\{[^}]+\}\}", "", without_host)
    if not without_variable_host:
        return "/"
    return without_variable_host if without_variable_host.startswith("/") else f"/{without_variable_host}"


def _query_names(url: Any) -> list[str]:
    if not _is_object(url) or not isinstance(url.get("query"), list):
        return []
    return [str(item.get("key")) for item in url["query"] if _is_object(item) and item.get("key")]


def _variable_names(url: Any) -> list[str]:
    if not _is_object(url) or not isinstance(url.get("variable"), list):
        return []
    return [str(item.get("key")) for item in url["variable"] if _is_object(item) and item.get("key")]


def _headers(request: dict[str, Any]) -> tuple[list[str], bool, list[str]]:
    header_names: list[str] = []
    auth_header = False
    content_types: list[str] = []
    headers = request.get("header") if isinstance(request.get("header"), list) else []
    for header in headers:
        if not _is_object(header):
            continue
        key = _text(header.get("key"))
        if not key:
            continue
        header_names.append(key)
        if key.lower() == "authorization":
            auth_header = True
        if key.lower() == "content-type" and _text(header.get("value")):
            content_types.append(_text(header.get("value")).split(";", 1)[0].strip())
    return sorted(set(header_names)), auth_header, sorted(set(content_types))


def _auth_type(request: dict[str, Any], inherited_auth: Any) -> str | None:
    auth = request.get("auth", inherited_auth)
    if _is_object(auth):
        kind = _text(auth.get("type")).lower()
        return None if kind == "noauth" else kind or None
    return None


def _body_content_types(request: dict[str, Any], header_content_types: list[str]) -> list[str]:
    body = request.get("body")
    if not _is_object(body):
        return header_content_types
    mode = _text(body.get("mode")).lower()
    inferred: list[str] = []
    if mode == "raw":
        language = _text((body.get("options") or {}).get("raw", {}).get("language") if _is_object(body.get("options")) else "")
        inferred.append("application/json" if language == "json" else "text/plain")
    elif mode == "urlencoded":
        inferred.append("application/x-www-form-urlencoded")
    elif mode == "formdata":
        inferred.append("multipart/form-data")
    elif mode == "graphql":
        inferred.append("application/graphql")
    return sorted(set(header_content_types + inferred))


def _body_parameter_names(request: dict[str, Any]) -> list[str]:
    body = request.get("body")
    if not _is_object(body):
        return []
    names: set[str] = set()
    for collection_key in ("urlencoded", "formdata"):
        items = body.get(collection_key)
        if isinstance(items, list):
            names.update(str(item.get("key")) for item in items if _is_object(item) and item.get("key"))
    raw = body.get("raw")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if _is_object(parsed):
            names.update(str(key) for key in parsed.keys())
    return sorted(name for name in names if name)


def parse_postman(content: bytes, filename: str) -> dict[str, Any]:
    raw = _decode(content)
    collection = _load(raw)
    endpoints: list[dict[str, Any]] = []
    folder_count = 0

    def walk(items: list[Any], folders: list[str], inherited_auth: Any, depth: int = 0) -> None:
        nonlocal folder_count
        if depth > 25:
            raise PostmanParseError("Postman folder nesting exceeds the safe parsing limit.")
        for item in items:
            if not _is_object(item):
                continue
            if isinstance(item.get("item"), list):
                folder_count += 1
                walk(item["item"], folders + [_text(item.get("name")) or "Unnamed folder"], item.get("auth", inherited_auth), depth + 1)
                continue
            request = item.get("request")
            if not _is_object(request):
                continue
            method = (_text(request.get("method")) or "GET").upper()
            path = _path_from_url(request.get("url"))
            header_names, has_auth_header, header_content_types = _headers(request)
            auth_type = _auth_type(request, inherited_auth)
            parameters = [
                {"name": name, "in": "query", "required": False, "schema_type": ""}
                for name in _query_names(request.get("url"))
            ] + [
                {"name": name, "in": "path-variable", "required": False, "schema_type": ""}
                for name in _variable_names(request.get("url"))
            ] + [
                {"name": name, "in": "body", "required": False, "schema_type": ""}
                for name in _body_parameter_names(request)
            ]
            if header_names:
                parameters.extend({"name": name, "in": "header", "required": False, "schema_type": ""} for name in header_names)
            auth_schemes = [auth_type] if auth_type else (["Authorization header"] if has_auth_header else [])
            endpoint = {
                "path": path,
                "method": method,
                "operation_id": None,
                "summary": _text(item.get("name")) or None,
                "description": _text(request.get("description")) or _text(item.get("description")) or None,
                "auth_required": bool(auth_schemes),
                "auth_schemes": auth_schemes,
                "request_content_types": _body_content_types(request, header_content_types),
                "response_content_types": [],
                "parameters": parameters,
                "tags": folders,
                "folder_path": " / ".join(folders) if folders else None,
                "deprecated": False,
            }
            risk_level, reasons = classify_endpoint(endpoint)
            endpoint["preliminary_risk_level"] = risk_level
            endpoint["preliminary_risk_reasons"] = reasons
            endpoints.append(endpoint)

    walk(collection["item"], [], collection.get("auth"))
    if not endpoints:
        raise PostmanParseError("No requests were found in the Postman collection.")

    collection_name = _text(collection["info"].get("name")) or "Imported Postman collection"
    return {
        "title": collection_name,
        "version": None,
        "server_urls": [],
        "base_url": None,
        "endpoints": endpoints,
        "redacted_content": json.dumps(redact_data(collection), ensure_ascii=True, indent=2, sort_keys=True),
        "summary": {
            "format": "postman",
            "collection_name": collection_name,
            "schema": _text(collection["info"].get("schema")) or "Not declared",
            "folder_count": folder_count,
            "request_count": len(endpoints),
            "passive_analysis_only": True,
        },
    }

