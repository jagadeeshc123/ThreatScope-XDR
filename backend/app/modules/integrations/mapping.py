from datetime import datetime, timezone

from .security import IntegrationSecurityError


ALLOWED_TRANSFORMS = {"direct", "constant", "default", "lowercase", "uppercase", "trim", "truncate", "concatenate", "list_join", "integer", "boolean", "iso_datetime", "severity_map", "enum_map", "conditional"}


def _path(data, path: str):
    parts = path.split(".") if path else []
    if len(parts) > 8 or any(not p or p.startswith("_") or "__" in p for p in parts):
        raise IntegrationSecurityError("CONNECTOR_MAPPING_FAILED", "Mapping path is prohibited")
    value = data
    for part in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def validate_mapping(rules):
    errors = []
    if not isinstance(rules, list) or len(rules) > 100:
        return {"valid": False, "errors": ["Mapping must contain at most 100 declarative rules"]}
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or rule.get("transform", "direct") not in ALLOWED_TRANSFORMS:
            errors.append(f"Rule {index} uses an unsupported transform")
        if not isinstance(rule.get("target"), str) or "__" in rule.get("target", ""):
            errors.append(f"Rule {index} has an invalid target")
        text = str(rule).casefold()
        if any(word in text for word in ("{{", "{%", "javascript:", "python", "__", "os.environ", "eval(", "exec(")):
            errors.append(f"Rule {index} contains a prohibited expression")
    return {"valid": not errors, "errors": errors[:20]}


def apply_mapping(source: dict, rules: list[dict]) -> dict:
    result = validate_mapping(rules)
    if not result["valid"]:
        raise IntegrationSecurityError("CONNECTOR_MAPPING_FAILED", "; ".join(result["errors"]))
    output = {}
    for rule in rules:
        transform = rule.get("transform", "direct")
        value = rule.get("value") if transform == "constant" else _path(source, str(rule.get("source", "")))
        if value is None and "default" in rule:
            value = rule["default"]
        if transform == "lowercase" and isinstance(value, str): value = value.casefold()
        elif transform == "uppercase" and isinstance(value, str): value = value.upper()
        elif transform == "trim" and isinstance(value, str): value = value.strip()
        elif transform == "truncate" and isinstance(value, str): value = value[:min(max(int(rule.get("length", 200)), 0), 4000)]
        elif transform == "concatenate": value = str(rule.get("separator", "")).join(str(_path(source, x) or "") for x in list(rule.get("sources", []))[:10])
        elif transform == "list_join" and isinstance(value, list): value = str(rule.get("separator", ", ")).join(str(x)[:200] for x in value[:100])
        elif transform == "integer":
            try: value = int(value)
            except (TypeError, ValueError): raise IntegrationSecurityError("CONNECTOR_MAPPING_FAILED", "Integer conversion failed")
        elif transform == "boolean": value = value if isinstance(value, bool) else str(value).casefold() in {"1", "true", "yes"}
        elif transform == "iso_datetime":
            try: value = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
            except ValueError as exc: raise IntegrationSecurityError("CONNECTOR_MAPPING_FAILED", "Datetime normalization failed") from exc
        elif transform in {"severity_map", "enum_map"}: value = dict(rule.get("map", {})).get(str(value), rule.get("default", value))
        elif transform == "conditional":
            condition = rule.get("condition", {})
            actual = _path(source, str(condition.get("field", "")))
            value = rule.get("then") if actual == condition.get("equals") else rule.get("else")
        output[str(rule["target"])[:100]] = value
    return output
