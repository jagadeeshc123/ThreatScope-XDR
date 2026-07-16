import fnmatch
import ipaddress
import json
import re
from datetime import datetime, timezone

ALLOWED_FIELDS = {
    "event.id", "event.module", "event.category", "event.action", "event.outcome", "event.severity", "event.timestamp", "event.message",
    "source.ip", "source.port", "source.domain", "source.email", "destination.ip", "destination.port", "destination.domain",
    "user.name", "user.email", "host.name", "process.name", "process.command_line", "file.name", "file.path", "file.sha256", "file.sha1", "file.md5",
    "url.full", "url.domain", "http.method", "http.status_code", "network.protocol", "threat.indicator", "threat.confidence", "case.id", "tags",
}
ALIASES = {
    "EventID": "event.id", "Category": "event.category", "EventType": "event.category", "Action": "event.action", "Outcome": "event.outcome",
    "Level": "event.severity", "Message": "event.message", "SourceIp": "source.ip", "DestinationIp": "destination.ip", "UserName": "user.name",
    "CommandLine": "process.command_line", "Image": "process.name", "FileName": "file.name", "TargetFilename": "file.path", "sha256": "file.sha256",
    "Url": "url.full", "Domain": "url.domain", "HttpMethod": "http.method", "StatusCode": "http.status_code",
}
OPERATORS = {"exact", "iexact", "contains", "startswith", "endswith", "wildcard", "in", "gt", "gte", "lt", "lte", "exists", "cidr"}
MAX_DEPTH = 8


class RuleValidationError(ValueError):
    pass


def canonical_field(name):
    return ALIASES.get(name, name)


def normalize_soc_event(event):
    extra = {}
    try:
        extra = json.loads(event.normalized_json or "{}")
    except (TypeError, ValueError):
        pass
    def text(value, limit=4000):
        return str(value)[:limit] if value is not None else None
    timestamp = event.event_time
    if timestamp and timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    host = extra.get("host") if isinstance(extra.get("host"), dict) else {}
    process = extra.get("process") if isinstance(extra.get("process"), dict) else {}
    file_data = extra.get("file") if isinstance(extra.get("file"), dict) else {}
    return {
        "event.id": event.id, "event.module": "soc", "event.category": text(event.event_type, 80), "event.action": text(event.action, 120),
        "event.outcome": text(event.outcome, 24), "event.severity": text(event.severity, 16), "event.timestamp": timestamp,
        "event.message": text(event.message), "source.ip": text(event.source_ip, 64), "source.port": extra.get("source_port"),
        "source.domain": text(extra.get("source_domain"), 255), "source.email": text(extra.get("source_email"), 320),
        "destination.ip": text(event.destination_ip, 64), "destination.port": extra.get("destination_port"), "destination.domain": text(extra.get("destination_domain"), 255),
        "user.name": text(event.username, 160), "user.email": text(extra.get("user_email"), 320), "host.name": text(host.get("name") or extra.get("hostname"), 255),
        "process.name": text(process.get("name"), 500), "process.command_line": text(process.get("command_line")), "file.name": text(file_data.get("name"), 500),
        "file.path": text(file_data.get("path"), 2000), "file.sha256": text(file_data.get("sha256"), 64), "file.sha1": text(file_data.get("sha1"), 40),
        "file.md5": text(file_data.get("md5"), 32), "url.full": text(extra.get("url") or event.request_path, 2000), "url.domain": text(extra.get("url_domain"), 255),
        "http.method": text(event.http_method, 16), "http.status_code": event.status_code, "network.protocol": text(extra.get("protocol"), 40),
        "threat.indicator": text(extra.get("threat_indicator"), 2048), "threat.confidence": extra.get("threat_confidence"), "case.id": extra.get("case_id"),
        "tags": extra.get("tags", []) if isinstance(extra.get("tags", []), list) else [],
    }


def _operator_from_key(key):
    parts = key.split("|")
    field = canonical_field(parts[0])
    modifiers = parts[1:]
    op = "iexact"
    if modifiers:
        mapped = {"re": "unsupported", "contains": "contains", "startswith": "startswith", "endswith": "endswith", "cidr": "cidr", "exists": "exists", "gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte", "all": "all"}
        op = mapped.get(modifiers[0], modifiers[0])
    return field, op, modifiers


def normalize_rule(content):
    detection = content.get("detection") or {}
    condition = str(detection.get("condition") or content.get("condition") or "").strip()
    selections = content.get("selections") or {k: v for k, v in detection.items() if k != "condition"}
    if not isinstance(selections, dict) or not selections or len(selections) > 32:
        raise RuleValidationError("Rule requires 1-32 selections")
    normalized = {}
    wildcard_count = 0
    field_count = 0
    for name, selection in selections.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", str(name)) or not isinstance(selection, dict) or not selection:
            raise RuleValidationError("Selections must be non-empty named objects")
        terms = []
        for raw_field, raw_value in selection.items():
            field_count += 1
            if field_count > 128:
                raise RuleValidationError("Rule field limit exceeded")
            field, op, modifiers = _operator_from_key(str(raw_field))
            if field not in ALLOWED_FIELDS:
                terms.append({"field": field, "operator": op, "value": raw_value, "unsupported": True})
                continue
            if isinstance(raw_value, dict):
                op = str(raw_value.get("operator", "iexact")); value = raw_value.get("value")
            else:
                value = raw_value
            if op not in OPERATORS and op != "all":
                raise RuleValidationError(f"Unsupported operator: {op}")
            values = value if isinstance(value, list) else [value]
            wildcard_count += sum(str(v).count("*") + str(v).count("?") for v in values)
            if wildcard_count > 20:
                raise RuleValidationError("Wildcard limit exceeded")
            terms.append({"field": field, "operator": op, "value": value, "all": "all" in modifiers})
        normalized[str(name)] = terms
    if not condition or len(condition) > 500:
        raise RuleValidationError("Condition is required and bounded to 500 characters")
    _parse_condition(condition, set(normalized))
    return {"selections": normalized, "condition": condition}


def _tokens(condition):
    return re.findall(r"\(|\)|\b(?:and|or|not|of|all)\b|\d+|[A-Za-z][A-Za-z0-9_*-]*", condition, flags=re.I)


def _parse_condition(condition, names):
    tokens = _tokens(condition)
    if "".join(tokens).lower() != re.sub(r"\s+", "", condition).lower():
        raise RuleValidationError("Condition contains unsupported syntax")
    pos = 0
    def expression(depth=0):
        nonlocal pos
        if depth > MAX_DEPTH: raise RuleValidationError("Condition depth limit exceeded")
        node = conjunction(depth + 1)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1; node = ("or", node, conjunction(depth + 1))
        return node
    def conjunction(depth):
        nonlocal pos
        node = unary(depth + 1)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1; node = ("and", node, unary(depth + 1))
        return node
    def unary(depth):
        nonlocal pos
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1; return ("not", unary(depth + 1))
        if pos < len(tokens) and tokens[pos] == "(":
            pos += 1; node = expression(depth + 1)
            if pos >= len(tokens) or tokens[pos] != ")": raise RuleValidationError("Unbalanced condition parentheses")
            pos += 1; return node
        if pos + 2 < len(tokens) and (tokens[pos].isdigit() or tokens[pos].lower() == "all") and tokens[pos + 1].lower() == "of":
            amount=tokens[pos].lower(); pattern=tokens[pos+2]; pos += 3
            prefix = pattern[:-1] if pattern.endswith("*") else pattern
            matched = sorted(n for n in names if n.startswith(prefix))
            if not matched: raise RuleValidationError("Condition wildcard references no selections")
            return ("of", amount, matched)
        if pos >= len(tokens): raise RuleValidationError("Incomplete condition")
        name=tokens[pos]; pos += 1
        if name not in names: raise RuleValidationError(f"Unknown selection in condition: {name}")
        return ("selection", name)
    tree=expression()
    if pos != len(tokens): raise RuleValidationError("Malformed condition")
    return tree


def _match_value(actual, op, expected):
    if op == "exists": return (actual is not None) == bool(expected)
    if actual is None: return False
    if op == "cidr":
        try: return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError: return False
    if op in {"gt", "gte", "lt", "lte"}:
        try: a, b = float(actual), float(expected)
        except (TypeError, ValueError): return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "in": return actual in (expected if isinstance(expected, list) else [expected])
    actual_text, expected_text = str(actual), str(expected)
    if op == "exact": return actual_text == expected_text
    a, b = actual_text.casefold(), expected_text.casefold()
    if op == "iexact": return a == b
    if op == "contains": return b in a
    if op == "startswith": return a.startswith(b)
    if op == "endswith": return a.endswith(b)
    if op == "wildcard": return fnmatch.fnmatchcase(a, b)
    return False


def evaluate(normalized, event):
    outcomes, matched = {}, {}
    for name, terms in normalized["selections"].items():
        term_results=[]
        for term in terms:
            if term.get("unsupported"):
                term_results.append(False); continue
            expected = term["value"]
            values = expected if isinstance(expected, list) and term["operator"] != "in" else [expected]
            checks=[_match_value(event.get(term["field"]), term["operator"], value) for value in values]
            ok = all(checks) if term.get("all") else any(checks)
            term_results.append(ok)
            if ok: matched[term["field"]] = event.get(term["field"])
        outcomes[name] = all(term_results)
    tree = _parse_condition(normalized["condition"], set(outcomes))
    def resolve(node):
        if node[0] == "selection": return outcomes[node[1]]
        if node[0] == "not": return not resolve(node[1])
        if node[0] == "and": return resolve(node[1]) and resolve(node[2])
        if node[0] == "or": return resolve(node[1]) or resolve(node[2])
        if node[0] == "of":
            count=sum(1 for name in node[2] if outcomes[name]); return count == len(node[2]) if node[1] == "all" else count >= int(node[1])
        return False
    result=resolve(tree)
    return result, matched if result else {}, sorted(name for name, value in outcomes.items() if value)


def validate(content):
    errors=[]; warnings=[]; normalized={}
    try: normalized=normalize_rule(content)
    except RuleValidationError as exc: errors.append(str(exc))
    if normalized:
        unknown=sorted({term["field"] for terms in normalized["selections"].values() for term in terms if term.get("unsupported")})
        if unknown: warnings.append("Unsupported fields evaluate as missing: " + ", ".join(unknown))
    complexity = min(100, len(json.dumps(normalized)) // 40 + (normalized.get("condition", "").count("and") + normalized.get("condition", "").count("or")) * 4) if normalized else 0
    return {"valid": not errors, "errors": errors, "warnings": warnings, "normalized": normalized, "complexity_score": complexity, "estimated_scan_scope": "bounded stored ThreatScope records only"}
