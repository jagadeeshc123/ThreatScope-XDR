import hashlib
import json
import re
from collections import deque
from typing import Any

from .catalog import ACTION_CATALOG
from .conditions import ALLOWED_ROOTS, MAX_DEPTH, OPERATORS, validate_reference


MAX_DEFINITION_BYTES = 512 * 1024
MAX_STEPS = 50
MAX_VARIABLES = 100
MAX_BRANCHES = 20
MAX_DELAY_SECONDS = 24 * 3600
MAX_RETRY_DELAY_SECONDS = 3600
MAX_TOTAL_SECONDS = 72 * 3600
STEP_TYPES = {"action", "approval", "condition", "analyst_input", "delay", "notification", "case_workflow", "evidence_snapshot", "end"}
FORBIDDEN_KEYS = {"command", "shell", "url", "webhook", "callable", "module", "python", "javascript", "sql", "query", "executable", "script", "headers", "http_method"}
KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,99}$")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _walk_forbidden(value: Any, errors: list[dict], path: str = "definition", depth: int = 0) -> None:
    if depth > 12:
        errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "JSON nesting exceeds safe depth"}); return
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in FORBIDDEN_KEYS or normalized.startswith("__"):
                errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.{key}", "message": "Executable, network, SQL, or internal-object fields are prohibited"})
            _walk_forbidden(item, errors, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value): _walk_forbidden(item, errors, f"{path}[{index}]", depth + 1)
    elif isinstance(value, str) and value.startswith("${") and value.endswith("}") and not validate_reference(value):
        errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "Variable reference is not in an allowlisted context"})


def _condition_errors(node: Any, path: str, errors: list[dict], depth: int = 0, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    if depth > MAX_DEPTH: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "Condition depth exceeds 8"}); return
    if not isinstance(node, dict) or node.get("operator") not in OPERATORS: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "Condition operator is invalid"}); return
    op = node["operator"]
    if op in {"all", "any"}:
        children = node.get("conditions")
        if not isinstance(children, list) or not 1 <= len(children) <= 20: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": f"{op} requires 1 to 20 conditions"}); return
        for index, child in enumerate(children): _condition_errors(child, f"{path}.conditions[{index}]", errors, depth + 1, count)
    elif op == "not": _condition_errors(node.get("condition"), f"{path}.condition", errors, depth + 1, count)
    else:
        count[0] += 1
        if count[0] > 100: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "Condition comparison count exceeds 100"})
        for side in ("left", "right"):
            if side in node and not validate_reference(node[side]): errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.{side}", "message": "Variable reference is not allowed"})


def _normalize(definition: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(canonical(definition))
    result["steps"] = sorted(result.get("steps", []), key=lambda item: (int(item.get("position", 0)), str(item.get("key", ""))))
    return result


def validate_definition(definition: Any, *, trigger_mode: str = "manual", policy_enabled: dict[str, bool] | None = None, policy_automatic: dict[str, bool] | None = None) -> dict[str, Any]:
    errors: list[dict] = []; warnings: list[dict] = []; policy_enabled = policy_enabled or {}; policy_automatic = policy_automatic or {}
    try: encoded = canonical(definition).encode("utf-8")
    except (TypeError, ValueError): encoded = b""; errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "definition", "message": "Definition must be JSON-compatible"})
    if len(encoded) > MAX_DEFINITION_BYTES: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "definition", "message": "Definition exceeds 512 KiB"})
    if not isinstance(definition, dict):
        return _result(False, errors or [{"code": "SOAR_PLAYBOOK_INVALID", "path": "definition", "message": "Definition must be an object"}], warnings, {}, [], [], False, [], 0)
    _walk_forbidden(definition, errors)
    supported_root = {"start_step", "variables", "constants", "steps", "description"}
    for key in definition:
        if key not in supported_root: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": key, "message": "Unsupported root field"})
    variables = definition.get("variables", {})
    if not isinstance(variables, dict) or len(variables) > MAX_VARIABLES: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "variables", "message": "Variables must be an object with at most 100 entries"})
    steps = definition.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "Playbook requires 1 to 50 steps"}); steps = []
    by_key: dict[str, dict] = {}; positions: set[int] = set(); simulation_actions = []; approval_requirements = []; automatic_ok = True; branches = 0; evidence_count = 0
    for index, step in enumerate(steps):
        path = f"steps[{index}]"
        if not isinstance(step, dict): errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": path, "message": "Step must be an object"}); continue
        key = step.get("key")
        if not isinstance(key, str) or not KEY_RE.fullmatch(key): errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.key", "message": "Stable step key is invalid"}); continue
        if key in by_key: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.key", "step_key": key, "message": "Duplicate stable step key"})
        by_key[key] = step
        step_type = step.get("type")
        if step_type not in STEP_TYPES: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.type", "step_key": key, "message": "Unsupported step type"})
        position = step.get("position", index)
        if not isinstance(position, int) or position in positions: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.position", "step_key": key, "message": "Step positions must be unique integers"})
        positions.add(position)
        retries = step.get("max_retries", 0); retry_delay = step.get("retry_delay_seconds", 0); timeout = step.get("timeout_seconds", 30)
        if not isinstance(retries, int) or not 0 <= retries <= 3: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.max_retries", "step_key": key, "message": "Retries must be between 0 and 3"})
        if not isinstance(retry_delay, int) or not 0 <= retry_delay <= MAX_RETRY_DELAY_SECONDS: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.retry_delay_seconds", "step_key": key, "message": "Retry delay exceeds one hour"})
        if not isinstance(timeout, int) or not 1 <= timeout <= 3600: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.timeout_seconds", "step_key": key, "message": "Step timeout must be 1 to 3600 seconds"})
        if step_type == "delay":
            delay = step.get("configuration", {}).get("delay_seconds") if isinstance(step.get("configuration", {}), dict) else None
            if not isinstance(delay, int) or not 1 <= delay <= MAX_DELAY_SECONDS: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.configuration.delay_seconds", "step_key": key, "message": "Delay must be 1 second to 24 hours"})
        if step_type == "condition": _condition_errors(step.get("condition"), f"{path}.condition", errors)
        if step_type == "analyst_input":
            fields = step.get("configuration", {}).get("fields", []) if isinstance(step.get("configuration", {}), dict) else []
            if not isinstance(fields, list) or len(fields) > 20: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.configuration.fields", "step_key": key, "message": "Analyst input supports at most 20 fields"})
            for field in fields if isinstance(fields, list) else []:
                if str(field.get("type", "")) not in {"short_text", "long_text", "select", "multi_select", "boolean", "integer", "date", "datetime"} or any(word in str(field.get("name", "")).casefold() for word in ("password", "secret", "token", "mfa", "recovery", "key")): errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": f"{path}.configuration.fields", "step_key": key, "message": "Secret or unsupported analyst-input fields are prohibited"})
        if step_type == "evidence_snapshot": evidence_count += 1
        if step_type == "approval": approval_requirements.append({"step_key": key, "minimum_approvals": max(1, min(5, int(step.get("configuration", {}).get("minimum_approvals", 1))))})
        if step_type in {"action", "notification", "case_workflow", "evidence_snapshot"}:
            action_key = step.get("action_key")
            action = ACTION_CATALOG.get(action_key)
            if not action: errors.append({"code": "SOAR_ACTION_UNKNOWN", "path": f"{path}.action_key", "step_key": key, "message": "Action key is not in the server-owned catalog"}); continue
            if policy_enabled.get(action_key) is False: warnings.append({"code": "SOAR_ACTION_DISABLED", "step_key": key, "message": "Action is disabled by policy"})
            if action.simulation_only: simulation_actions.append(action_key)
            if action.safety_classification == "sensitive_local" and not any(item.get("type") == "approval" for item in steps): errors.append({"code": "SOAR_APPROVAL_REQUIRED", "path": path, "step_key": key, "message": "Sensitive actions require an approval step"})
            if trigger_mode == "automatic_local" and (not action.automatic_local_eligible or (action.safety_classification == "harmless_local" and not policy_automatic.get(action_key, False))): errors.append({"code": "SOAR_ACTION_POLICY_VIOLATION", "path": path, "step_key": key, "message": "Action is not explicitly policy-enabled for automatic-local execution"}); automatic_ok = False
            if retries and not action.supports_idempotency: warnings.append({"code": "SOAR_PLAYBOOK_INVALID", "step_key": key, "message": "Retry is configured for a non-idempotent action"})
            if action.simulation_only: warnings.append({"code": "SOAR_ACTION_MODE_NOT_ALLOWED", "step_key": key, "message": "SIMULATION ONLY — NO EXTERNAL ACTION IS PERFORMED"})
            if action.safety_classification == "sensitive_local": warnings.append({"code": "SOAR_APPROVAL_REQUIRED", "step_key": key, "message": "ADMINISTRATOR APPROVAL REQUIRED"})
        for field in ("on_success", "on_failure", "on_timeout"):
            if step.get(field): branches += 1
    if branches > MAX_BRANCHES: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "Branch count exceeds 20"})
    if evidence_count > 25: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "Evidence snapshot count exceeds 25"})
    start = definition.get("start_step")
    if start not in by_key: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "start_step", "message": "Start step does not exist"})
    adjacency: dict[str, list[str]] = {}
    for key, step in by_key.items():
        routes = [step.get(field) for field in ("on_success", "on_failure", "on_timeout") if step.get(field)]
        adjacency[key] = routes
        if step.get("type") != "end" and not routes: warnings.append({"code": "SOAR_PLAYBOOK_INVALID", "step_key": key, "message": "Non-terminal step has no route"})
        for target in routes:
            if target == key: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "step_key": key, "message": "Self-loop is prohibited"})
            elif target not in by_key: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "step_key": key, "message": f"Route target {target!r} does not exist"})
    reachable = set(); queue = deque([start] if start in by_key else [])
    while queue:
        key = queue.popleft()
        if key in reachable: continue
        reachable.add(key); queue.extend(item for item in adjacency.get(key, []) if item in by_key)
    unreachable = sorted(set(by_key) - reachable)
    for key in unreachable: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "step_key": key, "message": "Step is unreachable"})
    color: dict[str, int] = {}; cycle = False
    def visit(key: str):
        nonlocal cycle
        color[key] = 1
        for target in adjacency.get(key, []):
            if target not in by_key: continue
            if color.get(target) == 1: cycle = True
            elif color.get(target, 0) == 0: visit(target)
        color[key] = 2
    if start in by_key: visit(start)
    if cycle: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "Cycles and recursive playbooks are prohibited"})
    terminal_reachable = any(by_key[key].get("type") == "end" for key in reachable)
    if not terminal_reachable: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "No reachable terminal end step"})
    normalized = _normalize(definition)
    estimated_seconds = sum(
        (step.get("configuration", {}).get("delay_seconds", 0) if step.get("type") == "delay" and isinstance(step.get("configuration", {}), dict) and isinstance(step.get("configuration", {}).get("delay_seconds", 0), int) else 0)
        + (step.get("timeout_seconds", 30) if isinstance(step.get("timeout_seconds", 30), int) else 30)
        * (1 + (step.get("max_retries", 0) if isinstance(step.get("max_retries", 0), int) else 0))
        for step in steps if isinstance(step, dict)
    )
    if estimated_seconds > MAX_TOTAL_SECONDS: errors.append({"code": "SOAR_PLAYBOOK_INVALID", "path": "steps", "message": "Estimated maximum execution path exceeds 72 hours"})
    return _result(not errors, errors, warnings, normalized, approval_requirements, sorted(set(simulation_actions)), automatic_ok, unreachable, estimated_seconds)


def _result(valid: bool, errors: list, warnings: list, normalized: dict, approvals: list, simulations: list, automatic: bool, unreachable: list, estimated: int) -> dict:
    return {"valid": valid, "errors": errors[:100], "warnings": warnings[:100], "normalized_definition": normalized, "complexity_score": min(100, len(normalized.get("steps", [])) * 2 + len(approvals) * 3 + len(simulations) * 2), "safety_summary": {"server_owned_actions_only": True, "external_execution": False, "no_code_execution": True}, "approval_requirements": approvals, "simulation_only_actions": simulations, "automatic_local_eligible": automatic and valid, "estimated_maximum_execution_path": {"seconds": estimated, "bounded": estimated <= MAX_TOTAL_SECONDS}, "unreachable_steps": unreachable, "content_sha256": content_hash(normalized)}
