from dataclasses import dataclass
from typing import Any


MISSING = object()
OPERATORS = {"equals", "not_equals", "contains", "starts_with", "ends_with", "in", "not_in", "greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal", "exists", "not_exists", "is_true", "is_false", "all", "any", "not"}
ALLOWED_ROOTS = {"trigger", "execution", "playbook", "steps", "analyst_input", "constants"}
MAX_DEPTH = 8
MAX_COMPARISONS = 100


@dataclass(frozen=True)
class ConditionResult:
    matched: bool
    explanation: str
    comparisons: int


def resolve_reference(value: Any, context: dict[str, Any]) -> Any:
    if not isinstance(value, str) or not (value.startswith("${") and value.endswith("}")):
        return value
    path = value[2:-1]
    parts = path.split(".")
    if not parts or parts[0] not in ALLOWED_ROOTS or any(not part or part.startswith("_") or "__" in part for part in parts):
        return MISSING
    current: Any = context
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current


def validate_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("${"):
        return True
    if not value.endswith("}"):
        return False
    parts = value[2:-1].split(".")
    return bool(parts and parts[0] in ALLOWED_ROOTS and all(part and not part.startswith("_") and "__" not in part and len(part) <= 100 for part in parts))


def evaluate(condition: dict[str, Any], context: dict[str, Any], *, depth: int = 0, budget: list[int] | None = None) -> ConditionResult:
    budget = budget if budget is not None else [MAX_COMPARISONS]
    if depth > MAX_DEPTH:
        raise ValueError("Condition nesting exceeds maximum depth 8")
    if budget[0] <= 0:
        raise ValueError("Condition comparison limit exceeded")
    if not isinstance(condition, dict) or condition.get("operator") not in OPERATORS:
        raise ValueError("Unsupported condition operator")
    operator = condition["operator"]
    if operator in {"all", "any"}:
        items = condition.get("conditions")
        if not isinstance(items, list) or not 1 <= len(items) <= 20:
            raise ValueError(f"{operator} requires 1 to 20 conditions")
        results = [evaluate(item, context, depth=depth + 1, budget=budget) for item in items]
        matched = all(item.matched for item in results) if operator == "all" else any(item.matched for item in results)
        return ConditionResult(matched, f"{operator}({', '.join(str(item.matched).lower() for item in results)}) => {str(matched).lower()}", sum(item.comparisons for item in results))
    if operator == "not":
        result = evaluate(condition.get("condition"), context, depth=depth + 1, budget=budget)
        return ConditionResult(not result.matched, f"not({result.matched}) => {not result.matched}", result.comparisons)
    budget[0] -= 1
    left = resolve_reference(condition.get("left"), context)
    right = resolve_reference(condition.get("right"), context)
    case_sensitive = condition.get("case_sensitive", True)
    if operator == "exists": matched = left is not MISSING and left is not None
    elif operator == "not_exists": matched = left is MISSING or left is None
    elif operator == "is_true": matched = left is True
    elif operator == "is_false": matched = left is False
    elif left is MISSING or right is MISSING: matched = False
    elif operator in {"equals", "not_equals"}:
        comparable_left, comparable_right = left, right
        if not case_sensitive and isinstance(left, str) and isinstance(right, str): comparable_left, comparable_right = left.casefold(), right.casefold()
        matched = type(comparable_left) is type(comparable_right) and comparable_left == comparable_right
        if operator == "not_equals": matched = not matched
    elif operator == "contains":
        if isinstance(left, str) and isinstance(right, str): matched = (right in left) if case_sensitive else (right.casefold() in left.casefold())
        elif isinstance(left, list): matched = any(type(item) is type(right) and item == right for item in left)
        else: matched = False
    elif operator in {"starts_with", "ends_with"}:
        if not isinstance(left, str) or not isinstance(right, str): matched = False
        else:
            a, b = (left, right) if case_sensitive else (left.casefold(), right.casefold())
            matched = a.startswith(b) if operator == "starts_with" else a.endswith(b)
    elif operator in {"in", "not_in"}:
        matched = isinstance(right, list) and any(type(left) is type(item) and left == item for item in right)
        if operator == "not_in": matched = not matched
    elif operator in {"greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"}:
        if isinstance(left, bool) or isinstance(right, bool) or not isinstance(left, (int, float)) or not isinstance(right, (int, float)): matched = False
        elif operator == "greater_than": matched = left > right
        elif operator == "greater_than_or_equal": matched = left >= right
        elif operator == "less_than": matched = left < right
        else: matched = left <= right
    else: matched = False
    safe_left = "missing" if left is MISSING else type(left).__name__
    safe_right = "missing" if right is MISSING else type(right).__name__
    return ConditionResult(matched, f"{operator}({safe_left}, {safe_right}) => {str(matched).lower()}", 1)
