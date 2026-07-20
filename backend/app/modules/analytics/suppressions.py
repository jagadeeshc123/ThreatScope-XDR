from datetime import datetime, timedelta

from .features import finite, utc


MAX_DURATION = 90 * 86400
EMERGENCY_MAX_DURATION = 4 * 3600
ALLOWED_FIELDS = {"detector_id", "source_entity_type", "source_entity_identifier", "approved_tag", "connector_id", "asset_id", "api_endpoint_id", "alert_source", "minimum_score", "maximum_score"}
PROTECTED_TOKENS = {"race", "ethnicity", "religion", "sex", "gender", "disability", "political", "health"}


def validate_scope(scope: dict, *, is_admin: bool, emergency: bool = False) -> dict:
    if not isinstance(scope, dict) or set(scope) - ALLOWED_FIELDS:
        raise ValueError("Suppression contains an unsupported declarative dimension")
    if not scope:
        raise ValueError("Suppression scope cannot be empty")
    encoded = " ".join(str(value).casefold() for value in scope.values())
    if any(token in encoded for token in PROTECTED_TOKENS):
        raise ValueError("Protected-attribute suppression scopes are prohibited")
    for value in scope.values():
        if isinstance(value, str) and ("*" in value or len(value) > 200):
            raise ValueError("Wildcard or oversized suppression scope is prohibited")
    broad = not scope.get("detector_id") and not scope.get("source_entity_identifier") and not scope.get("connector_id") and not scope.get("asset_id") and not scope.get("api_endpoint_id")
    if broad and not is_admin:
        raise PermissionError("Administrator approval is required for broad suppressions")
    if scope.get("minimum_score") is not None: finite(scope["minimum_score"], non_negative=True)
    if scope.get("maximum_score") is not None: finite(scope["maximum_score"], non_negative=True)
    if scope.get("minimum_score") is not None and scope.get("maximum_score") is not None and scope["minimum_score"] > scope["maximum_score"]:
        raise ValueError("Suppression score range is invalid")
    return {**scope, "broad_scope": broad, "maximum_duration_seconds": EMERGENCY_MAX_DURATION if emergency else MAX_DURATION}


def validate_period(start: datetime, end: datetime, *, emergency: bool = False) -> tuple[datetime, datetime, int]:
    start, end = utc(start), utc(end)
    maximum = EMERGENCY_MAX_DURATION if emergency else MAX_DURATION
    duration = int((end - start).total_seconds())
    if duration <= 0 or duration > maximum:
        raise ValueError("Suppression duration exceeds the server-owned bound")
    return start, end, maximum


def matches(item, detector_id: int, entity_type: str, entity_identifier: str, score: float, now: datetime) -> bool:
    now = utc(now)
    if not item.enabled or item.starts_at > now or item.ends_at <= now: return False
    if item.detector_id and item.detector_id != detector_id: return False
    if item.source_entity_type and item.source_entity_type != entity_type: return False
    if item.source_entity_identifier and item.source_entity_identifier != entity_identifier: return False
    if item.minimum_score is not None and score < item.minimum_score: return False
    if item.maximum_score is not None and score > item.maximum_score: return False
    return True
