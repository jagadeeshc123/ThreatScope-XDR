import json
from typing import Any

from .catalog import REASON_CODES, feature
from .features import finite, stable_round


SENSITIVE_TOKENS = {"password", "secret", "token", "cookie", "authorization", "csrf", "credential", "raw", "payload", "email_body", "document_body", "evidence_blob"}


def _safe_text(value: object, limit: int = 1000) -> str:
    text = " ".join(str(value or "").replace("\x00", " ").split())[:limit]
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://")


def safe_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return "[bounded]"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:50]:
            normalized = str(key).casefold()
            if any(token in normalized for token in SENSITIVE_TOKENS):
                result[str(key)[:80]] = "[redacted]"
            else:
                result[str(key)[:80]] = safe_json(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [safe_json(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, str): return _safe_text(value, 1000)
    if value is None or isinstance(value, bool): return value
    if isinstance(value, (int, float)): return stable_round(finite(value))
    return _safe_text(value, 200)


def contribution(feature_key: str, scoring: dict, normalized_contribution: float | None = None) -> dict:
    definition = feature(feature_key)
    reason = scoring.get("reason_code", "ABOVE_BASELINE")
    if reason not in REASON_CODES:
        raise ValueError("Unknown reason code")
    expected = scoring.get("expected_range") or [None, None]
    return {
        "feature_key": feature_key, "feature_name": definition.display_name,
        "observed_value": scoring.get("observed_value"), "baseline_value": scoring.get("expected_value"),
        "expected_range": expected, "normalized_contribution": stable_round(normalized_contribution if normalized_contribution is not None else (scoring.get("score") or 0) / 100),
        "direction": scoring.get("direction", "within"), "unit": definition.unit, "reason_code": reason,
    }


def build_explanation(*, detector_name: str, detector_version: int, observation_window: tuple, baseline_window: tuple, source_scope: str, scoring: dict, confidence: dict, severity: str, minimum_samples: int, actual_samples: int, feature_keys: list[str], seasonality: str = "none", seasonal_fallback: str | None = None, peer_group: str | None = None, data_freshness: str = "current", suppression_status: str = "not_suppressed", deduplication_status: str = "new_lineage", drift_status: str = "stable", winsorized: bool = False) -> dict:
    if not feature_keys or len(feature_keys) > 10:
        raise ValueError("An explanation requires one to ten approved features")
    reason = scoring.get("reason_code", "DATA_INSUFFICIENT")
    if reason not in REASON_CODES:
        raise ValueError("Unknown reason code")
    score_value = scoring.get("score")
    confidence_band = confidence.get("band", "insufficient")
    direction = scoring.get("direction", "within")
    plain = (
        f"{detector_name} observed {scoring.get('observed_value')} compared with the approved expected range "
        f"{scoring.get('expected_range')}. The result is a statistical deviation requiring analyst review; it is not proof of compromise."
        if score_value is not None else
        f"{detector_name} could not be scored because the approved minimum data requirement was not met."
    )
    limitations = [
        "Anomaly scores describe statistical deviation, not malicious intent or a confirmed attack.",
        "Confidence and severity are calculated and displayed separately.",
        "Only bounded derived aggregates are retained; raw evidence is not included.",
    ]
    if actual_samples < minimum_samples: limitations.append("Historical data is insufficient for a reliable score.")
    if seasonal_fallback: limitations.append(_safe_text(seasonal_fallback))
    if winsorized: limitations.append("The configured server-owned winsorization limits were applied to baseline construction; the safe original aggregate summary remains recorded.")
    contributions = [contribution(key, scoring, 1 / len(feature_keys)) for key in feature_keys]
    return safe_json({
        "detector_name": detector_name, "detector_version": detector_version,
        "observation_window": {"start": observation_window[0], "end": observation_window[1]},
        "baseline_window": {"start": baseline_window[0], "end": baseline_window[1]}, "source_scope": source_scope,
        "observed_value": scoring.get("observed_value"), "expected_value": scoring.get("expected_value"), "expected_range": scoring.get("expected_range"),
        "deviation_direction": direction, "deviation_magnitude": scoring.get("deviation_magnitude"), "anomaly_score": score_value,
        "confidence": confidence_band, "confidence_details": confidence, "severity": severity, "method": scoring.get("method"),
        "minimum_sample_requirement": minimum_samples, "actual_sample_count": actual_samples,
        "data_sufficiency": "sufficient" if actual_samples >= minimum_samples else "insufficient_data",
        "seasonality_usage": seasonality, "peer_group_usage": peer_group or "none", "data_freshness": data_freshness,
        "top_contributing_features": contributions, "fallback_behavior": seasonal_fallback or scoring.get("fallback") or "none",
        "suppression_status": suppression_status, "deduplication_status": deduplication_status, "drift_status": drift_status,
        "plain_language_reason": plain, "reason_code": reason, "winsorized_baseline": winsorized, "limitations": limitations,
    })


def dumps(explanation: dict) -> str:
    safe = safe_json(explanation)
    encoded = json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("Explanation exceeds the server bound")
    return encoded
