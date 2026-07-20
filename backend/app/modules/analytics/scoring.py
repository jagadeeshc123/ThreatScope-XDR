import math
from typing import Any

from .catalog import METHODS
from .features import finite, stable_round


def _bounded(value: float) -> float:
    return round(min(100.0, max(0.0, finite(value))), 2)


def _magnitude_score(magnitude: float, threshold: float) -> float:
    magnitude, threshold = abs(finite(magnitude)), abs(finite(threshold))
    if threshold <= 0:
        raise ValueError("Scoring threshold must be positive")
    if magnitude == 0:
        return 0.0
    # Crossing a configured statistical threshold enters the high-anomaly band.
    return _bounded(70.0 * magnitude / threshold)


def _direction(observed: float, expected: float) -> str:
    return "above" if observed > expected else "below" if observed < expected else "within"


def score(method: str, observed: object, baseline: dict[str, Any], parameters: dict[str, Any] | None = None) -> dict:
    if method not in METHODS or method == "weighted_ensemble":
        raise ValueError("Unknown or inapplicable server-owned scoring method")
    observed_value = finite(observed, non_negative=True)
    baseline = dict(baseline or {})
    parameters = dict(parameters or {})
    threshold = finite(parameters.get("threshold", 3.0))
    expected = baseline.get("mean")
    low = baseline.get("minimum")
    high = baseline.get("maximum")
    fallback = None
    reason = "ABOVE_BASELINE"

    if method == "static_threshold":
        static = finite(parameters.get("value", parameters.get("threshold_value", threshold)), non_negative=True)
        direction = parameters.get("direction", "above")
        if direction not in {"above", "below"}:
            raise ValueError("Static-threshold direction is invalid")
        crossed = observed_value >= static if direction == "above" else observed_value <= static
        magnitude = abs(observed_value - static)
        denominator = max(abs(static), 1.0)
        result_score = _bounded(70 + min(30, magnitude / denominator * 30)) if crossed else _bounded(max(0, 24 * observed_value / denominator) if direction == "above" else 0)
        expected, low, high = static, None if direction == "above" else static, static if direction == "above" else None
    elif method == "z_score":
        center = finite(baseline.get("mean", 0))
        spread = finite(baseline.get("standard_deviation", 0), non_negative=True)
        if spread == 0:
            magnitude = 0.0 if observed_value == center else abs(observed_value - center)
            result_score = 0.0 if magnitude == 0 else 100.0
            fallback = "Zero variance baseline; any non-zero deviation is explicit and confidence is limited."
        else:
            magnitude = abs((observed_value - center) / spread); result_score = _magnitude_score(magnitude, threshold)
        expected, low, high = center, center - threshold * spread, center + threshold * spread
    elif method == "robust_z_score":
        center = finite(baseline.get("median", 0))
        spread = finite(baseline.get("mad", 0), non_negative=True)
        if spread == 0:
            magnitude = 0.0 if observed_value == center else abs(observed_value - center)
            result_score = 0.0 if magnitude == 0 else 100.0
            fallback = "Zero MAD baseline; any non-zero deviation is explicit and confidence is limited."
        else:
            magnitude = abs(0.67448975 * (observed_value - center) / spread); result_score = _magnitude_score(magnitude, threshold)
        expected, low, high = center, center - threshold * spread / 0.67448975 if spread else center, center + threshold * spread / 0.67448975 if spread else center
    elif method == "iqr_deviation":
        percentiles = baseline.get("percentiles") or {}
        q1 = finite(percentiles.get("25", baseline.get("q1", baseline.get("median", 0))))
        q3 = finite(percentiles.get("75", baseline.get("q3", baseline.get("median", 0))))
        iqr = finite(baseline.get("iqr", q3 - q1), non_negative=True)
        multiplier = finite(parameters.get("multiplier", 1.5), non_negative=True)
        low, high = q1 - multiplier * iqr, q3 + multiplier * iqr
        outside = max(low - observed_value, observed_value - high, 0)
        magnitude = outside / iqr if iqr else (0 if outside == 0 else outside)
        result_score = _magnitude_score(magnitude, 1.0) if outside else 0.0
        expected = (q1 + q3) / 2
        if iqr == 0 and outside: fallback = "Zero IQR baseline; confidence is limited."
    elif method == "percentile_deviation":
        percentiles = baseline.get("percentiles") or {}
        low = finite(percentiles.get(str(int(parameters.get("low_percentile", 5))), baseline.get("minimum", 0)))
        high = finite(percentiles.get(str(int(parameters.get("high_percentile", 95))), baseline.get("maximum", 0)))
        expected = finite(baseline.get("median", (low + high) / 2))
        width = max(high - low, 0)
        outside = max(low - observed_value, observed_value - high, 0)
        magnitude = outside / width if width else (0 if outside == 0 else outside)
        result_score = _magnitude_score(magnitude, finite(parameters.get("distance_threshold", 0.25))) if outside else 0.0
    elif method == "ewma_deviation":
        expected = finite(baseline.get("ewma", baseline.get("mean", 0)))
        spread = finite(baseline.get("standard_deviation", 0), non_negative=True)
        magnitude = abs(observed_value - expected) / spread if spread else (0 if observed_value == expected else abs(observed_value - expected))
        result_score = _magnitude_score(magnitude, threshold)
        low, high = expected - threshold * spread, expected + threshold * spread
        if spread == 0 and magnitude: fallback = "Zero-variance EWMA baseline; confidence is limited."
    elif method == "rate_of_change":
        previous = finite(baseline.get("previous", baseline.get("mean", 0)), non_negative=True)
        if previous == 0:
            magnitude = 0 if observed_value == 0 else observed_value
            fallback = "Previous value was zero; an absolute bounded change was used."
        else: magnitude = abs((observed_value - previous) / previous)
        change_threshold = finite(parameters.get("change_threshold", threshold if threshold <= 1 else 0.5), non_negative=True)
        result_score = _magnitude_score(magnitude, max(change_threshold, 0.000001)); expected = previous
        low, high = previous * (1 - change_threshold), previous * (1 + change_threshold); reason = "RAPID_GROWTH" if observed_value > previous else "BELOW_BASELINE"
    elif method == "consecutive_failures":
        required = int(parameters.get("count_threshold", max(1, int(threshold))))
        if not 1 <= required <= 1000: raise ValueError("Consecutive-failure threshold is outside the server bound")
        magnitude = observed_value / required
        result_score = _bounded(70 * magnitude); expected, low, high = 0.0, 0.0, float(required - 1); reason = "CONSECUTIVE_FAILURES"
    elif method == "seasonal_deviation":
        selected = baseline.get("seasonal_bucket")
        if not isinstance(selected, dict) or selected.get("status") != "ready":
            selected = baseline
            fallback = "Seasonal bucket was sparse or unavailable; the non-seasonal baseline was used."
        nested = score("robust_z_score", observed_value, selected, parameters)
        nested.update({"method": method, "fallback": fallback, "reason_code": "SEASONAL_DEVIATION"})
        return nested
    else:
        raise ValueError("Unsupported scoring method")

    expected_number = finite(expected) if expected is not None else None
    return {
        "method": method, "score": _bounded(result_score), "observed_value": stable_round(observed_value),
        "expected_value": stable_round(expected_number), "expected_range": [stable_round(low), stable_round(high)],
        "direction": _direction(observed_value, expected_number if expected_number is not None else observed_value),
        "deviation_magnitude": stable_round(magnitude), "threshold": stable_round(threshold),
        "threshold_crossed": result_score >= 70, "reason_code": reason if observed_value >= (expected_number or 0) else "BELOW_BASELINE",
        "fallback": fallback, "deterministic": True,
    }


def weighted_ensemble(outputs: list[dict], weights: list[object] | None = None, minimum_participation: int = 2) -> dict:
    if not 2 <= minimum_participation <= 10:
        raise ValueError("Ensemble participation bound is invalid")
    valid = [item for item in outputs[:10] if isinstance(item, dict) and item.get("score") is not None]
    if len(valid) < minimum_participation:
        return {"method": "weighted_ensemble", "score": None, "status": "insufficient_data", "participants": len(valid), "minimum_participation": minimum_participation, "reason_code": "DATA_INSUFFICIENT"}
    supplied = list(weights or [1.0] * len(outputs))[:len(outputs)]
    pairs = []
    for index, item in enumerate(outputs[:10]):
        if not isinstance(item, dict) or item.get("score") is None: continue
        weight = finite(supplied[index] if index < len(supplied) else 1.0, non_negative=True)
        pairs.append((item, weight))
    total = sum(weight for _, weight in pairs)
    if total <= 0: raise ValueError("Ensemble weights must have a positive total")
    normalized = [weight / total for _, weight in pairs]
    result = sum(finite(item["score"], non_negative=True) * weight for (item, _), weight in zip(pairs, normalized))
    return {
        "method": "weighted_ensemble", "score": _bounded(result), "status": "scored",
        "participants": len(pairs), "minimum_participation": minimum_participation,
        "normalized_weights": [round(item, 6) for item in normalized],
        "threshold_crossed": result >= 70, "reason_code": "DISTRIBUTION_SHIFT", "deterministic": True,
    }


def confidence(*, sample_count: int, minimum_samples: int, missing_rate: float = 0, baseline_stability: float = 1, seasonal_sufficient: bool = True, method_agreement: float = 1, data_freshness: float = 1, feature_completeness: float = 1, validation_state: str = "validated", drifted: bool = False) -> dict:
    if sample_count < minimum_samples:
        return {"band": "insufficient", "value": 0.0, "reasons": ["Historical sample requirement is not met."]}
    factors = {
        "sample_sufficiency": min(1.0, sample_count / max(minimum_samples * 2, 1)),
        "missing_data": 1 - min(1.0, max(0.0, finite(missing_rate))),
        "baseline_stability": min(1.0, max(0.0, finite(baseline_stability))),
        "seasonal_sufficiency": 1.0 if seasonal_sufficient else 0.5,
        "method_agreement": min(1.0, max(0.0, finite(method_agreement))),
        "data_freshness": min(1.0, max(0.0, finite(data_freshness))),
        "feature_completeness": min(1.0, max(0.0, finite(feature_completeness))),
        "validation": 1.0 if validation_state in {"validated", "active"} else 0.6,
        "drift": 0.5 if drifted else 1.0,
    }
    value = round(sum(factors.values()) / len(factors) * 100, 2)
    band = "high" if value >= 80 else "medium" if value >= 55 else "low"
    reasons = [key.replace("_", " ") for key, factor in factors.items() if factor < 0.75]
    return {"band": band, "value": value, "factors": {key: round(value, 4) for key, value in factors.items()}, "reasons": reasons}


def severity(score_value: object, confidence_band: str, *, criticality: float = 1.0, occurrence_count: int = 1, source_risk: float = 1.0) -> str:
    value = finite(score_value, non_negative=True) * min(1.5, max(0.5, finite(criticality))) * min(1.25, 1 + max(0, occurrence_count - 1) * 0.05) * min(1.25, max(0.5, finite(source_risk)))
    value = min(100.0, value)
    if confidence_band in {"insufficient", "low"}: value = min(value, 69.0)
    return "critical" if value >= 85 else "high" if value >= 70 else "medium" if value >= 50 else "low" if value >= 25 else "informational"
