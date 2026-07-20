import math
from typing import Any

from .features import deterministic_hash, finite, stable_round


DRIFT_THRESHOLDS = {
    "mean_shift": 1.0, "median_shift": 1.0, "variance_change": 1.0, "mad_change": 1.0,
    "percentile_shift": 1.0, "missing_data_increase": 0.2, "cardinality_increase": 1.0,
    "anomaly_volume_change": 1.0, "score_distribution_change": 0.25, "confidence_distribution_change": 0.25,
    "false_positive_change": 0.2, "freshness_degradation": 0.5, "schema_version_change": 0.0,
}


def relative_change(previous: object, current: object) -> float:
    old, new = finite(previous), finite(current)
    if old == 0:
        return 0.0 if new == 0 else min(100.0, abs(new))
    return stable_round(abs(new - old) / abs(old)) or 0.0


def normalized_mean_shift(previous: dict[str, Any], current: dict[str, Any]) -> float:
    old, new = finite(previous.get("mean", 0)), finite(current.get("mean", 0))
    spread = max(finite(previous.get("standard_deviation", 0), non_negative=True), 1e-9)
    return stable_round(abs(new - old) / spread) or 0.0


def robust_median_shift(previous: dict[str, Any], current: dict[str, Any]) -> float:
    old, new = finite(previous.get("median", 0)), finite(current.get("median", 0))
    spread = max(finite(previous.get("mad", 0), non_negative=True), 1e-9)
    return stable_round(abs(new - old) / spread) or 0.0


def population_stability_index(previous_bins: list[object], current_bins: list[object]) -> float:
    if not previous_bins or len(previous_bins) != len(current_bins) or len(previous_bins) > 50:
        raise ValueError("PSI requires matching bounded fixed-bin distributions")
    old = [finite(value, non_negative=True) for value in previous_bins]
    new = [finite(value, non_negative=True) for value in current_bins]
    if sum(old) <= 0 or sum(new) <= 0:
        raise ValueError("PSI distributions require positive totals")
    score = 0.0
    for left, right in zip(old, new):
        expected = max(left / sum(old), 1e-6); actual = max(right / sum(new), 1e-6)
        score += (actual - expected) * math.log(actual / expected)
    return stable_round(score) or 0.0


def evaluate(previous: dict[str, Any], current: dict[str, Any], signal: str = "mean_shift", minimum_samples: int = 10) -> dict:
    if signal not in DRIFT_THRESHOLDS:
        raise ValueError("Unknown server-owned drift signal")
    if int(previous.get("observation_count", 0)) < minimum_samples or int(current.get("observation_count", 0)) < minimum_samples:
        return {"signal": signal, "status": "insufficient_data", "drift_score": None, "threshold": DRIFT_THRESHOLDS[signal], "confidence": "insufficient", "reason_code": "DATA_INSUFFICIENT"}
    if signal == "mean_shift": value = normalized_mean_shift(previous, current)
    elif signal == "median_shift": value = robust_median_shift(previous, current)
    elif signal in {"score_distribution_change", "confidence_distribution_change"}: value = population_stability_index(previous.get("bins", []), current.get("bins", []))
    elif signal == "schema_version_change": value = 1.0 if previous.get("schema_version") != current.get("schema_version") else 0.0
    else:
        keys = {"variance_change": "standard_deviation", "mad_change": "mad", "percentile_shift": "p95", "missing_data_increase": "missing_rate", "cardinality_increase": "cardinality", "anomaly_volume_change": "anomaly_volume", "false_positive_change": "false_positive_estimate", "freshness_degradation": "freshness"}
        value = relative_change(previous.get(keys[signal], 0), current.get(keys[signal], 0))
    threshold = DRIFT_THRESHOLDS[signal]; detected = value > threshold
    result = {"signal": signal, "status": "detected" if detected else "stable", "drift_score": value, "threshold": threshold, "confidence": "high" if min(previous["observation_count"], current["observation_count"]) >= minimum_samples * 2 else "medium", "reason_code": "DETECTOR_DRIFTED" if detected else "DISTRIBUTION_SHIFT", "automatic_retraining": False}
    result["current_data_hash"] = deterministic_hash(current)
    return result
