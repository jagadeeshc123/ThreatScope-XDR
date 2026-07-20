from statistics import median

from .features import deterministic_hash, stable_round


def quality_metrics(feedback: list[dict], anomalies: list[dict] | None = None, suppression_hits: int = 0) -> dict:
    anomalies = anomalies or []
    latest: dict[tuple, dict] = {}
    for item in feedback:
        key = (item.get("anomaly_id"), item.get("analyst_user_id"))
        if key not in latest or int(item.get("revision_number", 1)) > int(latest[key].get("revision_number", 1)): latest[key] = item
    labels = list(latest.values()); reviewed_ids = {item.get("anomaly_id") for item in labels}
    confirmed = sum(item.get("label") in {"confirmed_true_positive", "likely_true_positive"} for item in labels)
    dismissed = sum(item.get("label") in {"false_positive", "benign_expected_behavior"} for item in labels)
    reviewed = confirmed + dismissed
    review_times = [float(item["review_time_seconds"]) for item in labels if item.get("review_time_seconds") is not None]
    total = len(anomalies)
    return {
        "reviewed_anomaly_count": len(reviewed_ids), "confirmed_count": confirmed, "dismissed_count": dismissed,
        "precision_estimate": stable_round(confirmed / reviewed) if reviewed else None,
        "false_positive_estimate": stable_round(dismissed / reviewed) if reviewed else None,
        "recall": None, "f1_score": None, "accuracy_claim_available": False,
        "metric_limitation": None if reviewed else "Precision and recall cannot be established without reviewed labels; operational proxy metrics are not accuracy.",
        "review_coverage": stable_round(len(reviewed_ids) / total) if total else 0.0,
        "median_review_time_seconds": stable_round(median(review_times)) if review_times else None,
        "duplicate_rate": stable_round(sum(int(item.get("occurrence_count", 1)) > 1 for item in anomalies) / total) if total else 0.0,
        "suppression_hit_rate": stable_round(suppression_hits / (total + suppression_hits)) if total + suppression_hits else 0.0,
    }


def quality_gates(*, sample_count: int, minimum_samples: int, baseline_finite: bool, deterministic_backtest: bool, candidate_count: int, maximum_candidates: int, duplicate_rate: float, explanations_complete: bool, unresolved_errors: list, unsupported_features: list, security_policy_violations: list, future_leakage: bool, implementation_version: str | None, reviewed_metrics: dict | None = None, limited_validation: bool = False) -> dict:
    gates = [
        ("sufficient_history", sample_count >= minimum_samples), ("finite_baseline", baseline_finite),
        ("deterministic_backtest", deterministic_backtest), ("bounded_candidate_volume", candidate_count <= maximum_candidates),
        ("duplicate_rate", duplicate_rate <= 0.8), ("explanations", explanations_complete),
        ("validation_errors", not unresolved_errors), ("supported_features", not unsupported_features),
        ("security_policy", not security_policy_violations), ("no_future_leakage", not future_leakage),
        ("implementation_version", bool(implementation_version)),
    ]
    if reviewed_metrics and reviewed_metrics.get("reviewed_anomaly_count", 0) >= 10:
        gates.extend([("reviewed_precision", (reviewed_metrics.get("precision_estimate") or 0) >= 0.5), ("reviewed_false_positive", (reviewed_metrics.get("false_positive_estimate") or 1) <= 0.5)])
    passed = all(value for _, value in gates)
    if limited_validation:
        # Limited validation waives only absent reviewed-label gates, never safety/data gates.
        passed = all(value for key, value in gates if not key.startswith("reviewed_"))
    result = {"passed": passed, "limited_validation": limited_validation, "gates": [{"gate": key, "passed": value} for key, value in gates], "accuracy_claimed": False}
    result["deterministic_hash"] = deterministic_hash(result)
    return result
