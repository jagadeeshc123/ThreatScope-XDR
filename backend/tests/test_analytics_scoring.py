import unittest

from app.modules.analytics import drift, evaluation, scoring


class AnalyticsScoringTests(unittest.TestCase):
    baseline = {"mean": 10, "median": 10, "standard_deviation": 2, "mad": 2, "minimum": 5, "maximum": 15, "iqr": 4, "percentiles": {"5": 6, "25": 8, "50": 10, "75": 12, "95": 14}, "previous": 10, "ewma": 10}

    def test_all_nine_atomic_methods_are_bounded_deterministic(self):
        methods = ["static_threshold", "z_score", "robust_z_score", "iqr_deviation", "percentile_deviation", "ewma_deviation", "rate_of_change", "consecutive_failures", "seasonal_deviation"]
        for method in methods:
            baseline = dict(self.baseline)
            if method == "seasonal_deviation": baseline["seasonal_bucket"] = {"status":"ready", **self.baseline}
            with self.subTest(method=method):
                first = scoring.score(method, 25, baseline, {"threshold":3, "value":20, "count_threshold":3})
                self.assertEqual(first, scoring.score(method, 25, baseline, {"threshold":3, "value":20, "count_threshold":3}))
                self.assertGreaterEqual(first["score"], 0); self.assertLessEqual(first["score"], 100)
                self.assertTrue(first["deterministic"])

    def test_zero_spread_fallback_is_explicit(self):
        result = scoring.score("z_score", 2, {"mean":1,"standard_deviation":0}, {"threshold":3})
        self.assertEqual(result["score"], 100)
        self.assertIn("Zero variance", result["fallback"])

    def test_ensemble_participation_and_normalization(self):
        insufficient = scoring.weighted_ensemble([{"score":80}], minimum_participation=2)
        self.assertEqual(insufficient["status"], "insufficient_data")
        result = scoring.weighted_ensemble([{"score":80},{"score":40}], [3,1])
        self.assertEqual(result["score"], 70)
        self.assertEqual(sum(result["normalized_weights"]), 1)
        with self.assertRaises(ValueError): scoring.weighted_ensemble([{"score":1},{"score":2}], [0,0])

    def test_confidence_is_separate_from_severity(self):
        low = scoring.confidence(sample_count=5, minimum_samples=10)
        self.assertEqual(low["band"], "insufficient")
        self.assertEqual(scoring.severity(100, low["band"]), "medium")
        high = scoring.confidence(sample_count=40, minimum_samples=10)
        self.assertEqual(high["band"], "high")
        self.assertEqual(scoring.severity(90, high["band"]), "critical")

    def test_quality_metrics_make_no_unsupported_claim(self):
        empty = evaluation.quality_metrics([], [{"id":1}])
        self.assertIsNone(empty["precision_estimate"])
        self.assertIsNone(empty["recall"]); self.assertIsNone(empty["f1_score"])
        self.assertFalse(empty["accuracy_claim_available"])
        reviewed = evaluation.quality_metrics([{"anomaly_id":1,"analyst_user_id":2,"revision_number":1,"label":"false_positive"},{"anomaly_id":1,"analyst_user_id":2,"revision_number":2,"label":"confirmed_true_positive"}], [{"id":1}])
        self.assertEqual(reviewed["confirmed_count"], 1)
        self.assertEqual(reviewed["reviewed_anomaly_count"], 1)

    def test_quality_gates_never_waive_safety(self):
        result = evaluation.quality_gates(sample_count=10,minimum_samples=5,baseline_finite=True,deterministic_backtest=True,candidate_count=1,maximum_candidates=100,duplicate_rate=0,explanations_complete=True,unresolved_errors=[],unsupported_features=[],security_policy_violations=["unsafe"],future_leakage=False,implementation_version="18",limited_validation=True)
        self.assertFalse(result["passed"])
        self.assertFalse(result["accuracy_claimed"])

    def test_drift_and_no_auto_retraining(self):
        previous={"observation_count":20,"mean":10,"standard_deviation":1,"median":10,"mad":1}
        current={"observation_count":20,"mean":20,"standard_deviation":1,"median":20,"mad":1}
        result=drift.evaluate(previous,current)
        self.assertEqual(result["status"],"detected")
        self.assertFalse(result["automatic_retraining"])
        sparse=drift.evaluate({"observation_count":1},{"observation_count":1})
        self.assertEqual(sparse["status"],"insufficient_data")

    def test_psi_is_bounded_and_validated(self):
        value=drift.population_stability_index([50,50],[80,20])
        self.assertGreater(value,0)
        with self.assertRaises(ValueError): drift.population_stability_index([1],[1,2])


if __name__ == "__main__": unittest.main()
