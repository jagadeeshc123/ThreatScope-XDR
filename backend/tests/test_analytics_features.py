import math
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models as _models  # noqa: F401
from app.database import Base
from app.modules.analytics import baselines, features
from app.modules.analytics.catalog import DETECTOR_CATALOG, FEATURE_CATALOG, METHODS


class AnalyticsFeatureTests(unittest.TestCase):
    def test_catalog_counts_identity_and_immutability(self):
        self.assertEqual(len(FEATURE_CATALOG), 42)
        self.assertEqual(len(DETECTOR_CATALOG), 64)
        self.assertEqual(len(METHODS), 10)
        self.assertTrue(all(not item.default_enabled for item in DETECTOR_CATALOG.values()))
        with self.assertRaises(Exception):
            FEATURE_CATALOG["auth.failure_count"].display_name = "changed"

    def test_catalog_marks_unsupported_detectors_honestly(self):
        unavailable = [item for item in DETECTOR_CATALOG.values() if not item.available]
        self.assertGreater(len(unavailable), 0)
        self.assertTrue(all(item.unavailable_reason for item in unavailable))
        self.assertTrue(all(item.selected_feature_keys for item in DETECTOR_CATALOG.values() if item.available))

    def test_finite_values_reject_unsafe_numeric_input(self):
        for value in (math.nan, math.inf, -math.inf, "1", True, 10**301):
            with self.subTest(value=value), self.assertRaises(ValueError):
                features.finite(value)
        with self.assertRaises(ValueError):
            features.finite(-1, non_negative=True)

    def test_deterministic_statistics(self):
        values = [1, 2, 3, 4, 100, None]
        self.assertEqual(features.mean(values), 22.0)
        self.assertEqual(features.median_value(values), 3.0)
        self.assertEqual(features.median_absolute_deviation(values), 1.0)
        self.assertEqual(features.interquartile_range(values), 2.0)
        self.assertEqual(features.percentile(values, 50), 3.0)
        self.assertEqual(features.ewma([1, 2, 3], 0.5), 2.25)
        self.assertEqual(features.ratio(1, 0), None)
        self.assertEqual(features.rate_of_change(0, 0), 0.0)
        self.assertIsNone(features.rate_of_change(1, 0))

    def test_consecutive_failures_and_seasonal_buckets(self):
        self.assertEqual(features.consecutive_failures([True, "failed", 0, False]), 3)
        stamp = datetime(2026, 7, 20, 11, tzinfo=timezone.utc)
        self.assertEqual(features.seasonal_bucket(stamp, "hour_of_day"), "hour:11")
        self.assertEqual(features.seasonal_bucket(stamp, "day_of_week"), "weekday:0")
        with self.assertRaises(ValueError):
            features.seasonal_bucket(stamp, "fixed_utc_bucket", 5)

    def test_window_and_scope_bounds(self):
        now = datetime.now(timezone.utc)
        with self.assertRaises(ValueError): features.validate_window(now, now)
        with self.assertRaises(ValueError): features.validate_window(now, now + timedelta(seconds=123), approved_only=True)
        with self.assertRaises(ValueError): features._bounded_scope({"command": "whoami"})
        with self.assertRaises(ValueError): features._bounded_scope({"peer_group_key": "race"})

    def test_baseline_sufficiency_winsorization_and_hash(self):
        first = baselines.build_statistics([1, 2, 3, 4, 100, None], minimum_samples=5, winsorize=True)
        second = baselines.build_statistics([1, 2, 3, 4, 100, None], minimum_samples=5, winsorize=True)
        self.assertEqual(first["status"], "ready")
        self.assertEqual(first["missing_value_count"], 1)
        self.assertGreater(first["winsorized_count"], 0)
        self.assertEqual(first["data_hash"], second["data_hash"])
        sparse = baselines.build_statistics([1], minimum_samples=5)
        self.assertEqual(sparse["status"], "insufficient_data")

    def test_peer_privacy_and_seasonal_fallback(self):
        now = datetime.now(timezone.utc)
        peer = baselines.build_statistics([1, 2, 3, 4, 5], minimum_samples=5, peer_group_size=4)
        self.assertEqual(peer["status"], "insufficient_data")
        seasonal = baselines.build_statistics([1, 2, 3], minimum_samples=3, timestamps=[now, now + timedelta(hours=1), now + timedelta(hours=2)], seasonality="hour_of_day")
        self.assertEqual(len(seasonal["seasonal_fallback_buckets"]), 3)
        self.assertNotIn("members", seasonal)

    def test_empty_database_feature_extraction_is_bounded(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with sessionmaker(bind=engine)() as db:
            end = datetime.now(timezone.utc); start = end - timedelta(hours=1)
            result = features.extract_feature(db, "auth.failure_count", start, end)
            self.assertEqual(result["value"], 0.0)
            self.assertEqual(result["status"], "available")
            self.assertEqual(len(result["data_hash"]), 64)
            self.assertIn("no raw evidence", result["limitations"][0].lower())
        engine.dispose()


if __name__ == "__main__": unittest.main()
