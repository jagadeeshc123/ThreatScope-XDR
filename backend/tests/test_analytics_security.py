import inspect
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from app.modules.analytics import catalog, explainability, features, scoring, suppressions


class AnalyticsSecurityTests(unittest.TestCase):
    def test_recursive_redaction_and_truncation(self):
        result=explainability.safe_json({"token":"secret","password":"secret","title":"safe","nested":{"authorization":"Bearer x"},"large":"x"*3000})
        self.assertEqual(result["token"],"[redacted]")
        self.assertNotIn("Bearer x",str(result))
        self.assertLessEqual(len(result["large"]),1000)

    def test_explanation_uses_cautious_language(self):
        now=datetime.now(timezone.utc)
        value=explainability.build_explanation(detector_name="Auth deviation",detector_version=1,observation_window=(now-timedelta(hours=1),now),baseline_window=(now-timedelta(days=30),now-timedelta(hours=1)),source_scope="platform",scoring={"method":"robust_z_score","score":80,"observed_value":20,"expected_value":5,"expected_range":[1,10],"direction":"above","reason_code":"ABOVE_BASELINE","deviation_magnitude":3,"threshold":3,"fallback":None},confidence={"band":"high","value":90,"reasons":[]},severity="high",minimum_samples=5,actual_samples=40,feature_keys=["auth.failure_count"],drift_status="stable")
        encoded=str(value).lower()
        self.assertIn("not proof of compromise",encoded)
        for prohibited in ("100% accurate","zero false positives","user is malicious","confirmed an attack"):
            self.assertNotIn(prohibited,encoded)

    def test_suppression_scope_rejects_protected_and_wildcard_input(self):
        with self.assertRaises(ValueError): suppressions.validate_scope({"approved_tag":"gender"},is_admin=True)
        with self.assertRaises(ValueError): suppressions.validate_scope({"source_entity_identifier":"*"},is_admin=True)
        with self.assertRaises(PermissionError): suppressions.validate_scope({"approved_tag":"known-maintenance"},is_admin=False)
        with self.assertRaises(ValueError): suppressions.validate_scope({"command":"calc.exe"},is_admin=True)

    def test_suppression_period_is_bounded(self):
        now=datetime.now(timezone.utc)
        with self.assertRaises(ValueError): suppressions.validate_period(now,now+timedelta(days=91))
        with self.assertRaises(ValueError): suppressions.validate_period(now,now+timedelta(hours=5),emergency=True)

    def test_no_arbitrary_execution_or_unsafe_serialization_tokens(self):
        source="\n".join(inspect.getsource(module) for module in (catalog,features,scoring,suppressions,explainability))
        for forbidden in ("subprocess","os.system","pickle.loads","joblib.load","eval(","exec(","importlib"):
            self.assertNotIn(forbidden,source)

    def test_pure_scoring_does_not_touch_network_or_processes(self):
        with patch("socket.socket",side_effect=AssertionError("network attempted")),patch("subprocess.Popen",side_effect=AssertionError("process attempted")):
            result=scoring.score("z_score",20,{"mean":10,"standard_deviation":2},{"threshold":3})
        self.assertGreater(result["score"],0)

    def test_suppression_matching_does_not_delete_evidence(self):
        now=datetime.now(timezone.utc).replace(tzinfo=None); item=SimpleNamespace(enabled=True,starts_at=now-timedelta(hours=1),ends_at=now+timedelta(hours=1),detector_id=1,source_entity_type="soc_alert",source_entity_identifier="7",minimum_score=50,maximum_score=90,reason="maintenance")
        before=dict(item.__dict__)
        self.assertTrue(suppressions.matches(item,1,"soc_alert","7",75,now))
        self.assertEqual(before,item.__dict__)


if __name__ == "__main__": unittest.main()
