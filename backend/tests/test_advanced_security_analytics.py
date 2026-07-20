import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.models import LoginAttempt, SecurityAuditEvent, UserAccount
from app.modules.access_control.user_service import create_user
from app.modules.analytics.models import AnalyticsDetector, AnalyticsJob, AnalyticsReport, SecurityAnomaly
from app.modules.analytics.service import REPORT_SECTIONS, analytics_diagnostics, queue_job, recover_stale_jobs
from app.modules.integrations.models import IntegrationOutboxEvent
from app.modules.unified_correlation.models import IncidentCase
from tests.access_helpers import authenticate_admin


class AdvancedSecurityAnalyticsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
        cls.factory=sessionmaker(bind=cls.engine)
        def override():
            with cls.factory() as db: yield db
        app.dependency_overrides[get_db]=override
        cls.client=TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close();app.dependency_overrides.clear();cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine)
        authenticate_admin(self.client,self.factory)

    def configuration(self):
        return {"template_key":"authentication_failure_burst","feature_keys":["auth.failure_count"],"method":"robust_z_score","observation_window_seconds":3600,"baseline_lookback_seconds":2592000,"minimum_historical_windows":5,"seasonality":"none","threshold_parameters":{"threshold":3},"severity_mapping":{"informational":25,"low":40,"medium":55,"high":70,"critical":85},"confidence_rules":{},"cooldown_seconds":3600,"deduplication_period_seconds":3600,"maximum_late_arrival_seconds":900,"scoring_frequency_seconds":3600,"source_scope":"platform","winsorize":True,"ensemble":[]}

    def create_detector(self):
        response=self.client.post("/api/analytics/detectors",json={"detector_key":"test.authentication.deviation","name":"Authentication deviation","description":"Bounded deterministic authentication analytics test.","configuration":self.configuration(),"reason":"Focused integration test"})
        self.assertEqual(response.status_code,201,response.text)
        return response.json()

    def login(self,username,role):
        password="Valid-Analytics-Password-83!"
        with self.factory() as db:
            create_user(db,username=username,display_name=username,password=password,role_keys=[role],must_change_password=False)
        self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None)
        response=self.client.post("/api/auth/login",json={"username":username,"password":password});self.assertEqual(response.status_code,200,response.text)
        self.client.headers["X-CSRF-Token"]=self.client.get("/api/auth/csrf").json()["csrf_token"]

    def test_catalog_overview_metrics_and_schema(self):
        features=self.client.get("/api/analytics/catalog/features");detectors=self.client.get("/api/analytics/catalog/detectors");methods=self.client.get("/api/analytics/catalog/methods")
        self.assertEqual(features.status_code,200);self.assertEqual(len(features.json()["items"]),42)
        self.assertEqual(len(detectors.json()["items"]),64);self.assertTrue(detectors.json()["immutable"])
        self.assertEqual(len(methods.json()["items"]),10)
        overview=self.client.get("/api/analytics/overview").json();self.assertFalse(overview["automatic_containment"]);self.assertFalse(overview["external_ai"])
        with self.factory() as db:
            diagnostics=analytics_diagnostics(db);self.assertTrue(diagnostics["tables_available"]);self.assertEqual(diagnostics["feature_catalog_loaded"],42)

    def test_detector_versioning_optimistic_lock_and_no_early_activation(self):
        detector=self.create_detector();self.assertEqual(detector["lifecycle_state"],"draft")
        detail=self.client.get(f"/api/analytics/detectors/{detector['id']}").json();self.assertIsNone(detail["active_version"])
        versions=self.client.get(f"/api/analytics/detectors/{detector['id']}/versions").json();self.assertEqual(versions["items"][0]["version_number"],1)
        invalid=self.client.patch(f"/api/analytics/detectors/{detector['id']}",json={"optimistic_lock_version":999,"name":"Conflict"});self.assertEqual(invalid.status_code,409)
        activation=self.client.post(f"/api/analytics/detectors/{detector['id']}/activate",json={"optimistic_lock_version":1,"reason":"No quality evidence yet","limited_validation":False});self.assertEqual(activation.status_code,409)
        with self.factory() as db:self.assertEqual(db.get(AnalyticsDetector,detector["id"]).lifecycle_state,"draft")

    def test_strict_configuration_and_csrf(self):
        payload={"detector_key":"test.unsafe","name":"Unsafe","description":"Should fail strict schema.","configuration":{**self.configuration(),"python":"import os"},"reason":"Unsafe input"}
        self.assertEqual(self.client.post("/api/analytics/detectors",json=payload).status_code,422)
        token=self.client.headers.pop("X-CSRF-Token")
        denied=self.client.post("/api/analytics/detectors",json={"detector_key":"test.csrf","name":"CSRF","description":"Must be rejected without CSRF.","configuration":self.configuration(),"reason":"CSRF test"})
        self.assertEqual(denied.status_code,403)
        self.client.headers["X-CSRF-Token"]=token

    def test_role_matrix_and_direct_backend_denial(self):
        self.login("analytics.registered","registered_user")
        self.assertEqual(self.client.get("/api/analytics/detectors").status_code,403)
        self.assertEqual(self.client.post("/api/analytics/process-due",json={"batch_size":1}).status_code,403)
        authenticate_admin(self.client,self.factory);detector=self.create_detector()
        self.login("analytics.auditor","auditor")
        self.assertEqual(self.client.get(f"/api/analytics/detectors/{detector['id']}").status_code,200)
        self.assertEqual(self.client.post(f"/api/analytics/detectors/{detector['id']}/disable",json={"optimistic_lock_version":1,"reason":"Must be denied"}).status_code,403)

    def test_job_idempotency_stale_recovery_and_no_retry(self):
        with self.factory() as db:
            actor=db.query(UserAccount).filter_by(username_normalized="test.admin").one()
            first=queue_job(db,"report_generation",None,actor.id,{},"analytics-job-same-key")
            second=queue_job(db,"report_generation",None,actor.id,{"ignored":"by idempotency"},"analytics-job-same-key")
            self.assertEqual(first.id,second.id);self.assertEqual(db.query(AnalyticsJob).count(),1)
            first.status="running";first.heartbeat_at=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(hours=1);db.commit()
            self.assertEqual(recover_stale_jobs(db),1);db.refresh(first);self.assertEqual(first.status,"failed");self.assertEqual(first.error_code,"ANALYTICS_JOB_STALE")

    def test_static_report_has_40_sections_is_escaped_and_idempotent(self):
        end=datetime.now(timezone.utc);start=end-timedelta(days=7)
        payload={"title":"<script>alert(1)</script> Analytics","report_type":"analytics_summary","period_start":start.isoformat(),"period_end":end.isoformat(),"scope":"platform","filters":{},"idempotency_key":"report-idempotency-18"}
        first=self.client.post("/api/analytics/reports",json=payload);self.assertEqual(first.status_code,201,first.text)
        second=self.client.post("/api/analytics/reports",json=payload);self.assertEqual(second.status_code,201);self.assertEqual(first.json()["id"],second.json()["id"])
        html=self.client.get(f"/api/analytics/reports/{first.json()['id']}/html").text
        self.assertEqual(len(REPORT_SECTIONS),40);self.assertEqual(html.count("<section>"),40)
        self.assertNotIn("<script>",html);self.assertNotIn("http://",html);self.assertNotIn("https://",html)
        self.assertIn("not proof of compromise",html)
        self.assertEqual(hashlib.sha256(html.encode()).hexdigest(),first.json()["content_sha256"])
        with self.factory() as db:self.assertEqual(db.query(AnalyticsReport).count(),1)

    def test_mutations_append_integrity_audit(self):
        detector=self.create_detector()
        with self.factory() as db:
            events=db.query(SecurityAuditEvent).filter(SecurityAuditEvent.resource_type=="analytics_detector",SecurityAuditEvent.resource_id==str(detector["id"])).all()
            self.assertGreaterEqual(len(events),1)
            self.assertTrue(all(event.event_hash and event.previous_event_hash is not None for event in events))

    def test_pagination_bounds_and_safe_empty_anomaly_shape(self):
        for index in range(3):
            payload={"detector_key":f"test.detector.{index}","name":f"Detector {index}","description":"Pagination test detector.","configuration":self.configuration(),"reason":"Pagination test"}
            self.assertEqual(self.client.post("/api/analytics/detectors",json=payload).status_code,201)
        page=self.client.get("/api/analytics/detectors?page=2&page_size=2").json();self.assertEqual(page["total"],3);self.assertEqual(len(page["items"]),1);self.assertEqual(page["pages"],2)
        self.assertEqual(self.client.get("/api/analytics/detectors?page_size=101").status_code,422)
        anomalies=self.client.get("/api/analytics/anomalies?page_size=100").json();self.assertEqual(anomalies["items"],[]);self.assertEqual(anomalies["total"],0)

    def test_end_to_end_baseline_backtest_validation_scoring_review_drift_and_case(self):
        configuration={**self.configuration(),"baseline_lookback_seconds":21600}
        created=self.client.post("/api/analytics/detectors",json={"detector_key":"test.e2e.auth","name":"E2E authentication deviation","description":"End-to-end deterministic anomaly lifecycle test.","configuration":configuration,"reason":"E2E test"})
        self.assertEqual(created.status_code,201,created.text);detector=created.json()
        version=self.client.get(f"/api/analytics/detectors/{detector['id']}/versions").json()["items"][0]
        cutoff=datetime(2026,7,1,6,0,0)
        with self.factory() as db:
            for hour in range(6): db.add(LoginAttempt(username_hash="e2e",client_ip_hash="local",success=False,failure_reason_code="TEST",attempted_at=cutoff-timedelta(hours=hour,minutes=30)))
            db.commit()
        baseline=self.client.post("/api/analytics/baselines/build",json={"detector_version_id":version["id"],"cutoff":cutoff.isoformat()+"Z","source_scope":"platform","source_entity_identifier":"","peer_group_identifier":"","idempotency_key":"baseline-e2e-18"})
        self.assertEqual(baseline.status_code,201,baseline.text);baseline_item=baseline.json()["items"][0];self.assertEqual(baseline_item["baseline_status"],"ready")
        backtest=self.client.post("/api/analytics/backtests",json={"detector_version_id":version["id"],"range_start":cutoff.isoformat()+"Z","range_end":(cutoff+timedelta(hours=2)).isoformat()+"Z","scoring_interval_seconds":3600,"idempotency_key":"backtest-e2e-18"})
        self.assertEqual(backtest.status_code,201,backtest.text);self.assertFalse(backtest.json()["future_leakage_detected"])
        validation=self.client.post(f"/api/analytics/detectors/{detector['id']}/validate",json={"optimistic_lock_version":1,"reason":"Validate E2E evidence","limited_validation":False})
        self.assertEqual(validation.status_code,200,validation.text);self.assertTrue(validation.json()["quality_gate_passed"])
        activated=self.client.post(f"/api/analytics/detectors/{detector['id']}/activate",json={"optimistic_lock_version":2,"reason":"Explicit E2E activation","limited_validation":False})
        self.assertEqual(activated.status_code,200,activated.text);self.assertEqual(activated.json()["lifecycle_state"],"active")
        observation_end=cutoff+timedelta(hours=3)
        with self.factory() as db:
            for minute in range(10): db.add(LoginAttempt(username_hash=f"spike-{minute}",client_ip_hash="local",success=False,failure_reason_code="TEST",attempted_at=observation_end-timedelta(minutes=minute+1)))
            db.commit()
        job_ids=[]
        for suffix in ("one","two"):
            queued=self.client.post("/api/analytics/jobs",json={"job_type":"score_window","detector_version_id":version["id"],"payload":{"observation_end":observation_end.isoformat()+"Z"},"idempotency_key":f"score-e2e-{suffix}"})
            self.assertEqual(queued.status_code,201,queued.text);job_ids.append(queued.json()["id"])
        processed=self.client.post("/api/analytics/process-due",json={"batch_size":10});self.assertEqual(processed.status_code,200,processed.text);self.assertEqual(processed.json()["succeeded"],2)
        with self.factory() as db:
            anomaly=db.query(SecurityAnomaly).one();self.assertEqual(anomaly.occurrence_count,2);self.assertGreaterEqual(anomaly.anomaly_score,70);anomaly_id=anomaly.id
            self.assertEqual(db.query(IntegrationOutboxEvent).filter_by(event_type="anomaly.created").count(),1)
            case=IncidentCase(case_key="CASE-ANALYTICS-18",title="Analytics review",summary="Explicit test case",case_type="investigation",severity="high",priority="P2",confidence="medium",risk_score=70,status="new",source_module_count=1,evidence_count=0);db.add(case);db.commit();case_id=case.id
        explanation=self.client.get(f"/api/analytics/anomalies/{anomaly_id}/explanation");self.assertEqual(explanation.status_code,200);self.assertIn("not proof of compromise",str(explanation.json()).lower())
        reviewed=self.client.post(f"/api/analytics/anomalies/{anomaly_id}/acknowledge",json={"reason":"Explicit analyst review","optimistic_lock_version":1});self.assertEqual(reviewed.status_code,200,reviewed.text)
        feedback=self.client.post(f"/api/analytics/anomalies/{anomaly_id}/feedback",json={"label":"likely_true_positive","confidence":"medium","reason":"Synthetic spike is expected in this test"});self.assertEqual(feedback.status_code,201,feedback.text)
        linked=self.client.post(f"/api/analytics/anomalies/{anomaly_id}/link-case",json={"case_id":case_id,"reason":"Explicit case evidence link","optimistic_lock_version":2,"idempotency_key":"case-link-e2e-18"});self.assertEqual(linked.status_code,200,linked.text)
        drift=self.client.post("/api/analytics/drift/evaluate",json={"detector_version_id":version["id"],"baseline_id":baseline_item["id"],"signal":"mean_shift","current_distribution":{"observation_count":20,"mean":25,"median":25,"standard_deviation":1,"mad":1},"minimum_samples":5})
        self.assertEqual(drift.status_code,201,drift.text);self.assertEqual(drift.json()["status"],"detected")
        with self.factory() as db:
            self.assertEqual(db.get(AnalyticsDetector,detector["id"]).lifecycle_state,"degraded")
            self.assertEqual(db.get(IncidentCase,case_id).status,"new")


if __name__ == "__main__": unittest.main()
