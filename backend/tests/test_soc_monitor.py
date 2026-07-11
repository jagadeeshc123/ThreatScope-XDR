import io
import json
import os
import socket
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.soc_monitor.detection_rules import seed_default_rules
from app.modules.soc_monitor.normalization import normalize_event, normalize_event_type, normalize_outcome, parse_timestamp
from app.modules.soc_monitor.parsers import parse_access_log, parse_auth_log, parse_csv, parse_jsonl, parse_key_value
from app.modules.soc_monitor.redaction import redact, redact_text
from app.modules.soc_monitor.simulator import generate
from app.modules.soc_monitor.correlation import qualifying_windows


FIXTURES = Path(__file__).parent / "fixtures" / "soc_monitor"


class SocMonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cls.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        def override_get_db():
            db = cls.session_factory()
            try: yield db
            finally: db.close()
        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close(); app.dependency_overrides.clear(); cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(bind=self.engine); Base.metadata.create_all(bind=self.engine)
        with self.session_factory() as db:
            db.add(models.AppSettings()); db.add(models.UserProfile(full_name="SOC Analyst", email="soc@example.test", organization="ThreatScope", role="Analyst", avatar_initials="SA")); db.commit(); seed_default_rules(db)

    def create_source(self, source_type="jsonl", name="Test source"):
        response = self.client.post("/api/soc/sources", json={"name": name, "description": "Local test", "source_type": source_type, "parser_type": source_type, "enabled": True})
        self.assertEqual(response.status_code, 200, response.text); return response.json()

    def simulate(self, scenario, count, seed=42, source_id=None, start="2026-01-01T00:00:00Z"):
        body = {"scenario": scenario, "number_of_events": count, "seed": seed, "start_time": start}
        if source_id: body["source_id"] = source_id
        response = self.client.post("/api/soc/simulator/generate", json=body)
        self.assertEqual(response.status_code, 200, response.text); return response.json()

    def test_zero_overview_and_source_crud_validation(self):
        overview = self.client.get("/api/soc/overview")
        self.assertEqual(overview.status_code, 200); self.assertEqual(overview.json()["total_events"], 0); self.assertEqual(overview.json()["recent_alerts"], [])
        source = self.create_source()
        self.assertEqual(len(self.client.get("/api/soc/sources").json()), 1)
        updated = self.client.patch(f"/api/soc/sources/{source['id']}", json={"enabled": False, "name": "Updated source"})
        self.assertEqual(updated.json()["name"], "Updated source"); self.assertFalse(updated.json()["enabled"])
        invalid = self.client.post("/api/soc/sources", json={"name": "Bad source", "source_type": "jsonl", "parser_type": "csv", "enabled": True})
        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(self.client.delete(f"/api/soc/sources/{source['id']}").status_code, 200)

    def test_all_parsers_aliases_timestamp_and_normalization(self):
        self.assertIsNotNone(parse_jsonl(FIXTURES.joinpath("events.jsonl").read_text())[0][0])
        self.assertIsNotNone(parse_csv(FIXTURES.joinpath("events.csv").read_text())[0][0])
        self.assertIsNotNone(parse_access_log(FIXTURES.joinpath("access.log").read_text())[0][0])
        self.assertIsNotNone(parse_auth_log(FIXTURES.joinpath("auth.log").read_text())[0][0])
        self.assertIsNotNone(parse_key_value(FIXTURES.joinpath("events-kv.log").read_text())[0][0])
        event = normalize_event({"time": "2026-01-01T12:30:00+05:30", "client_ip": "192.0.2.1", "account": "demo", "uri": "/api/demo", "http_status": "403"}, "safe")
        self.assertEqual(event["event_time"].isoformat(), "2026-01-01T07:00:00+00:00")
        self.assertEqual(event["event_type"], "api_request"); self.assertEqual(event["outcome"], "denied")
        self.assertEqual(normalize_outcome("invalid"), "failure"); self.assertEqual(normalize_event_type({"message": "login failed"}, "failure"), "authentication")
        self.assertIsNotNone(parse_timestamp("malformed", datetime(2026, 1, 1, tzinfo=timezone.utc)).tzinfo)

    def test_recursive_redaction(self):
        value = {"password": "secret-one", "items": [{"authorization": "Bearer token-two"}, {"nested": {"api_key": "key-three"}}], "message": "cookie=session-four"}
        serialized = json.dumps(redact(value))
        for secret in ("secret-one", "token-two", "key-three", "session-four"): self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized); self.assertNotIn("abc", redact_text("Authorization: Bearer abc"))

    def test_import_formats_hash_counts_duplicates_limits_and_cleanup(self):
        cases = [("jsonl", "events.jsonl"), ("csv", "events.csv"), ("access_log", "access.log"), ("auth_log", "auth.log"), ("key_value", "events-kv.log")]
        for source_type, filename in cases:
            source = self.create_source(source_type, f"{source_type} source")
            content = FIXTURES.joinpath(filename).read_bytes()
            response = self.client.post(f"/api/soc/sources/{source['id']}/imports", files={"file": (filename, content, "text/plain")})
            self.assertEqual(response.status_code, 200, response.text); self.assertEqual(len(response.json()["file_hash"]), 64); self.assertGreater(response.json()["total_lines"], 0)
        duplicate_source = self.create_source("jsonl", "Duplicate source")
        duplicate = self.client.post(f"/api/soc/sources/{duplicate_source['id']}/imports", files={"file": ("duplicates.jsonl", FIXTURES.joinpath("duplicates.jsonl").read_bytes(), "text/plain")})
        self.assertEqual(duplicate.json()["accepted_events"], 1); self.assertEqual(duplicate.json()["rejected_events"], 1)
        bad_ext = self.client.post(f"/api/soc/sources/{duplicate_source['id']}/imports", files={"file": ("events.exe", b"safe", "text/plain")})
        self.assertEqual(bad_ext.status_code, 422)
        too_large = self.client.post(f"/api/soc/sources/{duplicate_source['id']}/imports", files={"file": ("large.jsonl", b"x" * (5 * 1024 * 1024 + 1), "text/plain")})
        self.assertEqual(too_large.status_code, 413)
        lines = b"\n".join(json.dumps({"timestamp": f"2026-01-01T00:00:{i%60:02d}Z", "message": f"event-{i}"}).encode() for i in range(10002))
        capped = self.client.post(f"/api/soc/sources/{duplicate_source['id']}/imports", files={"file": ("cap.jsonl", lines, "text/plain")})
        self.assertLessEqual(capped.json()["accepted_events"], 10000)
        self.assertFalse(any(path.name.startswith("tmp") for path in FIXTURES.iterdir()))

    def test_simulator_determinism_reserved_ranges_and_scenarios(self):
        first = generate("mixed_demo", 30, 7, datetime(2026, 1, 1, tzinfo=timezone.utc)); second = generate("mixed_demo", 30, 7, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(first, second)
        for scenario in ("normal_activity", "single_source_brute_force", "distributed_password_spray", "repeated_401_403", "suspicious_admin_access", "path_probing", "blocked_indicator_activity", "mixed_demo"):
            events = generate(scenario, 12, 3, datetime(2026, 1, 1, tzinfo=timezone.utc)); self.assertEqual(len(events), 12)
            for event in events:
                ip = event.get("source_ip"); self.assertTrue(not ip or ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")))
                self.assertFalse(any(key in event for key in ("password", "token", "authorization", "cookie", "api_key")))
        result = self.simulate("normal_activity", 5); duplicate = self.simulate("normal_activity", 5)
        self.assertEqual(result["events_created"], 5); self.assertEqual(duplicate["events_skipped_as_duplicates"], 5)

    def test_all_default_rules_sliding_window_links_and_deduplication(self):
        starts = ["2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z", "2026-01-01T03:00:00Z", "2026-01-01T04:00:00Z", "2026-01-01T05:00:00Z"]
        for args in (("single_source_brute_force",6), ("distributed_password_spray",4), ("repeated_401_403",21), ("suspicious_admin_access",16), ("path_probing",7)):
            self.simulate(args[0], args[1], start=starts.pop(0))
        self.client.post("/api/soc/blocklist", json={"indicator_type":"ip","indicator_value":"203.0.113.99","reason":"Safe test simulation"})
        self.simulate("blocked_indicator_activity", 1, start="2026-01-01T06:00:00Z")
        source = self.create_source("jsonl", "Authorization source")
        authz = "\n".join(json.dumps({"timestamp": f"2026-01-01T07:00:0{i}Z", "event_type":"authorization", "source_ip":"192.0.2.101", "username":"demo-user", "outcome":"denied"}) for i in range(5))
        authz_import = self.client.post(f"/api/soc/sources/{source['id']}/imports", files={"file": ("authz.jsonl", authz.encode(), "text/plain")})
        self.assertEqual(authz_import.json()["accepted_events"], 5)
        with self.session_factory() as db:
            high_rate = db.query(models.SocDetectionRule).filter(models.SocDetectionRule.rule_code == "SOC-006").one(); high_rate.threshold = 8; db.commit()
            authorization_rule = db.query(models.SocDetectionRule).filter(models.SocDetectionRule.rule_code == "SOC-008").one()
            authorization_events = db.query(models.SocEvent).filter(models.SocEvent.event_type == "authorization").order_by(models.SocEvent.event_time).all()
            self.assertTrue(qualifying_windows(authorization_rule, authorization_events, set()), [(event.outcome, event.username) for event in authorization_events])
        first = self.client.post("/api/soc/detections/run", json={}); self.assertEqual(first.status_code, 200, first.text)
        with self.session_factory() as db:
            codes = {alert.rule.rule_code for alert in db.query(models.SocAlert).all()}
            self.assertEqual(codes, {f"SOC-{i:03d}" for i in range(1,9)})
            self.assertTrue(all(alert.event_links for alert in db.query(models.SocAlert).all()))
            count = db.query(models.SocAlert).count(); fingerprints = [a.fingerprint for a in db.query(models.SocAlert).all()]; self.assertEqual(len(fingerprints), len(set(fingerprints)))
        second = self.client.post("/api/soc/detections/run", json={}).json(); self.assertGreater(second["duplicate_alerts_skipped"], 0)
        with self.session_factory() as db: self.assertEqual(db.query(models.SocAlert).count(), count)

    def test_alert_investigation_enrichment_blocklist_report_integrations(self):
        self.simulate("single_source_brute_force", 6)
        self.client.post("/api/soc/detections/run", json={})
        alert = self.client.get("/api/soc/alerts").json()["items"][0]
        detail = self.client.get(f"/api/soc/alerts/{alert['id']}"); self.assertGreaterEqual(len(detail.json()["events"]), 5)
        self.assertEqual(self.client.patch(f"/api/soc/alerts/{alert['id']}", json={"status":"investigating", "analyst_notes":"Review token=fake-secret"}).status_code, 200)
        known = self.client.post("/api/soc/enrichment", json={"alert_id":alert["id"],"indicator_type":"ip","indicator_value":"192.0.2.66"})
        self.assertEqual(known.json()["source_name"], "local_mock_intelligence"); self.assertEqual(known.json()["reputation"], "malicious")
        unknown = self.client.post("/api/soc/enrichment", json={"indicator_type":"ip","indicator_value":"192.0.2.200"}).json(); self.assertEqual(unknown["reputation"], "unknown")
        entry = self.client.post("/api/soc/blocklist", json={"indicator_type":"ip","indicator_value":"192.0.2.66","reason":"Analyst-only simulation","source_alert_id":alert["id"]})
        self.assertEqual(entry.status_code, 200); self.assertIn("does not modify", entry.json()["disclaimer"])
        self.assertEqual(self.client.patch(f"/api/soc/blocklist/{entry.json()['id']}", json={"status":"expired"}).status_code, 200)
        report = self.client.post("/api/soc/reports", json={"report_type":"soc_summary"})
        self.assertEqual(report.status_code, 200, report.text)
        html = report.json()["html_content"]
        for section in ("Executive Summary","Monitoring Scope","Log Sources","Event Ingestion Summary","Detection Methodology","Alert Summary","Alert Severity Distribution","Alert Timeline","Detailed Alerts","Correlated Evidence","Local Threat-Intelligence Enrichment","Local Blocklist Actions","Investigation Recommendations","Methodology and Limitations","Safe Simulation Disclaimer"): self.assertIn(section, html)
        self.assertNotIn("fake-secret", html); self.assertIn("not live reputation data", html); self.assertIn("does not modify any real firewall", html)
        download = self.client.get(f"/api/soc/reports/{report.json()['id']}/download"); self.assertEqual(download.status_code, 200); self.assertIn("attachment", download.headers["content-disposition"])
        dashboard = self.client.get("/api/dashboard/summary").json(); self.assertGreater(dashboard["soc_total_events"], 0); self.assertGreater(dashboard["soc_open_alerts"], 0)
        search = self.client.get("/api/search/", params={"q":"Repeated"}).json(); self.assertTrue(search["soc_alerts"] or search["soc_rules"])
        notifications = self.client.get("/api/notifications/").json(); self.assertTrue(any(item["entity_type"].startswith("soc_") for item in notifications))
        overview = self.client.get("/api/soc/overview").json(); self.assertTrue(overview["recent_activity"])

    def test_safety_interfaces_are_never_called(self):
        fail = RuntimeError("network or command interface must not be called")
        with patch("socket.create_connection", side_effect=fail), patch("socket.getaddrinfo", side_effect=fail), patch("subprocess.run", side_effect=fail), patch("subprocess.Popen", side_effect=fail), patch("os.system", side_effect=fail), patch("httpx.get", side_effect=fail), patch("httpx.post", side_effect=fail), patch("urllib.request.urlopen", side_effect=fail):
            self.simulate("single_source_brute_force", 6)
            self.assertEqual(self.client.post("/api/soc/detections/run", json={}).status_code, 200)
            alert = self.client.get("/api/soc/alerts").json()["items"][0]
            self.assertEqual(self.client.post("/api/soc/enrichment", json={"alert_id":alert["id"],"indicator_type":"ip","indicator_value":"192.0.2.66"}).status_code, 200)
            self.assertEqual(self.client.post("/api/soc/blocklist", json={"indicator_type":"ip","indicator_value":"192.0.2.66","reason":"Local simulation"}).status_code, 200)
            self.assertEqual(self.client.post("/api/soc/reports", json={"report_type":"soc_summary"}).status_code, 200)


if __name__ == "__main__": unittest.main()
