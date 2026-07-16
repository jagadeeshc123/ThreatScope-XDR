import json
import os
import socket
import subprocess
import tempfile
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.models import UserAccount
from app.modules.access_control.user_service import create_user
from app.modules.threat_intelligence.normalization import IndicatorValidationError, defang, normalize_indicator
from app.modules.threat_intelligence.report_service import SECTIONS
from app.modules.threat_intelligence.service import seed_watchlists
from tests.access_helpers import authenticate_admin


class ThreatIntelligenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cls.factory = sessionmaker(bind=cls.engine)
        def override():
            with cls.factory() as db:
                yield db
        app.dependency_overrides[get_db] = override
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close(); app.dependency_overrides.clear(); cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(self.engine); Base.metadata.create_all(self.engine)
        authenticate_admin(self.client, self.factory)
        with self.factory() as db:
            seed_watchlists(db)
        source = self.client.post("/api/threat-intel/sources", json={"name": "Local Test Intelligence", "source_type": "manual", "reliability": 90, "default_confidence": 70, "default_tlp": "amber"})
        self.assertEqual(source.status_code, 200, source.text)
        self.source_id = source.json()["id"]

    def indicator(self, kind="domain", value="evil.example", **changes):
        payload = {"type": kind, "value": value, "severity": "high", "confidence": 90, "tlp": "amber", "tags": ["test"], "source_id": self.source_id}
        payload.update(changes)
        response = self.client.post("/api/threat-intel/indicators", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def login(self, username, role):
        password = "Valid-Threat-Intel-Password-83!"
        with self.factory() as db:
            if not db.query(UserAccount).filter_by(username_normalized=username).first():
                create_user(db, username=username, display_name=username, password=password, role_keys=[role], must_change_password=False)
        self.client.cookies.clear(); self.client.headers.pop("X-CSRF-Token", None)
        response = self.client.post("/api/auth/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers["X-CSRF-Token"] = self.client.get("/api/auth/csrf").json()["csrf_token"]

    def test_indicator_type_normalization_validation_and_defanging(self):
        valid = {
            "ipv4": ("192.0.2.001", None),
            "ipv6": ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
            "cidr": ("192.0.2.4/24", "192.0.2.0/24"),
            "domain": ("ExAmPle.COM.", "example.com"),
            "hostname": ("Host.Example.COM", "host.example.com"),
            "url": ("HTTPS://Example.COM:443/a#fragment", "https://example.com/a"),
            "email": ("Analyst@Example.COM", "Analyst@example.com"),
            "sha256": ("A" * 64, "a" * 64), "sha1": ("B" * 40, "b" * 40), "md5": ("C" * 32, "c" * 32),
            "file_name": ("Threat.PDF", "threat.pdf"), "user_agent": ("Bad   Bot/1.0", "bad bot/1.0"),
            "vulnerability_id": ("cve-2026-12345", "CVE-2026-12345"), "custom": ("  Local   Marker ", "local marker"),
        }
        for kind, (value, expected) in valid.items():
            with self.subTest(kind=kind):
                if kind == "ipv4":
                    with self.assertRaises(IndicatorValidationError): normalize_indicator(kind, value)
                else:
                    item = normalize_indicator(kind, value); self.assertEqual(item.normalized, expected); self.assertEqual(len(item.value_hash), 64)
        invalid = [("ipv4", "999.1.1.1"), ("ipv6", "not-ip"), ("cidr", "10.0.0.0/99"), ("domain", "bad_domain"), ("url", "javascript:alert(1)"), ("email", "missing-at"), ("sha256", "a" * 63), ("sha1", "g" * 40), ("md5", "0" * 31), ("vulnerability_id", "GHSA-test")]
        for kind, value in invalid:
            with self.subTest(kind=kind): self.assertRaises(IndicatorValidationError, normalize_indicator, kind, value)
        self.assertEqual(defang("https://evil.example/a", "url"), "hxxps://evil[.]example/a")

    def test_manual_creation_duplicate_lifecycle_and_audit(self):
        created = self.indicator(value="EXAMPLE.com", first_seen=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
        duplicate = self.indicator(value="example.com.", confidence=95, tags=["test", "duplicate"])
        self.assertFalse(created["duplicate"]); self.assertTrue(duplicate["duplicate"]); self.assertEqual(created["indicator"]["id"], duplicate["indicator"]["id"])
        with self.factory() as db:
            self.assertEqual(db.query(models.ThreatIndicator).count(), 1)
            self.assertGreater(db.query(models.SecurityAuditEvent).filter_by(action="indicator_created").count(), 0)
        item_id = created["indicator"]["id"]
        self.assertTrue(self.client.post(f"/api/threat-intel/indicators/{item_id}/revoke").json()["revoked"])
        duplicate = self.indicator(value="example.com")
        self.assertTrue(duplicate["indicator"]["revoked"])
        restored = self.client.post(f"/api/threat-intel/indicators/{item_id}/restore").json(); self.assertFalse(restored["revoked"])
        self.assertEqual(self.client.patch(f"/api/threat-intel/indicators/{item_id}", json={"first_seen": "2026-07-20T00:00:00Z", "last_seen": "2026-07-19T00:00:00Z"}).status_code, 422)

    def test_csv_json_stix_and_malformed_imports(self):
        csv_data = b"type,value,severity,confidence,tags\ndomain,one.example,high,80,alpha\ndomain,one.example,high,80,alpha\nipv4,999.1.1.1,high,80,bad\n"
        result = self.client.post("/api/threat-intel/imports", data={"source_id": self.source_id}, files={"file": ("../../unsafe.csv", csv_data, "text/csv")})
        self.assertEqual(result.status_code, 200, result.text); body = result.json(); self.assertEqual((body["accepted_records"], body["duplicate_records"], body["rejected_records"]), (1, 1, 1)); self.assertEqual(body["filename"], "unsafe.csv")
        json_data = json.dumps([{"type": "email", "value": "User@Example.COM"}, {"type": "sha256", "value": "a" * 64}]).encode()
        result = self.client.post("/api/threat-intel/imports", data={"source_id": self.source_id}, files={"file": ("iocs.json", json_data, "application/json")}); self.assertEqual(result.status_code, 200, result.text); self.assertEqual(result.json()["accepted_records"], 2)
        stix = {"type": "bundle", "id": "bundle--test", "objects": [{"type": "indicator", "id": "indicator--one", "pattern": "[domain-name:value = 'stix.example']", "confidence": 88}, {"type": "indicator", "id": "indicator--two", "pattern": "[url:value = 'https://stix.example/path']"}, {"type": "relationship", "source_ref": "indicator--one", "target_ref": "indicator--two", "relationship_type": "related-to"}, {"type": "malware", "id": "malware--context", "name": "Bounded STIX Context", "labels": ["offline"]}, {"type": "identity", "id": "identity--unsupported"}]}
        result = self.client.post("/api/threat-intel/imports", data={"source_id": self.source_id}, files={"file": ("bundle.json", json.dumps(stix).encode(), "application/json")}); self.assertEqual(result.status_code, 200, result.text); self.assertEqual(result.json()["format"], "stix"); self.assertGreaterEqual(result.json()["warning_count"], 1)
        with self.factory() as db:
            self.assertEqual(db.query(models.IndicatorRelationship).count(), 1); self.assertEqual(db.query(models.ThreatCampaign).filter_by(name="Bounded STIX Context").count(), 1)
            self.assertFalse(hasattr(db.query(models.ThreatIntelImport).first(), "file_content"))
        malformed = self.client.post("/api/threat-intel/imports", data={"source_id": self.source_id}, files={"file": ("bad.json", b"{not-json", "application/json")}); self.assertEqual(malformed.status_code, 422)
        oversized = self.client.post("/api/threat-intel/imports", data={"source_id": self.source_id}, files={"file": ("large.txt", b"x" * (2 * 1024 * 1024 + 1), "text/plain")}); self.assertEqual(oversized.status_code, 413)

    def test_watchlists_campaigns_relationships_and_protection(self):
        first = self.indicator()["indicator"]; second = self.indicator("ipv4", "192.0.2.10")["indicator"]
        watchlist = self.client.post("/api/threat-intel/watchlists", json={"name": "Analyst Review", "severity_threshold": "medium"}).json()
        add = self.client.post(f"/api/threat-intel/watchlists/{watchlist['id']}/entries", json={"indicator_id": first["id"]}); self.assertEqual(add.status_code, 200, add.text)
        self.assertEqual(self.client.post(f"/api/threat-intel/watchlists/{watchlist['id']}/entries", json={"indicator_id": first["id"]}).status_code, 409)
        campaign = self.client.post("/api/threat-intel/campaigns", json={"name": "Offline Campaign", "severity": "high", "confidence": 80, "indicator_ids": [first["id"], second["id"]]}).json(); self.assertEqual(len(self.client.get(f"/api/threat-intel/campaigns/{campaign['id']}").json()["indicators"]), 2)
        relationship = self.client.post("/api/threat-intel/relationships", json={"source_indicator_id": first["id"], "target_indicator_id": second["id"], "relationship_type": "resolves_to", "confidence": 75}); self.assertEqual(relationship.status_code, 200, relationship.text)
        self.assertEqual(self.client.post("/api/threat-intel/relationships", json={"source_indicator_id": first["id"], "target_indicator_id": first["id"], "relationship_type": "related_to"}).status_code, 422)
        system = self.client.get("/api/threat-intel/watchlists").json()["items"]
        protected = next(item for item in system if item["system_owned"])
        self.assertEqual(self.client.patch(f"/api/threat-intel/watchlists/{protected['id']}", json={"name": "Changed"}).status_code, 403)

    def test_correlation_idempotency_risk_review_and_escalation(self):
        domain = self.indicator(value="evil.example")["indicator"]
        url = self.indicator("url", "https://evil.example/path")["indicator"]
        cidr = self.indicator("cidr", "192.0.2.0/24")["indicator"]
        with self.factory() as db:
            target = models.Target(name="Stored target", base_url="https://evil.example/path", domain="evil.example", authorization_confirmed=True, environment="test"); db.add(target)
            source = models.SocLogSource(name="Stored logs", source_type="file", parser_type="json", enabled=True); db.add(source); db.flush()
            db.add(models.SocEvent(source_id=source.id, event_time=datetime.now(timezone.utc), event_type="connection", severity="high", source_ip="192.0.2.10", normalized_json="{}", raw_event_hash="c" * 64)); db.commit()
        first = self.client.post("/api/threat-intel/correlation/run", json={"maximum_records": 1000}); self.assertEqual(first.status_code, 200, first.text); self.assertGreaterEqual(first.json()["matches_created"], 3)
        with self.factory() as db:
            before = (db.query(models.IndicatorSighting).count(), db.query(models.IndicatorMatch).count())
            match = db.query(models.IndicatorMatch).filter_by(indicator_id=domain["id"]).first(); self.assertGreaterEqual(match.risk_score, 60); match_id = match.id
            self.assertTrue(db.query(models.IndicatorMatch).filter_by(indicator_id=url["id"]).first())
            self.assertEqual(db.query(models.IndicatorMatch).filter_by(indicator_id=cidr["id"]).first().match_type, "cidr_membership")
        second = self.client.post("/api/threat-intel/correlation/run", json={"maximum_records": 1000}); self.assertEqual(second.status_code, 200)
        with self.factory() as db: self.assertEqual((db.query(models.IndicatorSighting).count(), db.query(models.IndicatorMatch).count()), before)
        reviewed = self.client.post(f"/api/threat-intel/matches/{match_id}/review", json={"status": "reviewing", "analyst_note": "Validated stored observation"}); self.assertEqual(reviewed.status_code, 200, reviewed.text)
        self.assertEqual(self.client.post(f"/api/threat-intel/matches/{match_id}/escalate", json={"confirmed": False}).status_code, 422)
        escalated = self.client.post(f"/api/threat-intel/matches/{match_id}/escalate", json={"confirmed": True, "case_title": "Explicit IOC escalation"}); self.assertEqual(escalated.status_code, 200, escalated.text); self.assertEqual(escalated.json()["match"]["status"], "escalated")

    def test_reports_all_sections_escaping_and_no_active_links(self):
        self.indicator("url", "https://evil.example/path")
        self.indicator("custom", "</li><script>alert(1)</script>")
        result = self.client.post("/api/threat-intel/reports", json={"title": "Offline & Safe", "defanged": True}); self.assertEqual(result.status_code, 200, result.text)
        report = self.client.get(f"/api/threat-intel/reports/{result.json()['id']}").json(); content = report["html_content"]
        for section in SECTIONS: self.assertIn(section, content)
        self.assertIn("hxxps://evil[.]example/path", content); self.assertNotIn("https://evil.example/path", content); self.assertNotIn("<script>alert", content); self.assertNotIn("<a ", content); self.assertNotIn("src=", content); self.assertNotIn("http://", content)

    def test_rbac_csrf_and_offline_contract(self):
        authenticate_admin(self.client, self.factory); self.client.headers.pop("X-CSRF-Token", None)
        self.assertEqual(self.client.post("/api/threat-intel/indicators", json={"type": "domain", "value": "csrf.example"}).status_code, 403)
        self.client.cookies.clear(); self.assertEqual(self.client.get("/api/threat-intel/overview").status_code, 401)
        self.login("registered.ti", "registered_user"); self.assertEqual(self.client.get("/api/threat-intel/overview").status_code, 403)
        self.login("auditor.ti", "auditor"); self.assertEqual(self.client.get("/api/threat-intel/overview").status_code, 200); self.assertEqual(self.client.post("/api/threat-intel/indicators", json={"type": "domain", "value": "denied.example"}).status_code, 403)
        authenticate_admin(self.client, self.factory)
        failure = RuntimeError("external interface forbidden")
        with patch("socket.create_connection", side_effect=failure), patch("socket.getaddrinfo", side_effect=failure), patch("subprocess.run", side_effect=failure), patch("subprocess.Popen", side_effect=failure), patch("os.system", side_effect=failure), patch("urllib.request.urlopen", side_effect=failure):
            item = self.indicator(value="offline.example")["indicator"]
            self.assertEqual(self.client.post("/api/threat-intel/correlation/run", json={"maximum_records": 100}).status_code, 200)
            self.assertEqual(self.client.post("/api/threat-intel/reports", json={"title": "Offline proof", "defanged": True}).status_code, 200)
            self.assertEqual(self.client.get(f"/api/threat-intel/indicators/{item['id']}").status_code, 200)


if __name__ == "__main__":
    unittest.main()
