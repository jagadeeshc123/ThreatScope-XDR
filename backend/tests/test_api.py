import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app


class VulnScopeApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.session_factory = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

        def override_get_db():
            db = cls.session_factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        app.dependency_overrides.clear()
        cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        with self.session_factory() as db:
            db.add(models.AppSettings())
            db.add(models.UserProfile(
                full_name="Security Analyst",
                email="analyst@vulnscope.local",
                organization="ThreatScope XDR",
                role="Security Analyst",
                avatar_initials="SA",
            ))
            db.commit()

    def create_target(self, name="Test Target"):
        response = self.client.post("/api/targets/", json={
            "name": name,
            "base_url": "http://example.test",
            "environment": "test",
            "authorization_confirmed": True,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def seed_completed_scan(self):
        with self.session_factory() as db:
            target = models.Target(
                name="Seed Target",
                base_url="https://seed.example",
                domain="seed.example",
                environment="test",
                authorization_confirmed=True,
            )
            db.add(target)
            db.flush()
            scan = models.Scan(
                target_id=target.id,
                profile="Full Safe Scan",
                status="completed",
                total_findings=1,
                risk_score=7.5,
                overall_posture_score=62,
                posture_transport_security=75,
                posture_browser_defense=55,
                posture_session_safety=70,
                posture_exposure_hygiene=45,
                posture_authentication_surface=65,
            )
            db.add(scan)
            db.flush()
            db.add(models.Finding(
                scan_id=scan.id,
                target_id=target.id,
                title="Missing Content-Security-Policy",
                severity="high",
                category="Security Headers",
                affected_url=target.base_url,
                description="CSP is missing.",
                evidence="No CSP response header.",
                impact="Browser defenses are reduced.",
                remediation="Add a restrictive CSP.",
                confidence="high",
                risk_score=7.5,
            ))
            db.add(models.CrawlNode(
                scan_id=scan.id,
                target_id=target.id,
                url=target.base_url,
                path="/",
                status_code=200,
                content_type="text/html",
                page_title="Seed",
                depth=0,
                has_forms=False,
                has_password_field=False,
                finding_count=1,
            ))
            db.add(models.EvidenceArtifact(
                scan_id=scan.id,
                target_id=target.id,
                artifact_type="header_snapshot",
                title="Response Headers",
                redacted_text="{'server': 'test'}",
                related_url=target.base_url,
            ))
            db.commit()
            return target.id, scan.id

    def test_target_create_and_delete(self):
        target = self.create_target()
        self.assertEqual(self.client.get(f"/api/targets/{target['id']}").status_code, 200)
        updated = self.client.patch(f"/api/targets/{target['id']}", json={
            "name": "Updated Target",
            "base_url": "https://updated.example",
            "environment": "staging",
        })
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "Updated Target")
        self.assertEqual(updated.json()["domain"], "updated.example")
        deleted = self.client.delete(f"/api/targets/{target['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["ok"])
        self.assertEqual(self.client.get(f"/api/targets/{target['id']}").status_code, 404)

    def test_scan_start_and_result_endpoints(self):
        target = self.create_target()
        with patch("app.routers.scans.run_scan") as run_scan:
            started = self.client.post("/api/scans/start", json={
                "target_id": target["id"],
                "profile": "Standard Safe Scan",
            })
        self.assertEqual(started.status_code, 200, started.text)
        self.assertEqual(started.json()["status"], "queued")
        run_scan.assert_called_once_with(started.json()["id"])

        _, scan_id = self.seed_completed_scan()
        findings = self.client.get(f"/api/scans/{scan_id}/findings")
        crawl_map = self.client.get(f"/api/scans/{scan_id}/crawl-map")
        evidence = self.client.get(f"/api/scans/{scan_id}/evidence")
        policies = self.client.get(f"/api/scans/{scan_id}/policy-results")
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(len(findings.json()), 1)
        self.assertEqual(crawl_map.status_code, 200)
        self.assertEqual(crawl_map.json()[0]["path"], "/")
        self.assertEqual(evidence.status_code, 200)
        self.assertEqual(evidence.json()[0]["artifact_type"], "header_snapshot")
        self.assertEqual(policies.status_code, 200)
        self.assertGreaterEqual(len(policies.json()), 1)
        deleted = self.client.delete(f"/api/scans/{scan_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get(f"/api/scans/{scan_id}").status_code, 404)

    def test_report_generation_view_download_and_notification(self):
        _, scan_id = self.seed_completed_scan()
        settings = self.client.patch("/api/settings/", json={
            "report_company_name": "ThreatScope Test Lab",
            "report_footer_text": "Authorized Test Footer",
        })
        self.assertEqual(settings.status_code, 200)
        generated = self.client.post(f"/api/reports/generate/{scan_id}")
        self.assertEqual(generated.status_code, 200, generated.text)
        report = generated.json()
        self.assertIn("ThreatScope Test Lab", report["html_content"])
        self.assertIn("Authorized Test Footer", report["html_content"])
        self.assertEqual(self.client.get(f"/api/reports/{report['id']}").status_code, 200)
        download = self.client.get(f"/api/reports/{report['id']}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["content-disposition"])
        notifications = self.client.get("/api/notifications/").json()
        self.assertTrue(any(item["entity_type"] == "report" and item["entity_id"] == report["id"] for item in notifications))
        deleted = self.client.delete(f"/api/reports/{report['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get(f"/api/reports/{report['id']}").status_code, 404)

    def test_dashboard_summary_and_search(self):
        target_id, scan_id = self.seed_completed_scan()
        self.client.post(f"/api/reports/generate/{scan_id}")
        summary = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary.status_code, 200)
        body = summary.json()
        self.assertEqual(body["total_targets"], 1)
        self.assertEqual(body["total_scans"], 1)
        self.assertEqual(body["high_findings"], 1)
        self.assertEqual(body["highest_risk_targets"][0]["id"], target_id)
        results = self.client.get("/api/search/", params={"q": "Seed"})
        self.assertEqual(results.status_code, 200)
        self.assertEqual(len(results.json()["targets"]), 1)
        self.assertEqual(len(results.json()["scans"]), 1)
        self.assertEqual(len(results.json()["findings"]), 1)
        self.assertEqual(len(results.json()["reports"]), 1)
        short_query = self.client.get("/api/search/", params={"q": "S"})
        self.assertEqual(short_query.status_code, 200)
        self.assertEqual(short_query.json()["targets"], [])

    def test_settings_get_patch_and_reset(self):
        current = self.client.get("/api/settings/")
        self.assertEqual(current.status_code, 200)
        updated = self.client.patch("/api/settings/", json={
            "default_scan_profile": "Full Safe Scan",
            "request_timeout_seconds": 22,
            "max_pages_standard": 12,
            "max_depth_full": 4,
            "rate_limit_delay_ms": 750,
            "report_company_name": "ThreatScope XDR",
            "report_footer_text": "Internal use only",
            "auto_generate_report": True,
        })
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["request_timeout_seconds"], 22)
        self.assertEqual(updated.json()["report_company_name"], "ThreatScope XDR")
        persisted = self.client.get("/api/settings/").json()
        self.assertEqual(persisted["max_depth_full"], 4)
        self.assertTrue(persisted["auto_generate_report"])
        reset = self.client.post("/api/settings/reset")
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(reset.json()["default_scan_profile"], "Standard Safe Scan")

    def test_profile_get_and_patch(self):
        self.assertEqual(self.client.get("/api/profile/").status_code, 200)
        updated = self.client.patch("/api/profile/", json={
            "full_name": "Web Exposure Lead",
            "avatar_initials": "WL",
        })
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["avatar_initials"], "WL")
        self.assertEqual(self.client.get("/api/profile/").json()["full_name"], "Web Exposure Lead")

    def test_notifications_read_mark_all_and_delete(self):
        with self.session_factory() as db:
            first = models.Notification(title="One", message="First", type="info", entity_type="system")
            second = models.Notification(title="Two", message="Second", type="warning", entity_type="scan", entity_id=1)
            db.add_all([first, second])
            db.commit()
            first_id, second_id = first.id, second.id

        unread = self.client.get("/api/notifications/unread-count")
        self.assertEqual(unread.json()["unread_count"], 2)
        marked = self.client.patch(f"/api/notifications/{first_id}/read")
        self.assertTrue(marked.json()["is_read"])
        self.assertEqual(self.client.patch("/api/notifications/mark-all-read").status_code, 200)
        self.assertEqual(self.client.get("/api/notifications/unread-count").json()["unread_count"], 0)
        self.assertEqual(self.client.delete(f"/api/notifications/{second_id}").status_code, 200)
        ids = [item["id"] for item in self.client.get("/api/notifications/").json()]
        self.assertNotIn(second_id, ids)


if __name__ == "__main__":
    unittest.main()
