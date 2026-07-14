import base64
import json
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from tests.access_helpers import authenticate_admin


FIXTURES = Path(__file__).parent / "fixtures" / "api_security"


def jwt_segment(value):
    encoded = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
    return encoded


def fake_jwt(header, payload):
    return f"{jwt_segment(header)}.{jwt_segment(payload)}.fake-signature"


class ApiSecurityPhase3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
        authenticate_admin(self.client, self.session_factory)

    def create_assessment(self):
        response = self.client.post("/api/api-security/assessments", json={
            "name": "Risk Intelligence Fixture",
            "description": "Safe static metadata",
            "source_type": "openapi",
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def import_risk_fixture(self, assessment_id):
        response = self.client.post(
            f"/api/api-security/assessments/{assessment_id}/import/openapi",
            files={"file": ("risk_openapi.json", (FIXTURES / "risk_openapi.json").read_bytes(), "application/json")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_jwt_analyzer_risks_and_raw_token_not_persisted(self):
        assessment = self.create_assessment()
        now = int(time.time())
        token = fake_jwt(
            {"alg": "none", "typ": "JWT"},
            {
                "iss": "https://issuer.example",
                "aud": "api://wrong",
                "iat": now + 900,
                "exp": now + 172800,
                "password": "FAKE_PASSWORD_DO_NOT_USE",
                "roles": ["admin", "owner", "*"],
            },
        )
        response = self.client.post("/api/api-security/jwt/analyze", json={
            "token": token,
            "assessment_id": assessment["id"],
            "expected_issuer": "https://expected.example",
            "expected_audience": "api://expected",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["algorithm"], "none")
        self.assertGreaterEqual(body["risk_score"], 8)
        self.assertIn("Decoded structure only", body["disclaimer"])
        self.assertEqual(body["payload"]["password"], "[REDACTED]")
        self.assertNotIn(token, json.dumps(body))
        with self.session_factory() as db:
            stored = db.query(models.JwtAnalysis).first()
            self.assertIsNotNone(stored)
            serialized = json.dumps({
                "header": stored.header_json_redacted,
                "payload": stored.payload_json_redacted,
                "fingerprint": stored.token_fingerprint,
            })
            self.assertNotIn(token, serialized)
            self.assertNotIn("FAKE_PASSWORD_DO_NOT_USE", serialized)

    def test_jwt_expired_and_missing_exp_checks(self):
        expired = fake_jwt({"alg": "RS256"}, {"iss": "issuer", "aud": "aud", "exp": int(time.time()) - 60})
        missing = fake_jwt({"alg": "RS256"}, {"iss": "issuer", "aud": "aud"})
        expired_response = self.client.post("/api/api-security/jwt/analyze", json={"token": expired})
        missing_response = self.client.post("/api/api-security/jwt/analyze", json={"token": missing})
        self.assertEqual(expired_response.json()["expiration_status"], "expired")
        self.assertEqual(missing_response.json()["expiration_status"], "missing")

    def test_findings_owasp_response_exposure_report_and_search(self):
        assessment = self.create_assessment()
        self.import_risk_fixture(assessment["id"])
        token = fake_jwt({"alg": "HS256"}, {"iss": "issuer", "aud": "aud", "exp": int(time.time()) + 600})
        self.assertEqual(self.client.post("/api/api-security/jwt/analyze", json={"token": token, "assessment_id": assessment["id"]}).status_code, 200)

        analyzed = self.client.post(f"/api/api-security/assessments/{assessment['id']}/analyze")
        self.assertEqual(analyzed.status_code, 200, analyzed.text)
        self.assertGreaterEqual(analyzed.json()["findings_created"], 6)

        findings = self.client.get(f"/api/api-security/assessments/{assessment['id']}/findings")
        self.assertEqual(findings.status_code, 200)
        titles = [item["title"] for item in findings.json()]
        self.assertIn("Unauthenticated State-Changing API Endpoint", titles)
        self.assertIn("Sensitive Endpoint Without Documented Authentication", titles)
        self.assertIn("Deprecated API Endpoint Still Present", titles)
        self.assertIn("Insecure HTTP Server URL Documented", titles)
        self.assertIn("Sensitive Response Field Documented", titles)

        analyzed_again = self.client.post(f"/api/api-security/assessments/{assessment['id']}/analyze")
        self.assertEqual(analyzed_again.json()["findings_created"], 0)

        coverage = self.client.get(f"/api/api-security/assessments/{assessment['id']}/owasp-coverage")
        self.assertEqual(coverage.status_code, 200)
        self.assertEqual(len(coverage.json()), 10)
        api1 = next(item for item in coverage.json() if item["category_id"] == "API1:2023")
        self.assertIn("Manual validation", api1["evidence_summary"])
        api6 = next(item for item in coverage.json() if item["category_id"] == "API6:2023")
        self.assertIn(api6["status"], ["not_applicable", "not_observed"])

        exposure = self.client.get(f"/api/api-security/assessments/{assessment['id']}/response-exposure")
        self.assertEqual(exposure.status_code, 200)
        fields = [item["field_path"] for item in exposure.json()]
        self.assertIn("access_token", fields)
        self.assertIn("profile.ssn", fields)
        self.assertNotIn("FAKE", json.dumps(exposure.json()))

        report = self.client.post(f"/api/api-security/assessments/{assessment['id']}/reports")
        self.assertEqual(report.status_code, 200, report.text)
        html = report.json()["html_content"]
        for section in [
            "Executive Summary",
            "Assessment Scope",
            "Imported Definition Summary",
            "Endpoint Inventory",
            "Authentication Posture",
            "OWASP API Security Top 10 Coverage",
            "Response Exposure Review",
            "JWT Analysis Summary",
            "Detailed Findings",
            "Risk Distribution",
            "Remediation Roadmap",
            "Methodology and Limitations",
            "Authorized Testing Disclaimer",
        ]:
            self.assertIn(section, html)
        download = self.client.get(f"/api/api-security/reports/{report.json()['id']}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["content-disposition"])

        search = self.client.get("/api/search/", params={"q": "JWT"})
        self.assertEqual(search.status_code, 200)
        self.assertGreaterEqual(len(search.json()["api_findings"]) + len(search.json()["api_reports"]), 1)
        dashboard = self.client.get("/api/dashboard/summary")
        self.assertEqual(dashboard.status_code, 200)
        self.assertGreaterEqual(dashboard.json()["api_finding_count"], 1)
        self.assertGreaterEqual(dashboard.json()["api_owasp_observed_category_count"], 1)


if __name__ == "__main__":
    unittest.main()
