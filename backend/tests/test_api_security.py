import json
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


class ApiSecurityTests(unittest.TestCase):
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
        authenticate_admin(self.client, self.session_factory)

    def create_assessment(self, source_type="openapi"):
        response = self.client.post("/api/api-security/assessments", json={
            "name": "Partner API",
            "description": "Safe fixture import",
            "source_type": source_type,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def import_file(self, assessment_id, route, fixture_name, content_type="application/json"):
        content = (FIXTURES / fixture_name).read_bytes()
        response = self.client.post(
            f"/api/api-security/assessments/{assessment_id}/import/{route}",
            files={"file": (fixture_name, content, content_type)},
        )
        return response

    def test_assessment_create_retrieve_and_delete(self):
        assessment = self.create_assessment("manual")
        self.assertEqual(assessment["status"], "draft")
        detail = self.client.get(f"/api/api-security/assessments/{assessment['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["name"], "Partner API")
        deleted = self.client.delete(f"/api/api-security/assessments/{assessment['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["ok"])
        self.assertEqual(self.client.get(f"/api/api-security/assessments/{assessment['id']}").status_code, 404)

    def test_valid_openapi_json_import_inventory_auth_and_risk(self):
        assessment = self.create_assessment()
        imported = self.import_file(assessment["id"], "openapi", "minimal_openapi.json")
        self.assertEqual(imported.status_code, 200, imported.text)
        body = imported.json()
        self.assertEqual(body["endpoints_discovered"], 3)
        self.assertEqual(body["unauthenticated_endpoints"], 2)
        self.assertEqual(body["high_risk_endpoints"], 1)
        endpoints = self.client.get(f"/api/api-security/assessments/{assessment['id']}/endpoints").json()
        self.assertEqual(len(endpoints), 3)
        delete_user = next(item for item in endpoints if item["method"] == "DELETE")
        self.assertFalse(delete_user["auth_required"])
        self.assertEqual(delete_user["preliminary_risk_level"], "high")
        self.assertEqual(delete_user["parameters"][0]["name"], "userId")

    def test_valid_openapi_yaml_import(self):
        assessment = self.create_assessment()
        imported = self.import_file(assessment["id"], "openapi", "minimal_openapi.yaml", "application/yaml")
        self.assertEqual(imported.status_code, 200, imported.text)
        self.assertEqual(imported.json()["endpoints_discovered"], 2)
        detail = self.client.get(f"/api/api-security/assessments/{assessment['id']}").json()
        self.assertEqual(detail["base_url"], "https://yaml.example.test/api")
        self.assertEqual(detail["api_version"], "2.0")

    def test_invalid_openapi_rejected_and_notified(self):
        assessment = self.create_assessment()
        imported = self.import_file(assessment["id"], "openapi", "invalid_openapi.json")
        self.assertEqual(imported.status_code, 400)
        detail = self.client.get(f"/api/api-security/assessments/{assessment['id']}").json()
        self.assertEqual(detail["status"], "failed")
        notifications = self.client.get("/api/notifications/").json()
        self.assertTrue(any(item["type"] == "danger" and item["entity_id"] == assessment["id"] for item in notifications))

    def test_postman_import_recursive_folders_and_redaction(self):
        assessment = self.create_assessment("postman")
        imported = self.import_file(assessment["id"], "postman", "postman_collection.json")
        self.assertEqual(imported.status_code, 200, imported.text)
        self.assertEqual(imported.json()["endpoints_discovered"], 2)
        endpoints = self.client.get(f"/api/api-security/assessments/{assessment['id']}/endpoints").json()
        payment = next(item for item in endpoints if item["path"] == "/payment")
        self.assertEqual(payment["preliminary_risk_level"], "high")
        self.assertIn("password", [item["name"] for item in payment["parameters"]])
        with self.session_factory() as db:
            artifact = db.query(models.ApiImportArtifact).first()
            self.assertIsNotNone(artifact)
            self.assertNotIn("FAKE_HEADER_TOKEN_DO_NOT_USE", artifact.redacted_content)
            self.assertNotIn("FAKE_PASSWORD_DO_NOT_USE", artifact.redacted_content)
            self.assertIn("[REDACTED]", artifact.redacted_content)

        nested = self.create_assessment("postman")
        nested_import = self.import_file(nested["id"], "postman", "nested_postman_collection.json")
        self.assertEqual(nested_import.status_code, 200, nested_import.text)
        nested_endpoints = self.client.get(f"/api/api-security/assessments/{nested['id']}/endpoints").json()
        self.assertEqual(nested_endpoints[0]["folder_path"], "Admin / Reports")

    def test_endpoint_inventory_filters_sorting_search_and_metrics(self):
        assessment = self.create_assessment()
        self.assertEqual(self.import_file(assessment["id"], "openapi", "minimal_openapi.json").status_code, 200)
        high = self.client.get(
            f"/api/api-security/assessments/{assessment['id']}/endpoints",
            params={"risk": "high", "auth": "unauthenticated", "sort": "method"},
        )
        self.assertEqual(high.status_code, 200)
        self.assertEqual(len(high.json()), 1)
        deprecated = self.client.get(
            f"/api/api-security/assessments/{assessment['id']}/endpoints",
            params={"deprecated": "true", "tag": "reports", "q": "export"},
        )
        self.assertEqual(len(deprecated.json()), 1)
        summary = self.client.get(f"/api/api-security/assessments/{assessment['id']}/summary")
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json()["risk_distribution"]["high"], 1)
        search = self.client.get("/api/search/", params={"q": "admin"})
        self.assertEqual(search.status_code, 200)
        self.assertEqual(len(search.json()["api_endpoints"]), 1)
        dashboard = self.client.get("/api/dashboard/summary")
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.json()["api_assessment_count"], 1)
        self.assertEqual(dashboard.json()["api_endpoint_count"], 3)
        self.assertEqual(dashboard.json()["api_high_risk_endpoint_count"], 1)

    def test_file_extension_validation(self):
        assessment = self.create_assessment()
        response = self.client.post(
            f"/api/api-security/assessments/{assessment['id']}/import/postman",
            files={"file": ("collection.yaml", b"{}", "application/yaml")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(".json", response.json()["detail"])

    def test_fake_redaction_fixture_contains_no_persisted_secret_values(self):
        assessment = self.create_assessment("postman")
        fake_values = json.loads((FIXTURES / "fake_authorization_tokens.json").read_text())
        collection = {
            "info": {
                "name": "Redaction Fixture",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [{
                "name": "Secret sample",
                "request": {
                    "method": "POST",
                    "url": "{{baseUrl}}/account/token",
                    "header": [{"key": key, "value": value} for key, value in fake_values.items()],
                    "body": {"mode": "raw", "raw": json.dumps(fake_values), "options": {"raw": {"language": "json"}}},
                },
            }],
        }
        response = self.client.post(
            f"/api/api-security/assessments/{assessment['id']}/import/postman",
            files={"file": ("redaction.json", json.dumps(collection).encode("utf-8"), "application/json")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        with self.session_factory() as db:
            artifact = db.query(models.ApiImportArtifact).first()
            for value in fake_values.values():
                self.assertNotIn(value, artifact.redacted_content)
            self.assertIn("[REDACTED]", artifact.redacted_content)


if __name__ == "__main__":
    unittest.main()
