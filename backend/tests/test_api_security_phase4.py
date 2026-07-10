import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app


FIXTURES = Path(__file__).parent / "fixtures" / "api_security"


class ApiSecurityPhase4Tests(unittest.TestCase):
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
            db.add(models.UserProfile(full_name="Analyst", email="analyst@example.test", organization="ThreatScope", role="Security Analyst", avatar_initials="SA"))
            db.commit()

    def create_imported_assessment(self, name="Phase 4 Fixture"):
        assessment = self.client.post("/api/api-security/assessments", json={"name": name, "source_type": "openapi"}).json()
        with patch("socket.create_connection", side_effect=AssertionError("network access attempted")):
            response = self.client.post(
                f"/api/api-security/assessments/{assessment['id']}/import/openapi",
                files={"file": ("authorization_flow_openapi.json", (FIXTURES / "authorization_flow_openapi.json").read_bytes(), "application/json")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        return assessment, self.client.get(f"/api/api-security/assessments/{assessment['id']}/endpoints").json()

    def add_roles(self, assessment_id):
        roles = []
        for name, level in (("Anonymous", "public"), ("User", "user"), ("Admin", "admin")):
            response = self.client.post(f"/api/api-security/assessments/{assessment_id}/roles", json={"name": name, "privilege_level": level})
            self.assertEqual(response.status_code, 200, response.text)
            roles.append(response.json())
        return roles

    def test_role_identity_matrix_crud_and_ownership(self):
        assessment, endpoints = self.create_imported_assessment()
        roles = self.add_roles(assessment["id"])
        identity = self.client.post(f"/api/api-security/assessments/{assessment['id']}/identities", json={"label": "QA User", "role_id": roles[1]["id"], "identity_type": "user", "notes": "token=FAKE_TOKEN_MUST_NOT_PERSIST"})
        self.assertEqual(identity.status_code, 200, identity.text)
        self.assertNotIn("FAKE_TOKEN_MUST_NOT_PERSIST", json.dumps(identity.json()))
        updated_identity = self.client.patch(f"/api/api-security/identities/{identity.json()['id']}", json={"label": "Authorized QA User"})
        self.assertEqual(updated_identity.json()["label"], "Authorized QA User")

        entry = self.client.post(f"/api/api-security/assessments/{assessment['id']}/authorization-matrix", json={"endpoint_id": endpoints[0]["id"], "role_id": roles[1]["id"], "expected_access": "conditional", "object_scope": "own", "expected_conditions": {"token": "FAKE_MATRIX_TOKEN_MUST_NOT_PERSIST"}})
        self.assertEqual(entry.status_code, 200, entry.text)
        self.assertEqual(entry.json()["expected_conditions"]["token"], "[REDACTED]")
        updated = self.client.patch(f"/api/api-security/authorization-matrix/{entry.json()['id']}", json={"review_status": "reviewed", "analyst_notes": "Owner scope confirmed by API owner"})
        self.assertEqual(updated.json()["review_status"], "reviewed")

        other, _ = self.create_imported_assessment("Other Assessment")
        invalid = self.client.post(f"/api/api-security/assessments/{other['id']}/authorization-matrix", json={"endpoint_id": endpoints[0]["id"], "role_id": roles[0]["id"]})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(self.client.delete(f"/api/api-security/authorization-matrix/{entry.json()['id']}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/api-security/identities/{identity.json()['id']}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/api-security/roles/{roles[2]['id']}").status_code, 200)

    def test_suggestions_generate_conservative_reviews_and_deduplicated_findings(self):
        assessment, endpoints = self.create_imported_assessment()
        self.add_roles(assessment["id"])
        first = self.client.post(f"/api/api-security/assessments/{assessment['id']}/authorization-review/generate")
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["matrix_entries_created"], len(endpoints) * 3)
        self.assertIn("runtime validation was not performed", first.json()["disclaimer"])
        second = self.client.post(f"/api/api-security/assessments/{assessment['id']}/authorization-review/generate")
        self.assertEqual(second.json()["matrix_entries_created"], 0)
        self.assertEqual(second.json()["reviews_created"], 0)

        reviews = self.client.get(f"/api/api-security/assessments/{assessment['id']}/authorization-reviews").json()
        self.assertTrue({"object_level", "function_level", "property_level"}.issubset({item["review_type"] for item in reviews}))
        for review in reviews:
            self.assertIn("potential", review["risk_indicator"].lower())
            self.assertIn("runtime behavior was not tested", review["risk_indicator"].lower())
            self.assertTrue(review["manual_validation_required"])
            self.assertNotIn("confirmed bola", review["risk_indicator"].lower())
            self.assertNotIn("confirmed bfla", review["risk_indicator"].lower())

        target = next(item for item in reviews if item["review_type"] == "object_level")
        accepted = self.client.patch(f"/api/api-security/authorization-reviews/{target['id']}", json={"analyst_decision": "accepted", "notes": "Authorized owner evidence recorded"})
        self.assertEqual(accepted.status_code, 200)
        findings = self.client.get(f"/api/api-security/assessments/{assessment['id']}/findings").json()
        matching = [item for item in findings if item["source"] == "object_level_review" and item["endpoint_id"] == target["endpoint_id"]]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["confidence"], "high")
        self.assertNotEqual(matching[0]["severity"], "critical")

    def test_business_flow_crud_ordering_analysis_status_and_finding_dedup(self):
        assessment, endpoints = self.create_imported_assessment()
        flow_response = self.client.post(f"/api/api-security/assessments/{assessment['id']}/business-flows", json={"name": "Payment approval", "description": "Submit and approve a payment", "business_goal": "Authorized payment", "actor_roles": ["User", "Admin"]})
        self.assertEqual(flow_response.status_code, 200, flow_response.text)
        flow = flow_response.json()
        payment = next(item for item in endpoints if "payments" in item["path"])
        admin_delete = next(item for item in endpoints if item["method"] == "DELETE")
        step1 = self.client.post(f"/api/api-security/business-flows/{flow['id']}/steps", json={"step_order": 1, "endpoint_id": payment["id"], "action_name": "Submit payment from client state", "expected_actor_role": "User", "sensitive_operation": True})
        self.assertEqual(step1.status_code, 200, step1.text)
        step2 = self.client.post(f"/api/api-security/business-flows/{flow['id']}/steps", json={"step_order": 2, "endpoint_id": admin_delete["id"], "action_name": "Delete user", "expected_actor_role": "User", "sensitive_operation": True})
        self.assertEqual(step2.status_code, 200, step2.text)
        duplicate_order = self.client.post(f"/api/api-security/business-flows/{flow['id']}/steps", json={"step_order": 2, "action_name": "Duplicate"})
        self.assertEqual(duplicate_order.status_code, 409)

        with patch("socket.create_connection", side_effect=AssertionError("network access attempted")):
            analyzed = self.client.post(f"/api/api-security/business-flows/{flow['id']}/analyze")
        self.assertEqual(analyzed.status_code, 200, analyzed.text)
        self.assertGreater(analyzed.json()["risks_total"], 3)
        self.assertIn("runtime behavior was not tested", analyzed.json()["disclaimer"])
        repeated = self.client.post(f"/api/api-security/business-flows/{flow['id']}/analyze").json()
        self.assertEqual(repeated["risks_created"], 0)

        risks = self.client.get(f"/api/api-security/business-flows/{flow['id']}/risks").json()
        self.assertIn("missing_prerequisite", {item["risk_type"] for item in risks})
        high = next(item for item in risks if item["severity"] == "high")
        accepted = self.client.patch(f"/api/api-security/business-flow-risks/{high['id']}", json={"status": "accepted"})
        self.assertEqual(accepted.json()["status"], "accepted")
        findings_before = self.client.get(f"/api/api-security/assessments/{assessment['id']}/findings").json()
        self.client.post(f"/api/api-security/business-flows/{flow['id']}/analyze")
        findings_after = self.client.get(f"/api/api-security/assessments/{assessment['id']}/findings").json()
        self.assertEqual(len(findings_before), len(findings_after))
        self.assertEqual(self.client.patch(f"/api/api-security/business-flow-steps/{step1.json()['id']}", json={"expected_state_before": "draft", "expected_state_after": "submitted"}).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/api-security/business-flow-steps/{step2.json()['id']}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/api-security/business-flows/{flow['id']}").status_code, 200)

    def test_report_search_dashboard_and_cascade_integration(self):
        assessment, endpoints = self.create_imported_assessment()
        self.add_roles(assessment["id"])
        self.client.post(f"/api/api-security/assessments/{assessment['id']}/authorization-review/generate")
        flow = self.client.post(f"/api/api-security/assessments/{assessment['id']}/business-flows", json={"name": "Profile export", "description": "Export profile data", "actor_roles": ["User"]}).json()
        self.client.post(f"/api/api-security/business-flows/{flow['id']}/steps", json={"step_order": 1, "endpoint_id": endpoints[0]["id"], "action_name": "Export profile", "sensitive_operation": True})
        self.client.post(f"/api/api-security/business-flows/{flow['id']}/analyze")

        report = self.client.post(f"/api/api-security/assessments/{assessment['id']}/reports")
        self.assertEqual(report.status_code, 200, report.text)
        for section in ("Authorization Model Summary", "Authorization Matrix Coverage", "Object-Level Review Summary", "Function-Level Review Summary", "Property-Level Review Summary", "Business Flow Inventory", "Business Flow Risk Review", "Manual Validation Backlog"):
            self.assertIn(section, report.json()["html_content"])
        search = self.client.get("/api/search/", params={"q": "Profile"}).json()
        self.assertGreaterEqual(len(search["api_business_flows"]) + len(search["api_business_flow_risks"]), 1)
        role_search = self.client.get("/api/search/", params={"q": "Admin"}).json()
        self.assertGreaterEqual(len(role_search["api_roles"]), 1)
        dashboard = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(dashboard["api_business_flow_count"], 1)
        self.assertGreater(dashboard["api_unresolved_authorization_review_count"], 0)
        self.assertIn("api_authorization_matrix_coverage", dashboard)
        self.assertEqual(self.client.delete(f"/api/api-security/assessments/{assessment['id']}").status_code, 200)
        with self.session_factory() as db:
            self.assertEqual(db.query(models.ApiRole).count(), 0)
            self.assertEqual(db.query(models.ApiBusinessFlow).count(), 0)


if __name__ == "__main__":
    unittest.main()
