import json
import os
import shutil
import tempfile
import unittest

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.models import AccessRole, RolePermissionAssignment, UserAccount
from app.modules.access_control.role_service import seed_roles_and_permissions
from app.modules.access_control.user_service import create_user
from app.modules.platform_operations.logging_service import JsonFormatter
from app.modules.platform_operations.models import BackupRecord, ExportPackage
from app.modules.platform_operations.redaction import redact
from tests.access_helpers import TEST_ADMIN_PASSWORD, authenticate_admin


class PlatformOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = tempfile.mkdtemp(prefix="threatscope-v11-")
        os.environ.update({"THREATSCOPE_RUNTIME_DIR": cls.runtime, "THREATSCOPE_BACKUP_DIR": os.path.join(cls.runtime,"backups"), "THREATSCOPE_EXPORT_DIR": os.path.join(cls.runtime,"exports"), "THREATSCOPE_RELEASE_DIR": os.path.join(cls.runtime,"releases"), "THREATSCOPE_SESSION_SECRET": "test-only-session-secret-material-123456", "THREATSCOPE_DEMO_MODE": "true", "THREATSCOPE_BACKUP_ENCRYPTION_KEY": ""})
        cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
        cls.factory=sessionmaker(autocommit=False,autoflush=False,bind=cls.engine)
        def override():
            with cls.factory() as db: yield db
        app.dependency_overrides[get_db]=override;cls.client=TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close();app.dependency_overrides.clear();cls.engine.dispose();shutil.rmtree(cls.runtime,ignore_errors=True)

    def setUp(self):
        Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine);authenticate_admin(self.client,self.factory)

    def login_as(self, username, role):
        password="Valid-Operations-Password-83!"
        with self.factory() as db:
            if not db.query(UserAccount).filter_by(username_normalized=username).first():create_user(db,username=username,display_name=username,password=password,role_keys=[role],must_change_password=False)
        self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None);response=self.client.post("/api/auth/login",json={"username":username,"password":password});self.assertEqual(response.status_code,200,response.text);csrf=self.client.get("/api/auth/csrf").json()["csrf_token"];self.client.headers.update({"X-CSRF-Token":csrf});return response.json()["user"]

    def test_public_health_is_minimal_and_details_are_protected(self):
        self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None)
        live=self.client.get("/api/health/live");self.assertEqual(live.status_code,200);self.assertEqual(set(live.json()),{"status","service","timestamp","version"})
        ready=self.client.get("/api/health/ready");self.assertIn(ready.status_code,(200,503));self.assertEqual(set(ready.json()),{"ready","status","timestamp","failed_check_count"})
        self.assertEqual(self.client.get("/api/operations/health/details").status_code,401)

    def test_role_authorization_and_csrf(self):
        self.login_as("analyst.ops","security_analyst");self.assertEqual(self.client.get("/api/operations/diagnostics").status_code,200);self.assertEqual(self.client.get("/api/operations/exports").status_code,200);self.assertEqual(self.client.get("/api/operations/backups").status_code,403)
        self.login_as("auditor.ops","auditor");self.assertEqual(self.client.get("/api/operations/health/details").status_code,200);self.assertEqual(self.client.post("/api/operations/backups/database",json={}).status_code,403)
        self.login_as("executive.ops","executive_viewer");self.assertEqual(self.client.get("/api/operations").status_code,403)
        authenticate_admin(self.client,self.factory);self.client.headers.pop("X-CSRF-Token",None);self.assertEqual(self.client.post("/api/operations/backups/database",json={}).status_code,403)

    def test_backup_manifest_verify_restore_validation_and_source_preservation(self):
        created=self.client.post("/api/operations/backups/database",json={});self.assertEqual(created.status_code,200,created.text);item=created.json()["backup"]
        self.assertEqual(len(item["sha256"]),64);self.assertEqual(item["verification_status"],"valid")
        self.assertTrue(self.client.post(f"/api/operations/backups/{item['id']}/verify").json()["valid"])
        with self.factory() as db: before=db.query(models.Target).count()
        validated=self.client.post("/api/operations/restores/validate",json={"backup_id":item["id"]});self.assertEqual(validated.status_code,200,validated.text);self.assertEqual(validated.json()["status"],"validated")
        with self.factory() as db:self.assertEqual(db.query(models.Target).count(),before)
        denied=self.client.post(f"/api/operations/restores/{validated.json()['id']}/execute",json={"confirmation_phrase":"wrong","current_password":TEST_ADMIN_PASSWORD});self.assertEqual(denied.status_code,422)

    def test_encrypted_backup(self):
        os.environ["THREATSCOPE_BACKUP_ENCRYPTION_KEY"]=Fernet.generate_key().decode()
        try:
            result=self.client.post("/api/operations/backups/database",json={});self.assertEqual(result.status_code,200,result.text);self.assertTrue(result.json()["backup"]["encrypted"]);self.assertTrue(result.json()["backup"]["filename"].endswith(".fernet"))
        finally:os.environ["THREATSCOPE_BACKUP_ENCRYPTION_KEY"]=""

    def test_export_and_non_mutating_import_validation(self):
        result=self.client.post("/api/operations/exports",json={"modules":["web_exposure","api_security"]});self.assertEqual(result.status_code,200,result.text);item=result.json();self.assertEqual(len(item["sha256"]),64)
        self.assertTrue(self.client.post(f"/api/operations/exports/{item['id']}/verify").json()["valid"])
        validated=self.client.post("/api/operations/imports/validate",json={"export_id":item["id"]});self.assertEqual(validated.status_code,200,validated.text);self.assertEqual(validated.json()["source_mutation_count"],0)
        self.assertNotIn("password",json.dumps(validated.json()).lower())

    def test_retention_requires_preview_and_preserves_audit(self):
        policies=self.client.get("/api/operations/retention/policies").json();policy=next(x for x in policies if x["entity_type"]=="operational_jobs")
        self.assertEqual(self.client.post("/api/operations/retention/apply",json={"run_id":999,"confirmation_phrase":"APPLY RETENTION PREVIEW"}).status_code,404)
        preview=self.client.post("/api/operations/retention/preview",json={"policy_id":policy["id"]});self.assertEqual(preview.status_code,200,preview.text)
        applied=self.client.post("/api/operations/retention/apply",json={"run_id":preview.json()["id"],"confirmation_phrase":"APPLY RETENTION PREVIEW"});self.assertEqual(applied.status_code,200,applied.text)

    def test_demo_seed_idempotent_and_reset_preserves_analyst_record(self):
        with self.factory() as db:db.add(models.Target(name="Analyst target",base_url="http://example.test",domain="example.test",authorization_confirmed=True,environment="test"));db.commit()
        first=self.client.post("/api/operations/demo/seed");second=self.client.post("/api/operations/demo/seed");self.assertTrue(first.json()["created"]);self.assertFalse(second.json()["created"])
        reset=self.client.post("/api/operations/demo/reset",json={"confirmation_phrase":"RESET DEMO DATA"});self.assertTrue(reset.json()["non_demo_records_preserved"])
        with self.factory() as db:self.assertIsNotNone(db.query(models.Target).filter_by(name="Analyst target").first())

    def test_configuration_diagnostics_inventory_and_release(self):
        config=self.client.get("/api/operations/configuration/status");self.assertEqual(config.status_code,200);body=json.dumps(config.json());self.assertNotIn(os.environ["THREATSCOPE_SESSION_SECRET"],body)
        diagnostic=json.dumps(self.client.get("/api/operations/diagnostics").json());self.assertNotIn(self.runtime,diagnostic)
        inventory=self.client.post("/api/operations/inventory/generate");self.assertEqual(inventory.status_code,200);self.assertEqual(inventory.json()["components"],sorted(inventory.json()["components"],key=lambda x:(x["ecosystem"].lower(),x["name"].lower(),x["version"])))
        release=self.client.post("/api/operations/releases/build",json={"allow_dirty":True});self.assertEqual(release.status_code,200,release.text);self.assertTrue(release.json()["dirty_working_tree"])

    def test_recursive_redaction(self):
        value=redact({"password":"open-sesame","nested":{"csrf_token":"abcd","safe":"ok"},"path":"C:\\Users\\person\\secret.txt"})
        self.assertEqual(value["password"],"[REDACTED]");self.assertEqual(value["nested"]["csrf_token"],"[REDACTED]");self.assertEqual(value["nested"]["safe"],"ok");self.assertNotIn("Users",value["path"])


if __name__=="__main__":unittest.main()
