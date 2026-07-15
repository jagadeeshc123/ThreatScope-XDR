import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.models import AccessRole, AuthSession, SecurityAuditEvent, UserAccount
from app.modules.access_control.password_service import verify_password
from app.modules.access_control.role_service import effective_permissions, role_keys, seed_roles_and_permissions
from app.modules.access_control.session_service import hash_value
from app.modules.access_control.user_service import create_user
from scripts import manage_accounts
from tests.access_helpers import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, authenticate_admin


class LocalRegistrationAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cls.factory = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)
        def override():
            with cls.factory() as db: yield db
        app.dependency_overrides[get_db] = override
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close(); app.dependency_overrides.clear(); cls.engine.dispose()

    def setUp(self):
        os.environ.update({
            "THREATSCOPE_SESSION_SECRET": "phase-12-test-session-secret-material-123456",
            "THREATSCOPE_LOCAL_LOGIN_ENABLED": "true",
            "THREATSCOPE_SELF_REGISTRATION_ENABLED": "true",
            "THREATSCOPE_REGISTRATION_MODE": "auto_activate_limited",
            "THREATSCOPE_PRIVACY_NOTICE_VERSION": "test-v1",
        })
        Base.metadata.drop_all(self.engine); Base.metadata.create_all(self.engine)
        with self.factory() as db: seed_roles_and_permissions(db)
        self.client.cookies.clear(); self.client.headers.pop("X-CSRF-Token", None)

    def payload(self, *, email="gmail.user@gmail.com", username="local.user", password="Separate-ThreatScope-91!", **updates):
        data={"email":email,"username":username,"display_name":"Local User","password":password,"password_confirmation":password,"terms_accepted":True,"privacy_notice_version":"test-v1"};data.update(updates);return data

    def register(self, **kwargs): return self.client.post("/api/auth/register", json=self.payload(**kwargs))

    def login(self, identifier, password="Separate-ThreatScope-91!"):
        self.client.cookies.clear(); self.client.headers.pop("X-CSRF-Token", None)
        return self.client.post("/api/auth/login", json={"identifier":identifier,"password":password})

    def test_providers_and_registration_disabled(self):
        providers=self.client.get("/api/auth/providers");self.assertEqual(providers.status_code,200);self.assertNotIn("secret",providers.text.lower())
        os.environ["THREATSCOPE_SELF_REGISTRATION_ENABLED"]="false"
        self.assertEqual(self.register().status_code,403)

    def test_gmail_and_non_gmail_registration_and_limited_role(self):
        gmail=self.register();self.assertEqual(gmail.status_code,201,gmail.text);self.assertFalse(gmail.json()["email_verified"])
        other=self.register(email="person@example.org",username="other.user",password="Another-Local-Password-82!");self.assertEqual(other.status_code,201,other.text)
        with self.factory() as db:
            user=db.query(UserAccount).filter_by(username_normalized="local.user").one();self.assertEqual(role_keys(db,user.id),["registered_user"])
            self.assertEqual(effective_permissions(db,user),{"dashboard:view","profile:manage","notifications:read"});self.assertNotIn("Separate-ThreatScope",user.password_hash);self.assertTrue(verify_password(user.password_hash,"Separate-ThreatScope-91!"))

    def test_generated_username_and_normalized_uniqueness(self):
        first=self.register(username=None);self.assertEqual(first.status_code,201);self.assertRegex(first.json()["username"],r"^[a-z0-9][a-z0-9._-]{2,63}$")
        duplicate=self.register(email="GMAIL.USER@GMAIL.COM",username="another.user");self.assertEqual(duplicate.status_code,422);self.assertEqual(duplicate.json()["detail"],"Account registration could not be completed")
        duplicate_username=self.register(email="unique@example.org",username=first.json()["username"],password="Unique-Local-Password-73!");self.assertEqual(duplicate_username.status_code,422)

    def test_registration_validation_and_privilege_injection(self):
        cases=[
            self.payload(email="bad",username="bad.user"),
            self.payload(display_name="   "),
            self.payload(password="short",password_confirmation="short"),
            self.payload(password="password1234",password_confirmation="password1234"),
            self.payload(password_confirmation="Different-Local-Password-22!"),
            self.payload(terms_accepted=False),
        ]
        for case in cases:self.assertEqual(self.client.post("/api/auth/register",json=case).status_code,422)
        for field,value in [("role_keys",["administrator"]),("status","active"),("is_system_admin",True),("mfa_enabled",True)]:
            body=self.payload(email=f"{field}@example.org",username=f"u.{field[:12]}",password="Injection-Safe-Password-66!");body[field]=value;self.assertEqual(self.client.post("/api/auth/register",json=body).status_code,422)

    def test_username_email_case_normalized_login_cookie_and_csrf(self):
        self.assertEqual(self.register().status_code,201)
        for identifier in ("local.user","gmail.user@gmail.com","GMAIL.USER@GMAIL.COM"):
            response=self.login(identifier);self.assertEqual(response.status_code,200,response.text);self.assertNotIn("token",response.text.lower());self.assertIn("HttpOnly",response.headers.get("set-cookie",""))
        csrf=self.client.get("/api/auth/csrf");self.assertEqual(csrf.status_code,200);self.assertEqual(self.client.post("/api/auth/logout").status_code,403);self.client.headers["X-CSRF-Token"]=csrf.json()["csrf_token"];self.assertEqual(self.client.post("/api/auth/logout").status_code,200)

    def test_non_gmail_email_login_and_registration_rate_limit(self):
        registered=self.register(email="person@example.org",username="other.user",password="Another-Local-Password-82!");self.assertEqual(registered.status_code,201)
        self.assertEqual(self.login("PERSON@EXAMPLE.ORG","Another-Local-Password-82!").status_code,200)
        for attempt in range(6):
            response=self.register(email="person@example.org",username=f"duplicate.{attempt}",password="Duplicate-Local-Password-86!")
        self.assertEqual(response.status_code,429)

    def test_generic_invalid_identifier_failures_and_lockout(self):
        self.register()
        email=self.login("gmail.user@gmail.com","Wrong-Local-Password-91!");username=self.login("local.user","Wrong-Local-Password-91!");unknown=self.login("absent@example.org","Wrong-Local-Password-91!")
        self.assertEqual(email.json()["detail"],username.json()["detail"]);self.assertEqual(username.json()["detail"],unknown.json()["detail"])
        for _ in range(5):self.login("local.user","Wrong-Local-Password-91!")
        with self.factory() as db:self.assertEqual(db.query(UserAccount).filter_by(username_normalized="local.user").one().status,"locked")

    def test_approval_pending_rejected_disabled_statuses(self):
        os.environ["THREATSCOPE_REGISTRATION_MODE"]="approval_required"
        pending=self.register();self.assertEqual(pending.json()["registration_status"],"pending_approval");self.assertEqual(self.login("local.user").json()["account_status"],"pending_approval")
        admin=authenticate_admin(self.client,self.factory)
        listed=self.client.get("/api/admin/registrations");self.assertEqual(listed.status_code,200);uid=listed.json()["items"][0]["id"]
        approved=self.client.post(f"/api/admin/registrations/{uid}/approve",json={"role_keys":["registered_user"]});self.assertEqual(approved.status_code,200,approved.text);self.assertEqual(self.login("gmail.user@gmail.com").status_code,200)
        authenticate_admin(self.client,self.factory);rejected=self.client.post(f"/api/admin/registrations/{uid}/reject",json={"reason":"Local access is not approved."});self.assertEqual(rejected.status_code,200);self.assertEqual(self.login("local.user").json()["account_status"],"rejected")
        authenticate_admin(self.client,self.factory);self.assertEqual(self.client.post(f"/api/admin/registrations/{uid}/reopen").json()["status"],"pending_approval")
        with self.factory() as db:u=db.get(UserAccount,uid);u.status="disabled";db.commit()
        self.assertEqual(self.login("local.user").status_code,401)

    def test_approval_authorization_roles_and_rollback(self):
        os.environ["THREATSCOPE_REGISTRATION_MODE"]="approval_required";self.register()
        with self.factory() as db:user=db.query(UserAccount).filter_by(username_normalized="local.user").one();user_id=user.id
        self.login("local.user");self.assertEqual(self.client.get("/api/admin/registrations").status_code,401)
        authenticate_admin(self.client,self.factory)
        self.assertEqual(self.client.post(f"/api/admin/registrations/{user_id}/approve",json={"role_keys":["administrator"]}).status_code,422)
        self.assertEqual(self.client.post(f"/api/admin/registrations/{user_id}/approve",json={"role_keys":["missing"]}).status_code,422)
        with self.factory() as db:
            role=db.query(AccessRole).filter_by(role_key="registered_user").one();role.enabled=False;db.commit()
        self.assertEqual(self.client.post(f"/api/admin/registrations/{user_id}/approve",json={"role_keys":["registered_user"]}).status_code,422)

    def test_analyst_registered_user_denied_and_operational_approval(self):
        os.environ["THREATSCOPE_REGISTRATION_MODE"]="approval_required";self.register()
        with self.factory() as db:
            pending_id=db.query(UserAccount).filter_by(username_normalized="local.user").one().id
            create_user(db,username="analyst.user",email="analyst@example.test",display_name="Analyst User",password="Analyst-Local-Password-84!",role_keys=["security_analyst"],must_change_password=False)
        self.login("analyst.user","Analyst-Local-Password-84!");self.assertEqual(self.client.get("/api/admin/registrations").status_code,403)
        os.environ["THREATSCOPE_REGISTRATION_MODE"]="auto_activate_limited"
        limited=self.register(email="limited@example.test",username="limited.user",password="Scope-Account-Password-83!");self.assertEqual(limited.status_code,201)
        self.login("limited.user","Scope-Account-Password-83!");self.assertEqual(self.client.get("/api/admin/registrations").status_code,403)
        authenticate_admin(self.client,self.factory)
        approved=self.client.post(f"/api/admin/registrations/{pending_id}/approve",json={"role_keys":["security_analyst"]});self.assertEqual(approved.status_code,200,approved.text)
        with self.factory() as db:self.assertEqual(role_keys(db,pending_id),["security_analyst"])

    def test_failed_approval_creates_no_success_side_effects(self):
        os.environ["THREATSCOPE_REGISTRATION_MODE"]="approval_required";self.register();authenticate_admin(self.client,self.factory)
        with self.factory() as db:
            pending=db.query(UserAccount).filter_by(username_normalized="local.user").one();counts=(db.query(models.Notification).count(),db.query(models.SocActivity).filter_by(action="account_approved").count(),db.query(SecurityAuditEvent).filter_by(event_type="account_approved").count())
        failed=self.client.post(f"/api/admin/registrations/{pending.id}/approve",json={"role_keys":["not_a_role"]});self.assertEqual(failed.status_code,422)
        with self.factory() as db:
            after=(db.query(models.Notification).count(),db.query(models.SocActivity).filter_by(action="account_approved").count(),db.query(SecurityAuditEvent).filter_by(event_type="account_approved").count());self.assertEqual(after,counts);self.assertEqual(db.get(UserAccount,pending.id).status,"pending_approval")

    def test_mfa_and_password_change_compatibility_contract(self):
        self.register()
        with self.factory() as db:u=db.query(UserAccount).filter_by(username_normalized="local.user").one();u.must_change_password=True;u.status="pending_password_change";db.commit()
        response=self.login("gmail.user@gmail.com");self.assertEqual(response.status_code,200);self.assertTrue(response.json()["user"]["must_change_password"])

    def test_audit_and_notifications_contain_no_password(self):
        self.register()
        with self.factory() as db:
            serialized=json.dumps([event.metadata_json for event in db.query(SecurityAuditEvent).all()]);self.assertNotIn("Separate-ThreatScope",serialized)
            notices=json.dumps([{"title":n.title,"message":n.message} for n in db.query(models.Notification).all()]);self.assertNotIn("Separate-ThreatScope",notices)
            self.assertTrue(db.query(models.SocActivity).filter_by(action="account_registered").count())

    def test_cli_additional_admin_reset_and_safe_list(self):
        with self.factory() as db:create_user(db,username="smoke.user",email="smoke@example.test",display_name="Smoke User",password="Smoke-Local-Password-88!",role_keys=["registered_user"],must_change_password=False)
        original_factory,original_engine=manage_accounts.SessionLocal,manage_accounts.engine;manage_accounts.SessionLocal,manage_accounts.engine=self.factory,self.engine
        try:
            with patch("builtins.input",side_effect=["owner@example.test","owner.user","Owner User"]),patch("getpass.getpass",side_effect=["Owner-Local-Password-97!","Owner-Local-Password-97!"]):manage_accounts.run(SimpleNamespace(command="create-admin"))
            output=io.StringIO()
            with redirect_stdout(output):manage_accounts.run(SimpleNamespace(command="list"))
            self.assertNotIn("Owner-Local-Password",output.getvalue());self.assertNotIn("$argon2",output.getvalue())
            with self.factory() as db:owner=db.query(UserAccount).filter_by(username_normalized="owner.user").one();self.assertTrue(owner.is_system_admin);self.assertIn("administrator",role_keys(db,owner.id))
            with patch("getpass.getpass",side_effect=["Reset-Local-Password-79!","Reset-Local-Password-79!"]):manage_accounts.run(SimpleNamespace(command="reset-password",identifier="owner@example.test",no_force_change=False))
            with self.factory() as db:owner=db.query(UserAccount).filter_by(username_normalized="owner.user").one();self.assertTrue(verify_password(owner.password_hash,"Reset-Local-Password-79!"));self.assertTrue(owner.must_change_password)
            with self.assertRaises(ValueError):manage_accounts.run(SimpleNamespace(command="disable",identifier="owner.user"))
        finally:manage_accounts.SessionLocal,manage_accounts.engine=original_factory,original_engine

    def test_cli_lifecycle_commands_and_duplicate_rejection(self):
        with self.factory() as db:
            user=create_user(db,username="command.user",email="command@example.test",display_name="Command User",password="Command-Local-Password-88!",role_keys=["registered_user"],must_change_password=False)
            user.status="locked";user.failed_login_count=5;db.commit()
        original_factory,original_engine=manage_accounts.SessionLocal,manage_accounts.engine;manage_accounts.SessionLocal,manage_accounts.engine=self.factory,self.engine
        try:
            manage_accounts.run(SimpleNamespace(command="unlock",identifier="command.user"));manage_accounts.run(SimpleNamespace(command="disable",identifier="command.user"));manage_accounts.run(SimpleNamespace(command="enable",identifier="command.user"));manage_accounts.run(SimpleNamespace(command="assign-role",identifier="command.user",role="auditor"));manage_accounts.run(SimpleNamespace(command="revoke-sessions",identifier="command.user"))
            with self.factory() as db:
                user=db.query(UserAccount).filter_by(username_normalized="command.user").one();self.assertEqual(user.status,"active");self.assertEqual(role_keys(db,user.id),["auditor","registered_user"])
            with patch("builtins.input",side_effect=["command@example.test","different.user","Duplicate User"]),patch("getpass.getpass",side_effect=["Different-Local-Password-98!","Different-Local-Password-98!"]):
                with self.assertRaises(ValueError):manage_accounts.run(SimpleNamespace(command="create-user"))
            with patch("builtins.input",side_effect=["weak@example.test","weak.user","Weak User"]),patch("getpass.getpass",side_effect=["password1234","password1234"]):
                with self.assertRaises(ValueError):manage_accounts.run(SimpleNamespace(command="create-user"))
        finally:manage_accounts.SessionLocal,manage_accounts.engine=original_factory,original_engine

    def test_frontend_static_security_contract(self):
        root=Path(__file__).resolve().parents[2] / "frontend" / "src"
        combined="\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*") if path.suffix in {".ts",".tsx"})
        for required in ("Create Account","Email or username","/signup","account-pending","account-rejected","RegistrationManagementPage","clearExpiredSession"):self.assertIn(required,combined)
        for forbidden in ("GoogleSignInButton","GoogleIdentityPanel","accounts.google.com","gapi.load"):self.assertNotIn(forbidden,combined)
        self.assertNotIn("admin/admin",combined.casefold())
        landing=(root/"pages"/"access"/"PublicLandingPage.tsx").read_text(encoding="utf-8").casefold()
        for protected_metric in ("finding count","alert count","backup state","user count"):self.assertNotIn(protected_metric,landing)


if __name__ == "__main__": unittest.main()
