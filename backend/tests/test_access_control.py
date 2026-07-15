import json
import os
import unittest
from datetime import timedelta

import pyotp
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.modules.access_control.audit_service import verify_integrity
from app.modules.access_control.models import (
    AccessPermission,
    AccessRole,
    AuthSession,
    MfaDevice,
    MfaRecoveryCode,
    RolePermissionAssignment,
    SecurityAuditEvent,
    UserAccount,
)
from app.modules.access_control.password_service import hash_password, verify_password
from app.modules.access_control.role_service import effective_permissions, seed_roles_and_permissions
from app.modules.access_control.session_service import utcnow
from app.modules.access_control.session_service import hash_value
from app.modules.access_control.user_service import create_user
from tests.access_helpers import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, authenticate_admin


class AccessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cls.factory = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

        def override():
            with cls.factory() as db:
                yield db

        app.dependency_overrides[get_db] = override
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close(); app.dependency_overrides.clear(); cls.engine.dispose()

    def setUp(self):
        os.environ["THREATSCOPE_MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        os.environ["THREATSCOPE_SESSION_SECRET"] = "test-only-session-pepper-value-123456789"
        Base.metadata.drop_all(self.engine); Base.metadata.create_all(self.engine)
        self.admin = authenticate_admin(self.client, self.factory)

    def refresh_csrf(self):
        response = self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers.update({"X-CSRF-Token": response.json()["csrf_token"]})

    def login(self, username, password):
        self.client.cookies.clear(); self.client.headers.pop("X-CSRF-Token", None)
        return self.client.post("/api/auth/login", json={"username": username, "password": password})

    def create_role_user(self, username, role_key, password="Valid-Local-Password-83!"):
        with self.factory() as db:
            return create_user(db, username=username, display_name=f"{role_key} user", password=password, role_keys=[role_key], must_change_password=False).id

    def test_permission_and_system_role_seeding_is_idempotent(self):
        with self.factory() as db:
            counts = (db.query(AccessPermission).count(), db.query(AccessRole).count(), db.query(RolePermissionAssignment).count())
            seed_roles_and_permissions(db)
            self.assertEqual(counts, (db.query(AccessPermission).count(), db.query(AccessRole).count(), db.query(RolePermissionAssignment).count()))
            self.assertEqual({r.role_key for r in db.query(AccessRole).filter_by(system_role=True)}, {"administrator", "registered_user", "security_analyst", "auditor", "executive_viewer"})
            admin = db.query(AccessRole).filter_by(role_key="administrator").one()
            self.assertEqual(len(admin.permissions), db.query(AccessPermission).count())

    def test_argon2id_policy_and_no_plaintext_persistence(self):
        digest = hash_password("Unicode-安全-Password-77!", "policy.user")
        self.assertTrue(digest.startswith("$argon2id$")); self.assertNotIn("Unicode", digest)
        self.assertTrue(verify_password(digest, "Unicode-安全-Password-77!"))
        with self.assertRaises(ValueError): hash_password("short", "policy.user")
        with self.assertRaises(ValueError): hash_password("policy.user-password-77!", "policy.user")
        with self.factory() as db:
            stored = db.get(UserAccount, self.admin["id"])
            self.assertNotEqual(stored.password_hash, TEST_ADMIN_PASSWORD)

    def test_public_health_and_protected_route(self):
        self.client.cookies.clear(); self.client.headers.pop("X-CSRF-Token", None)
        self.assertEqual(self.client.get("/health").status_code, 200)
        response = self.client.get("/api/dashboard/summary")
        self.assertEqual(response.status_code, 401); self.assertIn("request_id", response.json())

    def test_login_cookie_opaque_session_and_csrf(self):
        response = self.login(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD)
        self.assertEqual(response.status_code, 200, response.text); self.assertNotIn("token", response.text.lower())
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=lax", cookie)
        with self.factory() as db:
            raw = self.client.cookies.get("threatscope_session")
            session = db.query(AuthSession).filter_by(token_hash=hash_value(raw)).one()
            self.assertNotEqual(raw, session.token_hash); self.assertEqual(len(session.token_hash), 64)
        missing = self.client.post("/api/auth/logout")
        self.assertEqual(missing.status_code, 403)
        self.refresh_csrf(); self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)

    def test_generic_login_failures_and_temporary_lockout(self):
        self.login("unknown.user", "Wrong-Password-Value!")
        unknown = self.client.post("/api/auth/login", json={"username": "unknown.user", "password": "Wrong-Password-Value!"})
        known = self.client.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": "Wrong-Password-Value!"})
        self.assertEqual(unknown.status_code, 401); self.assertEqual(known.status_code, 401)
        self.assertEqual(unknown.json()["detail"], known.json()["detail"])
        for _ in range(4): self.client.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": "Wrong-Password-Value!"})
        limited = self.client.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})
        self.assertIn(limited.status_code, (401, 429))
        with self.factory() as db:
            user = db.query(UserAccount).filter_by(username_normalized=TEST_ADMIN_USERNAME).one()
            self.assertEqual(user.status, "locked"); user.locked_until = utcnow() - timedelta(seconds=1); db.commit()
        self.assertEqual(self.client.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}).status_code, 200)

    def test_role_authorization_and_dashboard_filtering(self):
        self.create_role_user("analyst.user", "security_analyst")
        response = self.login("analyst.user", "Valid-Local-Password-83!"); self.assertEqual(response.status_code, 200)
        self.refresh_csrf()
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code, 200)
        self.assertEqual(self.client.get("/api/admin/users").status_code, 403)
        self.assertNotIn("users:manage", response.json()["user"]["permissions"])
        self.create_role_user("audit.user", "auditor")
        self.assertEqual(self.login("audit.user", "Valid-Local-Password-83!").status_code, 200); self.refresh_csrf()
        self.assertEqual(self.client.get("/api/security-audit/events").status_code, 200)
        self.assertEqual(self.client.post("/api/scans/start", json={"target_id": 1, "profile": "safe"}).status_code, 403)

    def test_user_lifecycle_password_reset_and_last_admin(self):
        created = self.client.post("/api/admin/users", json={"username": "managed.user", "display_name": "Managed User", "role_keys": ["security_analyst"]})
        self.assertEqual(created.status_code, 200, created.text); temp = created.json()["temporary_password"]
        self.assertNotIn(temp, json.dumps(created.json()["user"])); user_id = created.json()["user"]["id"]
        self.assertEqual(self.client.post(f"/api/admin/users/{self.admin['id']}/disable").status_code, 422)
        self.assertEqual(self.client.post(f"/api/admin/users/{user_id}/disable").status_code, 200)
        self.assertEqual(self.login("managed.user", temp).status_code, 401)
        authenticate_admin(self.client, self.factory)
        disabled_reset = self.client.post(f"/api/admin/users/{user_id}/reset-password", json={})
        self.assertEqual(disabled_reset.status_code, 200)
        self.assertEqual(self.client.get(f"/api/admin/users/{user_id}").json()["status"], "disabled")
        self.assertEqual(self.client.post(f"/api/admin/users/{user_id}/enable").status_code, 200)
        reset = self.client.post(f"/api/admin/users/{user_id}/reset-password", json={})
        self.assertEqual(reset.status_code, 200); self.assertTrue(reset.json()["temporary_password"])

    def test_session_revocation_and_password_change_revoke_other_sessions(self):
        first_cookie = self.client.cookies.get("threatscope_session")
        second = TestClient(app); login = second.post("/api/auth/login", json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD}); self.assertEqual(login.status_code, 200)
        csrf = second.get("/api/auth/csrf").json()["csrf_token"]; second.headers.update({"X-CSRF-Token": csrf})
        change = second.post("/api/auth/password/change", json={"current_password": TEST_ADMIN_PASSWORD, "new_password": "Different-Secure-Password-91!"})
        self.assertEqual(change.status_code, 200, change.text)
        self.client.cookies.set("threatscope_session", first_cookie)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        second.close()

    def test_totp_challenge_recovery_code_and_secret_protection(self):
        enroll = self.client.post("/api/auth/mfa/enroll", json={"current_password": TEST_ADMIN_PASSWORD, "label": "Test authenticator"})
        self.assertEqual(enroll.status_code, 200, enroll.text); secret = enroll.json()["secret"]
        confirm = self.client.post("/api/auth/mfa/confirm", json={"device_id": enroll.json()["device_id"], "code": pyotp.TOTP(secret).now()})
        self.assertEqual(confirm.status_code, 200, confirm.text); recovery = confirm.json()["recovery_codes"][0]
        with self.factory() as db:
            user = db.get(UserAccount, self.admin["id"]); device = db.query(MfaDevice).filter_by(user_id=user.id).one()
            self.assertNotIn(secret, device.secret_encrypted_or_protected)
            self.assertFalse(any(recovery.replace("-", "") in row.code_hash for row in db.query(MfaRecoveryCode).all()))
        self.refresh_csrf(); self.client.post("/api/auth/logout")
        challenge = self.login(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD).json()["challenge_token"]
        verified = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge, "code": recovery, "recovery_code": True})
        self.assertEqual(verified.status_code, 200, verified.text)
        self.refresh_csrf(); self.client.post("/api/auth/logout")
        challenge2 = self.login(TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD).json()["challenge_token"]
        reused = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge2, "code": recovery, "recovery_code": True})
        self.assertEqual(reused.status_code, 401)

    def test_custom_role_permission_removal_has_no_stale_session(self):
        role = self.client.post("/api/admin/roles", json={"role_key": "limited_view", "name": "Limited View", "permission_keys": ["dashboard:view"]}).json()
        self.create_role_user("limited.user", "limited_view")
        self.assertEqual(self.login("limited.user", "Valid-Local-Password-83!").status_code, 200); self.refresh_csrf()
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code, 200)
        authenticate_admin(self.client, self.factory)
        changed = self.client.put(f"/api/admin/roles/{role['id']}/permissions", json={"permission_keys": []})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.login("limited.user", "Valid-Local-Password-83!").status_code, 200); self.refresh_csrf()
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code, 403)

    def test_audit_redaction_chain_and_tamper_detection(self):
        self.client.post("/api/admin/users", json={"username": "audit.target", "display_name": "Audit Target", "temporary_password": "Never-Store-This-Password-55!"})
        with self.factory() as db:
            events = db.query(SecurityAuditEvent).all(); self.assertTrue(events)
            serialized = json.dumps([event.metadata_json for event in events])
            self.assertNotIn("Never-Store-This-Password", serialized)
            self.assertTrue(verify_integrity(db)["valid_chain"])
            events[0].action = "tampered"; db.commit()
            result = verify_integrity(db); self.assertFalse(result["valid_chain"]); self.assertIsNotNone(result["first_invalid_sequence"])
        self.assertEqual(self.client.put("/api/security-audit/events/1", json={}).status_code, 405)
        self.assertEqual(self.client.delete("/api/security-audit/events/1").status_code, 405)


if __name__ == "__main__":
    unittest.main()
