import json
import os
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pyotp
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.modules.access_control import mfa_service
from app.modules.access_control.audit_service import verify_integrity
from app.modules.access_control.models import MfaDevice, MfaRecoveryCode, SecurityAuditEvent, UserAccount
from app.modules.access_control.session_service import utcnow
from tests.access_helpers import TEST_ADMIN_PASSWORD, TEST_ADMIN_USERNAME, authenticate_admin


class TotpEnrollmentTests(unittest.TestCase):
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
        cls.client.close()
        app.dependency_overrides.clear()
        cls.engine.dispose()

    def setUp(self):
        os.environ["THREATSCOPE_MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode("ascii")
        os.environ["THREATSCOPE_SESSION_SECRET"] = "totp-test-session-pepper-value-123456789"
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        self.admin = authenticate_admin(self.client, self.factory)

    def refresh_csrf(self):
        response = self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers.update({"X-CSRF-Token": response.json()["csrf_token"]})

    def start(self, restart=False):
        response = self.client.post("/api/auth/mfa/enroll", json={
            "current_password": TEST_ADMIN_PASSWORD,
            "label": "Test authenticator",
            "restart": restart,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def confirm(self, setup, code=None):
        value = code or pyotp.TOTP(setup["manual_setup_key"]).now()
        return self.client.post("/api/auth/mfa/confirm", json={"device_id": setup["device_id"], "code": value})

    def logout(self):
        self.refresh_csrf()
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)

    def password_login(self):
        self.client.cookies.clear()
        self.client.headers.pop("X-CSRF-Token", None)
        return self.client.post("/api/auth/login", json={"identifier": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD})

    def test_start_requires_authentication_and_csrf(self):
        anonymous = TestClient(app)
        response = anonymous.post("/api/auth/mfa/enroll", json={"current_password": TEST_ADMIN_PASSWORD, "label": "Test"})
        self.assertEqual(response.status_code, 401)
        anonymous.close()
        self.client.headers.pop("X-CSRF-Token", None)
        response = self.client.post("/api/auth/mfa/enroll", json={"current_password": TEST_ADMIN_PASSWORD, "label": "Test"})
        self.assertEqual(response.status_code, 403)

    def test_pending_and_disabled_accounts_are_denied(self):
        with self.factory() as db:
            user = db.get(UserAccount, self.admin["id"])
            user.status = "pending_password_change"
            user.must_change_password = True
            db.commit()
        pending = self.client.post("/api/auth/mfa/enroll", json={"current_password": TEST_ADMIN_PASSWORD, "label": "Test"})
        self.assertEqual(pending.status_code, 403)
        with self.factory() as db:
            user = db.get(UserAccount, self.admin["id"])
            user.status = "disabled"
            user.must_change_password = False
            db.commit()
        disabled = self.client.post("/api/auth/mfa/enroll", json={"current_password": TEST_ADMIN_PASSWORD, "label": "Test"})
        self.assertEqual(disabled.status_code, 401)

    def test_start_encrypts_secret_and_returns_compatible_setup(self):
        setup = self.start()
        self.assertEqual(setup["issuer"], "ThreatScope XDR")
        self.assertEqual(setup["account_label"], "test-admin@example.test")
        self.assertTrue(setup["provisioning_uri"].startswith("otpauth://totp/"))
        self.assertIn("issuer=ThreatScope%20XDR", setup["provisioning_uri"])
        self.assertGreaterEqual(len(setup["manual_setup_key"]), 32)
        with self.factory() as db:
            device = db.get(MfaDevice, setup["device_id"])
            self.assertFalse(device.enabled)
            self.assertIsNone(device.confirmed_at)
            self.assertIsNotNone(device.enrollment_expires_at)
            self.assertNotEqual(device.secret_encrypted_or_protected, setup["manual_setup_key"])
            self.assertNotIn(setup["manual_setup_key"], device.secret_encrypted_or_protected)
            self.assertEqual(db.query(MfaRecoveryCode).count(), 0)

    def test_repeated_start_resumes_and_explicit_restart_replaces_pending_setup(self):
        first = self.start()
        resumed = self.start()
        self.assertEqual(resumed["operation"], "resumed")
        self.assertEqual(resumed["device_id"], first["device_id"])
        self.assertEqual(resumed["manual_setup_key"], first["manual_setup_key"])
        restarted = self.start(restart=True)
        self.assertEqual(restarted["operation"], "restarted")
        self.assertNotEqual(restarted["manual_setup_key"], first["manual_setup_key"])
        with self.factory() as db:
            self.assertEqual(db.query(MfaDevice).filter_by(user_id=self.admin["id"], enabled=False).count(), 1)

    def test_confirm_rejects_missing_csrf_malformed_incorrect_expired_and_replayed_codes(self):
        setup = self.start()
        anonymous = TestClient(app)
        self.assertEqual(anonymous.post("/api/auth/mfa/confirm", json={"device_id": setup["device_id"], "code": "123456"}).status_code, 401)
        anonymous.close()
        self.client.headers.pop("X-CSRF-Token", None)
        self.assertEqual(self.confirm(setup).status_code, 403)
        self.refresh_csrf()
        self.assertEqual(self.confirm(setup, "123").status_code, 422)
        self.assertEqual(self.confirm(setup, "000000").status_code, 422)
        with self.factory() as db:
            device = db.get(MfaDevice, setup["device_id"])
            self.assertFalse(device.enabled)
            device.enrollment_expires_at = utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.confirm(setup).status_code, 409)
        setup = self.start(restart=True)
        code = pyotp.TOTP(setup["manual_setup_key"]).now()
        self.assertEqual(self.confirm(setup, code).status_code, 200)
        self.refresh_csrf()
        self.assertEqual(self.confirm(setup, code).status_code, 409)

    def test_too_many_invalid_confirmation_attempts_are_bounded(self):
        setup = self.start()
        valid = pyotp.TOTP(setup["manual_setup_key"]).now()
        invalid = f"{(int(valid) + 1) % 1_000_000:06d}"
        for _ in range(mfa_service.MAX_ENROLLMENT_ATTEMPTS - 1):
            self.assertEqual(self.confirm(setup, invalid).status_code, 422)
        self.assertEqual(self.confirm(setup, invalid).status_code, 429)
        self.assertEqual(self.confirm(setup, valid).status_code, 429)
        with self.factory() as db:
            self.assertFalse(db.get(UserAccount, self.admin["id"]).mfa_enabled)

    def test_valid_confirmation_is_atomic_and_returns_hashed_recovery_codes_once(self):
        setup = self.start()
        response = self.confirm(setup)
        self.assertEqual(response.status_code, 200, response.text)
        codes = response.json()["recovery_codes"]
        self.assertEqual(len(codes), mfa_service.RECOVERY_CODE_COUNT)
        with self.factory() as db:
            user = db.get(UserAccount, self.admin["id"])
            device = db.get(MfaDevice, setup["device_id"])
            stored = db.query(MfaRecoveryCode).filter_by(user_id=user.id).all()
            self.assertTrue(user.mfa_enabled)
            self.assertTrue(device.enabled)
            self.assertIsNotNone(device.confirmed_at)
            self.assertIsNone(device.enrollment_expires_at)
            self.assertEqual(len(stored), len(codes))
            serialized_hashes = json.dumps([item.code_hash for item in stored])
            for code in codes:
                self.assertNotIn(code, serialized_hashes)
                self.assertNotIn(code.replace("-", ""), serialized_hashes)
        status = self.client.get("/api/auth/mfa/status")
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json()["enabled"])
        self.assertNotIn("secret", json.dumps(status.json()).lower())
        self.refresh_csrf()
        self.assertEqual(self.confirm(setup).status_code, 409)

    def test_confirmation_rolls_back_when_recovery_generation_fails(self):
        with self.factory() as db:
            user = db.get(UserAccount, self.admin["id"])
            device, secret, _, _ = mfa_service.begin_enrollment(db, user, "Rollback test", restart=True)
            with patch.object(mfa_service, "generate_recovery_codes", side_effect=RuntimeError("simulated storage failure")):
                with self.assertRaises(RuntimeError):
                    mfa_service.confirm_enrollment(db, user, pyotp.TOTP(secret).now(), device.id)
            db.expire_all()
            user = db.get(UserAccount, self.admin["id"])
            device = db.get(MfaDevice, device.id)
            self.assertFalse(user.mfa_enabled)
            self.assertFalse(device.enabled)
            self.assertIsNone(device.confirmed_at)
            self.assertEqual(db.query(MfaRecoveryCode).count(), 0)

    def test_cancel_removes_only_pending_setup_and_never_disables_confirmed_mfa(self):
        setup = self.start()
        cancelled = self.client.post("/api/auth/mfa/cancel")
        self.assertEqual(cancelled.status_code, 200)
        with self.factory() as db:
            self.assertIsNone(db.get(MfaDevice, setup["device_id"]))
        setup = self.start()
        self.assertEqual(self.confirm(setup).status_code, 200)
        self.refresh_csrf()
        self.assertEqual(self.client.post("/api/auth/mfa/cancel").status_code, 200)
        with self.factory() as db:
            self.assertTrue(db.get(MfaDevice, setup["device_id"]).enabled)
            self.assertTrue(db.get(UserAccount, self.admin["id"]).mfa_enabled)

    def test_confirmed_mfa_login_totp_and_one_time_recovery_flow(self):
        setup = self.start()
        confirmed = self.confirm(setup)
        recovery = confirmed.json()["recovery_codes"][0]
        self.logout()
        challenge = self.password_login()
        self.assertEqual(challenge.status_code, 200)
        self.assertTrue(challenge.json()["requires_mfa"])
        self.assertNotIn("user", challenge.json())
        invalid = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge.json()["challenge_token"], "code": "000000", "recovery_code": False})
        self.assertEqual(invalid.status_code, 401)
        future = utcnow() + timedelta(seconds=30)
        future_code = pyotp.TOTP(setup["manual_setup_key"]).at(time.time() + 30)
        with patch.object(mfa_service, "utcnow", return_value=future):
            valid = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge.json()["challenge_token"], "code": future_code, "recovery_code": False})
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertNotIn("token", valid.text.lower())
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        self.logout()
        challenge = self.password_login().json()["challenge_token"]
        recovered = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge, "code": recovery, "recovery_code": True})
        self.assertEqual(recovered.status_code, 200, recovered.text)
        self.logout()
        challenge = self.password_login().json()["challenge_token"]
        replay = self.client.post("/api/auth/mfa/verify-login", json={"challenge_token": challenge, "code": recovery, "recovery_code": True})
        self.assertEqual(replay.status_code, 401)

    def test_regeneration_invalidates_old_codes_and_disable_requires_confirmation(self):
        setup = self.start()
        old_codes = self.confirm(setup).json()["recovery_codes"]
        self.refresh_csrf()
        future = utcnow() + timedelta(seconds=30)
        future_code = pyotp.TOTP(setup["manual_setup_key"]).at(time.time() + 30)
        with patch.object(mfa_service, "utcnow", return_value=future):
            regenerated = self.client.post("/api/auth/mfa/recovery/regenerate", json={"current_password": TEST_ADMIN_PASSWORD, "code": future_code, "recovery_code": False})
        self.assertEqual(regenerated.status_code, 200, regenerated.text)
        new_codes = regenerated.json()["recovery_codes"]
        with self.factory() as db:
            old_hashes = {mfa_service.recovery_hash(code) for code in old_codes}
            current_hashes = {row.code_hash for row in db.query(MfaRecoveryCode).all()}
            self.assertTrue(old_hashes.isdisjoint(current_hashes))
        self.refresh_csrf()
        missing_confirmation = self.client.post("/api/auth/mfa/disable", json={"current_password": TEST_ADMIN_PASSWORD, "code": new_codes[0], "recovery_code": True})
        self.assertEqual(missing_confirmation.status_code, 422)
        disabled = self.client.post("/api/auth/mfa/disable", json={"current_password": TEST_ADMIN_PASSWORD, "code": new_codes[0], "recovery_code": True, "confirm_disable": True})
        self.assertEqual(disabled.status_code, 200, disabled.text)
        with self.factory() as db:
            self.assertFalse(db.get(UserAccount, self.admin["id"]).mfa_enabled)
            self.assertEqual(db.query(MfaRecoveryCode).count(), 0)

    def test_audit_chain_contains_no_setup_or_recovery_material(self):
        setup = self.start()
        confirmed = self.confirm(setup)
        sensitive = [setup["manual_setup_key"], setup["provisioning_uri"], *confirmed.json()["recovery_codes"]]
        with self.factory() as db:
            events = db.query(SecurityAuditEvent).all()
            serialized = json.dumps([{
                "event_type": item.event_type,
                "action": item.action,
                "reason": item.reason_code,
                "metadata": item.metadata_json,
            } for item in events])
            for value in sensitive:
                self.assertNotIn(value, serialized)
                self.assertNotIn(value.replace("-", ""), serialized)
            self.assertTrue(verify_integrity(db)["valid_chain"])


class TotpFrontendContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parents[2]
        frontend = root / "frontend"
        cls.dashboard = (frontend / "src/pages/Dashboard.tsx").read_text(encoding="utf-8")
        cls.security = (frontend / "src/pages/access/ProfileSecurityPage.tsx").read_text(encoding="utf-8")
        cls.panel = (frontend / "src/pages/access/components/MfaEnrollmentPanel.tsx").read_text(encoding="utf-8")
        cls.dialog = (frontend / "src/pages/access/components/TotpEnrollmentDialog.tsx").read_text(encoding="utf-8")
        cls.recovery = (frontend / "src/pages/access/components/RecoveryCodesPanel.tsx").read_text(encoding="utf-8")
        cls.api = (frontend / "src/api/mfa.ts").read_text(encoding="utf-8")
        cls.package = (frontend / "package.json").read_text(encoding="utf-8")

    def test_both_entry_points_use_the_same_live_component(self):
        self.assertIn("<MfaEnrollmentPanel", self.dashboard)
        self.assertIn("<MfaEnrollmentPanel", self.security)
        self.assertIn("<TotpEnrollmentDialog", self.panel)
        self.assertIn("onClick={() => openEnrollment(false)}", self.panel)

    def test_dialog_calls_typed_api_and_renders_local_qr_manual_key_and_six_digits(self):
        self.assertIn("mfaApi.startEnrollment", self.dialog)
        self.assertIn("mfaApi.confirmEnrollment", self.dialog)
        self.assertIn("QRCodeSVG", self.dialog)
        self.assertIn("qrcode.react", self.package)
        self.assertIn("manual_setup_key", self.dialog)
        self.assertIn("inputMode=\"numeric\"", self.dialog)
        self.assertIn("/^\\d{6}$/", self.dialog)
        self.assertNotIn("http://", self.dialog)
        self.assertNotIn("https://", self.dialog)
        self.assertNotIn("Google", self.dialog)

    def test_recovery_acknowledgement_and_in_memory_download_are_required(self):
        self.assertIn("I have saved my recovery codes", self.recovery)
        self.assertIn("URL.createObjectURL(new Blob", self.recovery)
        self.assertIn("disabled={!acknowledged", self.recovery)
        combined = self.dialog + self.recovery + self.api
        self.assertNotIn("localStorage", combined)
        self.assertNotIn("sessionStorage", combined)

    def test_completion_refreshes_auth_and_status_without_session_expiry_copy(self):
        self.assertIn("await onCompleted()", self.dialog)
        self.assertIn("await onChanged(); await loadStatus();", self.panel)
        self.assertIn("status?.enabled", self.panel)
        self.assertNotIn("Session expired", self.dialog + self.panel + self.api)


if __name__ == "__main__":
    unittest.main()
