import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from app.modules.production.config import ConfigurationError, RuntimeProfile, get_runtime_config
from app.modules.production.secrets import MAX_SECRET_BYTES, SecretLoadError, load_secret


def production_environment(root: Path) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    secrets_dir = root / "secrets"; secrets_dir.mkdir(exist_ok=True)
    tls_dir = root / "tls"; tls_dir.mkdir(exist_ok=True)
    session = secrets_dir / "session"; session.write_text("strong-production-session-material-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", encoding="utf-8")
    values = {}
    for name in ("mfa", "connector", "backup"):
        path = secrets_dir / name; path.write_bytes(Fernet.generate_key()); values[name] = str(path.resolve())
    certificate = tls_dir / "tls.crt"; certificate.write_text("test-only-certificate-placeholder", encoding="utf-8")
    private_key = tls_dir / "tls.key"; private_key.write_text("test-only-key-placeholder", encoding="utf-8")
    database = (root / "data" / "vulnscope.db").resolve().as_posix()
    return {
        "THREATSCOPE_PROFILE": "production",
        "THREATSCOPE_DEBUG": "false",
        "THREATSCOPE_RELOAD": "false",
        "THREATSCOPE_API_DOCS": "false",
        "THREATSCOPE_ALLOWED_HOSTS": "security.example.test",
        "THREATSCOPE_ALLOWED_ORIGINS": "https://security.example.test",
        "THREATSCOPE_TRUSTED_PROXY_NETWORKS": "172.20.0.0/16",
        "THREATSCOPE_COOKIE_SECURE": "true",
        "THREATSCOPE_CSRF_ENABLED": "true",
        "THREATSCOPE_TLS_PROXY_EXPECTED": "true",
        "THREATSCOPE_WORKERS": "1",
        "THREATSCOPE_DEMO_MODE": "false",
        "THREATSCOPE_SELF_REGISTRATION_ENABLED": "false",
        "THREATSCOPE_REGISTRATION_MODE": "disabled",
        "THREATSCOPE_BUILD_COMMIT": "b150ffd35c25397857f7c25ca69ea346dc63fe99",
        "THREATSCOPE_APP_VERSION": "1.0.0-rc2",
        "THREATSCOPE_RUNTIME_DIR": str((root / "runtime").resolve()),
        "THREATSCOPE_DATA_DIR": str((root / "data").resolve()),
        "THREATSCOPE_BACKUP_DIR": str((root / "backups").resolve()),
        "THREATSCOPE_UPLOAD_DIR": str((root / "uploads").resolve()),
        "THREATSCOPE_REPORT_DIR": str((root / "reports").resolve()),
        "DATABASE_URL": f"sqlite:////{database.lstrip('/')}",
        "THREATSCOPE_SESSION_SECRET_FILE": str(session.resolve()),
        "THREATSCOPE_MFA_ENCRYPTION_KEY_FILE": values["mfa"],
        "THREATSCOPE_CONNECTOR_SECRETS_KEY_FILE": values["connector"],
        "THREATSCOPE_BACKUP_ENCRYPTION_KEY_FILE": values["backup"],
        "THREATSCOPE_REQUIRE_BACKUP_ENCRYPTION": "true",
        "THREATSCOPE_TLS_CERTIFICATE_FILE": str(certificate.resolve()),
        "THREATSCOPE_TLS_PRIVATE_KEY_FILE": str(private_key.resolve()),
    }


class ProductionConfigurationTests(unittest.TestCase):
    def test_explicit_profiles_and_compatibility(self):
        for value in ("development", "test"):
            with self.subTest(value=value), patch.dict(os.environ, {"THREATSCOPE_PROFILE": value}, clear=True):
                self.assertEqual(get_runtime_config().profile, RuntimeProfile(value))
        with patch.dict(os.environ, {"THREATSCOPE_ENV": "test"}, clear=True):
            self.assertEqual(get_runtime_config().profile, RuntimeProfile.TEST)

    def test_unknown_profile_rejected(self):
        with patch.dict(os.environ, {"THREATSCOPE_PROFILE": "staging"}, clear=True):
            with self.assertRaises(ConfigurationError): get_runtime_config()

    def test_valid_production_is_exact_and_file_backed(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory))
            with patch.dict(os.environ, env, clear=True):
                config = get_runtime_config()
            self.assertTrue(config.production); self.assertEqual(config.worker_count, 1)
            self.assertTrue(all(item.source == "file" for item in config.secret_statuses if item.configured))
            self.assertNotIn(config.secrets["THREATSCOPE_SESSION_SECRET"], str(config.public_summary()))

    def _reject(self, **changes):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); env.update(changes)
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ConfigurationError): get_runtime_config()

    def test_rejects_debug_docs_reload_and_insecure_cookie(self):
        for key, value in (("THREATSCOPE_DEBUG", "true"), ("THREATSCOPE_API_DOCS", "true"), ("THREATSCOPE_RELOAD", "true"), ("THREATSCOPE_COOKIE_SECURE", "false")):
            with self.subTest(key=key): self._reject(**{key: value})

    def test_rejects_wildcards_and_http_origin(self):
        for key, value in (("THREATSCOPE_ALLOWED_HOSTS", "*"), ("THREATSCOPE_ALLOWED_ORIGINS", "*"), ("THREATSCOPE_ALLOWED_ORIGINS", "http://security.example.test")):
            with self.subTest(key=key, value=value): self._reject(**{key: value})

    def test_rejects_multiple_sqlite_workers_and_ephemeral_path(self):
        self._reject(THREATSCOPE_WORKERS="2")
        self._reject(DATABASE_URL="sqlite:///./temporary.db")

    def test_rejects_public_registration_without_acknowledgement(self):
        self._reject(THREATSCOPE_SELF_REGISTRATION_ENABLED="true", THREATSCOPE_REGISTRATION_MODE="approval_required")

    def test_rejects_demo_seed_and_environment_password_bootstrap(self):
        self._reject(THREATSCOPE_DEMO_MODE="true")
        self._reject(THREATSCOPE_BOOTSTRAP_ADMIN_USERNAME="owner", THREATSCOPE_BOOTSTRAP_ADMIN_PASSWORD="not-used")

    def test_rejects_unsafe_numeric_values_instead_of_clamping(self):
        self._reject(THREATSCOPE_MAX_REQUEST_BYTES="999999999")
        self._reject(THREATSCOPE_SESSION_HOURS="168")

    def test_development_preserves_direct_secret_compatibility(self):
        with patch.dict(os.environ, {"THREATSCOPE_PROFILE": "development", "THREATSCOPE_SESSION_SECRET": "development-only"}, clear=True):
            config = get_runtime_config()
        self.assertEqual(config.secrets["THREATSCOPE_SESSION_SECRET"], "development-only")

    def test_secret_conflict_empty_and_oversized_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_text("", encoding="utf-8")
            with patch.dict(os.environ, {"EXAMPLE_SECRET_FILE": str(path)}, clear=True):
                with self.assertRaises(SecretLoadError): load_secret("EXAMPLE_SECRET", production=True, required=True)
            path.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
            with patch.dict(os.environ, {"EXAMPLE_SECRET_FILE": str(path)}, clear=True):
                with self.assertRaises(SecretLoadError): load_secret("EXAMPLE_SECRET", production=True, required=True)
            path.write_text("file-value", encoding="utf-8")
            with patch.dict(os.environ, {"EXAMPLE_SECRET": "direct-value", "EXAMPLE_SECRET_FILE": str(path)}, clear=True):
                with self.assertRaises(SecretLoadError): load_secret("EXAMPLE_SECRET", production=True, required=True)

    def test_secret_trailing_newline_and_unicode_are_handled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"; path.write_text("synthetic-unicode-秘密\r\n", encoding="utf-8")
            with patch.dict(os.environ, {"EXAMPLE_SECRET_FILE": str(path.resolve())}, clear=True):
                value, status = load_secret("EXAMPLE_SECRET", production=True, required=True)
            self.assertEqual(value, "synthetic-unicode-秘密"); self.assertEqual(status.source, "file")

    def test_secret_directory_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"EXAMPLE_SECRET_FILE": str(root.resolve())}, clear=True):
                with self.assertRaises(SecretLoadError): load_secret("EXAMPLE_SECRET", production=True, required=True)
            source = root / "source"; source.write_text("synthetic", encoding="utf-8"); link = root / "link"
            try: link.symlink_to(source)
            except OSError: self.skipTest("Symbolic-link creation is unavailable")
            with patch.dict(os.environ, {"EXAMPLE_SECRET_FILE": str(link.resolve(strict=False))}, clear=True):
                # resolve(strict=False) dereferences on some platforms, so use the literal absolute link path.
                os.environ["EXAMPLE_SECRET_FILE"] = str(link.absolute())
                with self.assertRaises(SecretLoadError): load_secret("EXAMPLE_SECRET", production=True, required=True)
