import unittest

from app.modules.production.config import RuntimeConfig, RuntimeProfile
from app.modules.production.headers import PRODUCTION_CSP, response_security_headers


class ProductionSecurityHeaderTests(unittest.TestCase):
    def _config(self):
        values = {field: None for field in RuntimeConfig.__dataclass_fields__}
        values.update(profile=RuntimeProfile.PRODUCTION, production=True if False else None)
        values.pop("production", None)
        values.update(
            debug=False, reload=False, allowed_hosts=("security.example",), allowed_origins=("https://security.example",), trusted_proxy_networks=("172.20.0.0/16",),
            cookie_secure=True, cookie_samesite="lax", session_hours=8, idle_minutes=30, csrf_enabled=True, database_url="sqlite:////data/db.sqlite",
            log_level="INFO", json_logging=True, max_request_bytes=1_000_000, max_upload_bytes=2_000_000, request_timeout_seconds=30, graceful_shutdown_seconds=30,
            worker_count=1, public_registration=False, registration_acknowledged=False, demo_seed=False, api_docs=False, connector_egress_enabled=False,
            tls_proxy_expected=True, schema_identifier="threatscope-schema-v19", application_version="1.0.0-rc2", source_revision="abc", build_timestamp="now",
            frontend_build_id="front", backend_build_id="back", minimum_free_bytes=1, tls_certificate_file="/tls.crt", tls_private_key_file="/tls.key", secrets={}, secret_statuses=(),
        )
        from pathlib import Path
        for name in ("data_dir", "upload_dir", "backup_dir", "report_dir", "runtime_dir", "export_dir", "release_dir"): values[name] = Path("/runtime")
        return RuntimeConfig(**values)

    def test_https_matrix_contains_required_headers(self):
        headers = response_security_headers(self._config(), https=True, path="/")
        required = {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-Frame-Options", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"}
        self.assertTrue(required.issubset(headers))

    def test_hsts_is_https_only(self):
        self.assertNotIn("Strict-Transport-Security", response_security_headers(self._config(), https=False, path="/"))

    def test_csp_forbids_eval_objects_and_framing(self):
        self.assertNotIn("unsafe-eval", PRODUCTION_CSP)
        self.assertIn("object-src 'none'", PRODUCTION_CSP)
        self.assertIn("frame-ancestors 'none'", PRODUCTION_CSP)
        self.assertIn("base-uri 'self'", PRODUCTION_CSP)

    def test_sensitive_routes_are_not_cached(self):
        for path in ("/api/auth/login", "/api/operations/production/readiness", "/api/reports/1"):
            with self.subTest(path=path): self.assertEqual(response_security_headers(self._config(), https=True, path=path)["Cache-Control"], "no-store")

    def test_nginx_header_fragment_matches_application_policy(self):
        root = __import__("pathlib").Path(__file__).resolve().parents[2]
        fragment = (root / "deploy" / "nginx" / "security-headers.conf").read_text(encoding="utf-8")
        self.assertIn("object-src 'none'", fragment); self.assertNotIn("unsafe-eval", fragment)
        self.assertIn("Cross-Origin-Opener-Policy", fragment)
