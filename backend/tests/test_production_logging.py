import json
import logging
import unittest

from app.modules.production.logging import ProductionJsonFormatter, redact


class ProductionLoggingTests(unittest.TestCase):
    def test_nested_sensitive_keys_are_redacted_case_insensitively(self):
        value = redact({"Authorization": "synthetic-bearer", "nested": [{"csrf_token": "synthetic-csrf"}], "safe": "visible"})
        self.assertEqual(value["Authorization"], "[REDACTED]"); self.assertEqual(value["nested"][0]["csrf_token"], "[REDACTED]"); self.assertEqual(value["safe"], "visible")

    def test_assignments_and_credential_url_are_redacted(self):
        value = redact("https://user:password@example.test/path?token=synthetic")
        self.assertNotIn("password", value); self.assertNotIn("synthetic", value); self.assertNotIn("user@", value)

    def test_redaction_is_depth_and_collection_bounded(self):
        value = {}; cursor = value
        for index in range(12): cursor["safe"] = {}; cursor = cursor["safe"]
        self.assertIn("[BOUNDED]", json.dumps(redact(value)))
        self.assertEqual(len(redact(list(range(200)))), 100)

    def test_json_formatter_emits_safe_operational_fields(self):
        record = logging.LogRecord("threatscope", logging.INFO, __file__, 1, "password=synthetic-value", (), None)
        record.event_name = "http_request"; record.request_id = "safe-request-id"; record.route_template = "/api/auth/login"; record.method = "POST"; record.status_code = 401; record.safe_metadata = {"cookie": "synthetic-cookie"}
        payload = json.loads(ProductionJsonFormatter().format(record))
        self.assertEqual(payload["request_id"], "safe-request-id"); self.assertEqual(payload["status"], 401)
        encoded = json.dumps(payload); self.assertNotIn("synthetic-value", encoded); self.assertNotIn("synthetic-cookie", encoded)

    def test_request_identifier_contract_is_bounded(self):
        from app.modules.access_control.audit_middleware import REQUEST_ID_RE
        self.assertTrue(REQUEST_ID_RE.fullmatch("request-12345678")); self.assertFalse(REQUEST_ID_RE.fullmatch("bad\nrequest")); self.assertFalse(REQUEST_ID_RE.fullmatch("x" * 65))

    def test_proxy_access_log_uses_normalized_path_without_query(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        nginx = (root / "deploy" / "nginx" / "nginx.conf.template").read_text(encoding="utf-8")
        self.assertIn('"path":"$uri"', nginx); self.assertNotIn("$request_uri\",\"status", nginx)
