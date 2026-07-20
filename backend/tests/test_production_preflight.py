import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.modules.production.config import get_runtime_config
from app.modules.production.preflight import run_preflight
from tests.test_production_configuration import production_environment


class ProductionPreflightTests(unittest.TestCase):
    def test_valid_configuration_creates_only_runtime_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory))
            with patch.dict(os.environ, env, clear=True): result = run_preflight(create_directories=True)
            self.assertTrue(result["ready"], result)
            self.assertEqual(result["failure_count"], 0)
            self.assertTrue((Path(directory) / "data").is_dir())

    def test_safe_json_shape_contains_no_secret_value_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); secret = Path(env["THREATSCOPE_SESSION_SECRET_FILE"]).read_text()
            with patch.dict(os.environ, env, clear=True): result = run_preflight(create_directories=True)
            serialized = __import__("json").dumps(result)
            self.assertNotIn(secret, serialized); self.assertNotIn(str(Path(directory).resolve()), serialized)

    def test_missing_secret_fails_without_revealing_value(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); env.pop("THREATSCOPE_SESSION_SECRET_FILE")
            with patch.dict(os.environ, env, clear=True): result = run_preflight()
            self.assertFalse(result["ready"]); self.assertIn("configuration", result["checks"][0]["name"])

    def test_corrupt_existing_database_fails_quick_check(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); data = Path(directory) / "data"; data.mkdir(); (data / "vulnscope.db").write_bytes(b"not-a-sqlite-database")
            with patch.dict(os.environ, env, clear=True): result = run_preflight(create_directories=True)
            self.assertFalse(result["ready"]); self.assertTrue(any(item["name"] == "database" and item["state"] == "failure" for item in result["checks"]))

    def test_unsupported_newer_schema_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); data = Path(directory) / "data"; data.mkdir(); database = data / "vulnscope.db"
            connection = sqlite3.connect(database); connection.execute("CREATE TABLE production_runtime_metadata (key TEXT, value TEXT)"); connection.execute("INSERT INTO production_runtime_metadata VALUES ('schema_identifier','threatscope-schema-v99')"); connection.commit(); connection.close()
            with patch.dict(os.environ, env, clear=True): result = run_preflight(create_directories=True)
            self.assertFalse(result["ready"]); self.assertTrue(any(item["name"] == "schema" for item in result["checks"]))

    def test_missing_tls_material_fails_configuration_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory)); Path(env["THREATSCOPE_TLS_PRIVATE_KEY_FILE"]).unlink()
            with patch.dict(os.environ, env, clear=True): result = run_preflight(create_directories=True)
            self.assertTrue(any(item["name"] == "tls_material" and item["state"] == "failure" for item in result["checks"]))

    def test_nonproduction_profile_is_rejected_by_preflight(self):
        with patch.dict(os.environ, {"THREATSCOPE_PROFILE": "test"}, clear=True): result = run_preflight()
        self.assertFalse(result["ready"]); self.assertEqual(result["checks"][0]["name"], "profile")

    def test_connector_egress_default_is_explicit_and_nonblocking(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory))
            with patch.dict(os.environ, env, clear=True): config = get_runtime_config(); result = run_preflight(config=config, create_directories=True)
            self.assertFalse(config.connector_egress_enabled)
            self.assertTrue(any(item["name"] == "connector_egress" and item["state"] == "pass" for item in result["checks"]))

    def test_preflight_makes_no_network_or_command_call(self):
        with tempfile.TemporaryDirectory() as directory:
            env = production_environment(Path(directory))
            env["THREATSCOPE_LOCAL_PRODUCTION_SMOKE"] = "true"
            failure = AssertionError("external operation attempted")
            with patch.dict(os.environ, env, clear=True), patch("socket.create_connection", side_effect=failure), patch("socket.getaddrinfo", side_effect=failure), patch("urllib.request.urlopen", side_effect=failure), patch("subprocess.Popen", side_effect=failure), patch("os.system", side_effect=failure), patch("os.popen", side_effect=failure):
                result = run_preflight(create_directories=True)
            self.assertTrue(result["ready"], result)
