import sqlite3
import re
import tempfile
import unittest
from pathlib import Path

from app.modules.production.config import RuntimeProfile
from app.modules.production.preflight import _sqlite_path


class ProductionHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]

    def test_production_compose_has_single_public_edge_and_internal_backend(self):
        compose = (self.root / "docker-compose.production.yml").read_text(encoding="utf-8")
        backend = compose.split("  backend:", 1)[1].split("  edge:", 1)[0]
        self.assertIsNone(re.search(r"^\s{4}ports:\s*$", backend, re.MULTILINE))
        self.assertIn("application:\n    internal: true", compose)
        self.assertNotIn("test-target", compose); self.assertNotIn("docker.sock", compose)

    def test_all_production_services_have_runtime_hardening(self):
        compose = (self.root / "docker-compose.production.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(compose.count("read_only: true"), 2)
        self.assertGreaterEqual(compose.count("cap_drop: [ALL]"), 2)
        self.assertGreaterEqual(compose.count("no-new-privileges:true"), 2)
        self.assertGreaterEqual(compose.count("pids_limit:"), 2)
        self.assertNotIn("privileged: true", compose)

    def test_secrets_are_file_mounts_not_literal_values(self):
        compose = (self.root / "docker-compose.production.yml").read_text(encoding="utf-8")
        self.assertIn("THREATSCOPE_SESSION_SECRET_FILE: /run/secrets/session_secret", compose)
        self.assertNotIn("THREATSCOPE_SESSION_SECRET:", compose)
        self.assertNotIn("THREATSCOPE_MFA_ENCRYPTION_KEY:", compose)

    def test_production_images_are_pinned_and_rootless(self):
        backend = (self.root / "backend" / "Dockerfile.production").read_text(encoding="utf-8")
        edge = (self.root / "deploy" / "nginx" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("python:3.11.9-slim-bookworm", backend); self.assertIn("USER 10001:10001", backend)
        self.assertIn("nginx:1.28.0-alpine3.21", edge); self.assertIn("USER 101:101", edge)
        self.assertNotIn(":latest", backend + edge)

    def test_nginx_enforces_tls_redirect_limits_and_safe_proxying(self):
        nginx = (self.root / "deploy" / "nginx" / "nginx.conf.template").read_text(encoding="utf-8")
        self.assertIn("return 308 https://$host$request_uri", nginx)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3", nginx)
        self.assertNotIn("TLSv1.1", nginx); self.assertNotIn("proxy_redirect on", nginx)
        self.assertIn("client_max_body_size 25m", nginx); self.assertIn("try_files $uri $uri/ /index.html", nginx)

    def test_frontend_runtime_contains_no_node_server(self):
        edge = (self.root / "deploy" / "nginx" / "Dockerfile").read_text(encoding="utf-8")
        runtime = edge.split("FROM nginx:", 1)[1]
        self.assertNotIn("npm run dev", runtime); self.assertNotIn("node_modules", runtime)

    def test_sqlite_absolute_path_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            target = (Path(directory) / "data.db").resolve()
            url = f"sqlite:////{target.as_posix().lstrip('/')}"
            parsed = _sqlite_path(url)
            self.assertIsNotNone(parsed)

    def test_sqlite_safety_pragmas_are_effective(self):
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys=ON"); connection.execute("PRAGMA busy_timeout=5000")
        self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertGreaterEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
        connection.close()

    def test_profiles_are_exact_enum_values(self):
        self.assertEqual({item.value for item in RuntimeProfile}, {"development", "test", "production"})
