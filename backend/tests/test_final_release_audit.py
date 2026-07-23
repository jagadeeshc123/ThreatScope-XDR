import json
import os
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
from app.modules.access_control.user_service import create_user
from app.version import SCHEMA_IDENTIFIER, version_info
from tests.access_helpers import authenticate_admin


REPOSITORY = Path(__file__).resolve().parents[2]


class FinalReleaseAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.factory = sessionmaker(bind=cls.engine)

        def override_db():
            db = cls.factory()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        app.dependency_overrides.clear()
        cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        self.admin = authenticate_admin(self.client, self.factory)

    def test_release_metadata_has_one_application_version_and_v19_schema(self):
        package = json.loads((REPOSITORY / "frontend" / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((REPOSITORY / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("THREATSCOPE_APP_VERSION", None)
            metadata = version_info()
        self.assertEqual((REPOSITORY / "VERSION").read_text(encoding="utf-8").strip(), "1.0.0")
        self.assertEqual(metadata["version"], "1.0.0")
        self.assertEqual(metadata["frontend_version"], "1.0.0")
        self.assertEqual(package["version"], "1.0.0")
        self.assertEqual(lock["version"], "1.0.0")
        self.assertEqual(lock["packages"][""]["version"], "1.0.0")
        self.assertEqual(SCHEMA_IDENTIFIER, "threatscope-schema-v19")

    def test_search_rejects_excessive_query_length(self):
        self.assertEqual(self.client.get("/api/search/", params={"q": "a" * 200}).status_code, 200)
        response = self.client.get("/api/search/", params={"q": "a" * 201})
        self.assertEqual(response.status_code, 422, response.text)

    def test_notifications_are_permission_and_recipient_bounded(self):
        with self.factory() as db:
            other = create_user(
                db,
                username="other.user",
                display_name="Other User",
                email="other-user@example.test",
                password="Correct-Horse-Battery-75!",
                role_keys=["registered_user"],
                must_change_password=False,
            )
            other_id = other.id
            db.add(models.Notification(title="Private", message="Other recipient", type="info", entity_type="scan", recipient_user_id=other_id))
            db.add(models.Notification(title="Visible", message="Administrator broadcast", type="info", entity_type="scan"))
            for index in range(120):
                db.add(models.Notification(title=f"Bounded {index}", message="Synthetic", type="info", entity_type="scan"))
            db.commit()

        response = self.client.get("/api/notifications/", params={"limit": 100})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()), 100)
        self.assertNotIn("Private", {item["title"] for item in response.json()})
        self.assertEqual(self.client.get("/api/notifications/", params={"limit": 101}).status_code, 422)
        self.assertEqual(self.client.get("/api/notifications/", params={"skip": -1}).status_code, 422)

        marked = self.client.patch("/api/notifications/mark-all-read")
        self.assertEqual(marked.status_code, 200, marked.text)
        with self.factory() as db:
            private = db.query(models.Notification).filter_by(title="Private").one()
            self.assertFalse(private.is_read)
            self.assertEqual(
                db.query(models.Notification).filter(models.Notification.recipient_user_id.is_(None), models.Notification.is_read.is_(False)).count(),
                0,
            )

    def test_frontend_has_safe_not_found_and_native_notification_controls(self):
        app_source = (REPOSITORY / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
        notification_source = (REPOSITORY / "frontend" / "src" / "pages" / "Notifications.tsx").read_text(encoding="utf-8")
        self.assertIn('<Route path="*" element={<NotFoundPage />} />', app_source)
        self.assertIn("Page not found", app_source)
        self.assertNotIn('role="button"', notification_source)
        self.assertIn("Open notification:", notification_source)
        self.assertIn("focus-visible:ring-2", notification_source)

    def test_release_document_index_and_permission_matrix_match_server_definitions(self):
        required = (
            "USER_GUIDE.md", "ADMINISTRATOR_GUIDE.md", "DEVELOPER_GUIDE.md", "DEMO_GUIDE.md",
            "MODULE_CAPABILITY_MATRIX.md", "PERMISSIONS_MATRIX.md", "CSRF_MUTATION_INVENTORY.md",
            "THREAT_MODEL.md", "DATA_HANDLING.md", "API_REFERENCE.md", "KNOWN_LIMITATIONS.md",
            "RELEASE_NOTES_V1.0.0.md", "V1_RELEASE_CHECKLIST.md", "FINAL_AUDIT_REPORT.md",
        )
        readme = (REPOSITORY / "README.md").read_text(encoding="utf-8")
        for name in required:
            self.assertTrue((REPOSITORY / "docs" / name).is_file(), name)
            self.assertIn(f"docs/{name}", readme, name)
        self.assertTrue((REPOSITORY / "SECURITY.md").is_file())
        self.assertTrue((REPOSITORY / "CONTRIBUTING.md").is_file())

        definitions = json.loads((REPOSITORY / "backend" / "app" / "modules" / "access_control" / "rules" / "permissions.json").read_text(encoding="utf-8"))
        matrix = (REPOSITORY / "docs" / "PERMISSIONS_MATRIX.md").read_text(encoding="utf-8")
        for identifier, _description, _category in definitions:
            self.assertEqual(matrix.count(f"| `{identifier}` |"), 1, identifier)
        self.assertIn(f"Permission count: {len(definitions)}.", matrix)

    def test_mutation_inventory_has_no_unclassified_authenticated_route(self):
        from scripts.generate_mutation_inventory import render

        inventory = render()
        self.assertIn("Total mutation routes: 355.", inventory)
        self.assertIn("Intentional non-session exceptions: 4. Unclassified: 0.", inventory)
        self.assertNotIn("UNCLASSIFIED", inventory)
        self.assertEqual(inventory.count("Pre-authentication login"), 1)
        self.assertEqual(inventory.count("No browser session"), 1)


if __name__ == "__main__":
    unittest.main()
