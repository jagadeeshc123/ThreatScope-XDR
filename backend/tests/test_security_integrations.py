import base64
import os
import time
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models as _registered_models  # noqa: F401
from app.database import Base
from app.modules.integrations.catalog import CONNECTOR_CATALOG
from app.modules.integrations.mapping import apply_mapping, validate_mapping
from app.modules.integrations.models import ConnectorInstance
from app.modules.integrations.security import IntegrationSecurityError, decrypt_secret, encrypt_secret, redact, sign_hmac, validate_destination, verify_hmac
from app.modules.integrations import service


PUBLIC = [(None, None, None, None, ("93.184.216.34", 443))]
PRIVATE = [(None, None, None, None, ("127.0.0.1", 443))]


class IntegrationSecurityTests(unittest.TestCase):
    def setUp(self):
        engine=create_engine("sqlite:///:memory:");Base.metadata.create_all(engine);self.db=sessionmaker(bind=engine)()

    def tearDown(self):self.db.close()

    def test_catalog_is_complete_immutable_and_safe(self):
        expected={"local_test_sink","generic_hmac_webhook_outbound","generic_hmac_webhook_inbound","slack_incoming_webhook","microsoft_teams_webhook","smtp_email","jira_issue","servicenow_incident","splunk_hec","stix_bundle_import","taxii_21_collection_pull"}
        self.assertEqual(expected,set(CONNECTOR_CATALOG));self.assertTrue(all(not x.enabled_by_default for x in CONNECTOR_CATALOG.values()));self.assertFalse(any("contain" in k for k in CONNECTOR_CATALOG))
        with self.assertRaises(Exception):CONNECTOR_CATALOG["local_test_sink"].display_name="changed"

    def test_local_sink_is_internal(self):
        item=CONNECTOR_CATALOG["local_test_sink"];self.assertFalse(item.public_https_required);self.assertFalse(item.private_network_supported);self.assertIn("TEST SINK",item.display_name)

    def test_mapping_transforms(self):
        rules=[{"target":"upper","source":"name","transform":"uppercase"},{"target":"short","source":"name","transform":"truncate","length":3},{"target":"level","source":"severity","transform":"severity_map","map":{"high":"P1"}}]
        self.assertEqual({"upper":"ALERT","short":"Ale","level":"P1"},apply_mapping({"name":"Alert","severity":"high"},rules))

    def test_mapping_rejects_expressions_and_dunder(self):
        self.assertFalse(validate_mapping([{"target":"x","source":"__class__","transform":"direct"}])["valid"])
        self.assertFalse(validate_mapping([{"target":"x","transform":"python"}])["valid"])

    def test_hmac_signature_and_constant_time_path(self):
        body=b'{"event_type":"soc.alert.created"}';stamp=str(int(time.time()));signature=sign_hmac("a"*32,stamp,body)
        self.assertTrue(verify_hmac("a"*32,stamp,body,signature));self.assertFalse(verify_hmac("b"*32,stamp,body,signature))

    def test_redaction(self):
        value=redact({"token":"usable-secret","nested":{"password":"pw"},"title":"safe"});self.assertEqual("[REDACTED]",value["token"]);self.assertNotIn("usable-secret",str(value))

    def test_credential_encrypted_and_wrong_key_fails_closed(self):
        key=base64.urlsafe_b64encode(b"1"*32).decode();wrong=base64.urlsafe_b64encode(b"2"*32).decode()
        with patch.dict(os.environ,{"THREATSCOPE_CONNECTOR_SECRETS_KEY":key}):cipher=encrypt_secret({"signing_secret":"super-secret-value"});self.assertNotIn("super-secret-value",cipher);self.assertEqual("super-secret-value",decrypt_secret(cipher)["signing_secret"])
        with patch.dict(os.environ,{"THREATSCOPE_CONNECTOR_SECRETS_KEY":wrong}):
            with self.assertRaises(IntegrationSecurityError):decrypt_secret(cipher)

    def test_missing_key_fails_closed(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(IntegrationSecurityError):encrypt_secret({"token":"x"})

    def test_public_destination_allowed_with_mocked_dns(self):
        result=validate_destination("https://example.test/hook",{"allowed_hosts":["example.test"],"allowed_ports":[443],"network_scope":"public_https"},resolver=lambda *a,**k:PUBLIC);self.assertEqual("example.test",result.hostname)

    def test_loopback_dns_answer_blocked(self):
        with self.assertRaises(IntegrationSecurityError):validate_destination("https://example.test",{"allowed_hosts":["example.test"],"allowed_ports":[443],"network_scope":"public_https"},resolver=lambda *a,**k:PRIVATE)

    def test_blocked_url_forms(self):
        policy={"allowed_hosts":["localhost","127.0.0.1"],"allowed_ports":[443],"network_scope":"public_https"}
        for url in ("http://example.test","https://localhost.","https://127.0.0.1","https://user:pass@example.test","https://example.test/#fragment","file:///tmp/x"):
            with self.subTest(url=url):
                with self.assertRaises(IntegrationSecurityError):validate_destination(url,policy,resolver=lambda *a,**k:PUBLIC)

    def test_private_requires_exact_approval(self):
        policy={"allowed_hosts":["private.example"],"allowed_ports":[443],"allowed_cidrs":["10.0.0.0/24"],"network_scope":"approved_private"};private=[(None,None,None,None,("10.0.0.8",443))]
        self.assertEqual("10.0.0.8",validate_destination("https://private.example",policy,resolver=lambda *a,**k:private).addresses[0])

    def test_canonical_event_is_redacted_and_idempotent(self):
        event=service.canonical_event("soc.alert.created","soc","alert",1,"Title","Summary",{"password":"nope","safe":"yes"},severity="high",event_id="11111111-1111-1111-1111-111111111111")
        self.assertEqual("[REDACTED]",event["redacted_payload"]["password"]);self.assertEqual(64,len(event["content_sha256"]));self.assertEqual(64,len(event["idempotency_key"]))

    def test_report_has_44_safe_sections(self):
        item=service.generate_report(self.db,"Integration report","integration_summary",{},1);self.assertEqual(44,len(service.REPORT_SECTIONS));self.assertNotIn("<script",item.html_content.casefold());self.assertNotIn("http://",item.html_content.casefold());self.assertIn("No-containment disclaimer",item.html_content)

    def test_connector_defaults_closed(self):
        item=ConnectorInstance(connector_uuid="11111111-1111-1111-1111-111111111111",connector_type="local_test_sink",name="TEST SINK",normalized_name="test sink",direction="outbound",configuration_json="{}",configuration_sha256="0"*64,created_by_user_id=1)
        self.db.add(item);self.db.flush()
        self.assertFalse(item.enabled);self.assertEqual("draft",item.lifecycle_status);self.assertEqual("closed",item.circuit_state)


if __name__=="__main__":unittest.main()
