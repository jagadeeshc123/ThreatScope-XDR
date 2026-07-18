import base64
import importlib.util
import json
import os
import tempfile
import time
import unittest
import smtplib
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models as root_models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.audit_service import verify_integrity
from app.modules.access_control.dependencies import _integration_operation
from app.modules.access_control.models import SecurityAuditEvent, UserAccount
from app.modules.access_control.role_service import seed_roles_and_permissions
from app.modules.access_control.user_service import create_user
from app.modules.integrations import adapters, rate_limit, service
from app.modules.integrations.models import *
from app.modules.integrations.security import IntegrationSecurityError, sign_hmac, verify_hmac
from app.modules.soar.catalog import ACTION_CATALOG
from app.modules.soar.models import SoarExecution, SoarExecutionEvent, SoarPlaybook, SoarStepExecution
from app.modules.soar.service import _dispatch
from tests.access_helpers import authenticate_admin


PUBLIC=[(None,None,None,None,("93.184.216.34",443))]


class RemediationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool);cls.factory=sessionmaker(bind=cls.engine)
        def override():
            with cls.factory() as db:yield db
        app.dependency_overrides[get_db]=override;cls.client=TestClient(app)

    @classmethod
    def tearDownClass(cls):cls.client.close();app.dependency_overrides.clear();cls.engine.dispose()

    def setUp(self):
        os.environ["THREATSCOPE_CONNECTOR_SECRETS_KEY"]=base64.urlsafe_b64encode(b"r"*32).decode();os.environ["THREATSCOPE_SESSION_SECRET"]="integration-remediation-test-session-pepper"
        Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine);self.admin=authenticate_admin(self.client,self.factory)

    def connector(self,db,kind="local_test_sink",name="TEST SINK",config=None,active=False):
        item=service.create_connector(db,{"connector_type":kind,"name":name,"configuration":config or {}},self.admin["id"])
        if active:item.lifecycle_status="active";item.enabled=True;item.health_status="healthy";item.last_test_status="passed";db.commit()
        return item

    def test_rate_limit_endpoint_boundary_retry_after_and_window_reset(self):
        with self.factory() as db:
            source=rate_limit.source_key("203.0.113.7")
            self.assertEqual(1,rate_limit.consume(db,"endpoint",1,source,now=100,limit=2,window=10));self.assertEqual(0,rate_limit.consume(db,"endpoint",1,source,now=101,limit=2,window=10))
            with self.assertRaises(rate_limit.RateLimitExceeded) as caught:rate_limit.consume(db,"endpoint",1,source,now=102,limit=2,window=10)
            self.assertLessEqual(caught.exception.retry_after,10);self.assertEqual(1,rate_limit.consume(db,"endpoint",1,source,now=110,limit=2,window=10))

    def test_rate_limit_source_endpoint_and_global_isolation(self):
        limits={"global":(3,60),"endpoint":(2,60),"source":(1,60)}
        with self.factory() as db:
            rate_limit.enforce_request(db,1,"203.0.113.1",now=1,limits=limits)
            with self.assertRaises(rate_limit.RateLimitExceeded):rate_limit.enforce_request(db,1,"203.0.113.1",now=2,limits=limits)
            rate_limit.enforce_request(db,2,"203.0.113.2",now=2,limits=limits)
            scopes={x.scope for x in db.query(ConnectorInboundRateCounter)};self.assertEqual({"global","endpoint","source"},scopes)

    def test_invalid_signature_and_replay_have_persistent_private_counters(self):
        with self.factory() as db:
            hashed=rate_limit.source_key("198.51.100.44");self.assertNotIn("198.51",hashed)
            rate_limit.record_failure(db,4,hashed,"signature",now=1,limits={"signature":(1,60)})
            with self.assertRaises(rate_limit.RateLimitExceeded):rate_limit.record_failure(db,4,hashed,"signature",now=2,limits={"signature":(1,60)})
            rate_limit.record_failure(db,4,hashed,"replay",now=1,limits={"replay":(2,60)})
            self.assertFalse(any("198.51" in x.key_hash for x in db.query(ConnectorInboundRateCounter)))

    def test_live_local_inbound_hmac_replay_and_429_create_no_extra_domain_rows(self):
        body=b'{"event_type":"soc.alert.created","severity":"high","title":"safe"}';stamp=str(int(time.time()))
        with self.factory() as db:
            connector=self.connector(db,"generic_hmac_webhook_inbound","Inbound",{});service.set_credential(db,connector,"hmac_signing",{"signing_secret":"z"*32},self.admin["id"])
            endpoint=ConnectorInboundEndpoint(endpoint_uuid="11111111-1111-4111-8111-111111111111",connector_id=connector.id,name="Inbound",allowed_event_types_json='["soc.alert.created"]',created_by_user_id=self.admin["id"]);db.add(endpoint);db.commit()
        headers={"Content-Type":"application/json","X-ThreatScope-Timestamp":stamp,"X-ThreatScope-Event-ID":"evt-1","X-ThreatScope-Schema-Version":"1.0","X-ThreatScope-Signature":sign_hmac("z"*32,stamp,body)}
        with patch.dict(rate_limit.DEFAULT_LIMITS,{"global":(20,60),"endpoint":(20,60),"source":(20,60),"replay":(1,60)}):
            accepted=self.client.post("/api/integrations/inbound/11111111-1111-4111-8111-111111111111",content=body,headers=headers);self.assertEqual(202,accepted.status_code,accepted.text)
            rejected=self.client.post("/api/integrations/inbound/11111111-1111-4111-8111-111111111111",content=body,headers=headers);self.assertEqual(401,rejected.status_code)
            limited=self.client.post("/api/integrations/inbound/11111111-1111-4111-8111-111111111111",content=body,headers=headers);self.assertEqual(429,limited.status_code);self.assertLessEqual(int(limited.headers["Retry-After"]),300)
        with self.factory() as db:self.assertEqual(1,db.query(ConnectorInboundEvent).count());self.assertEqual(1,db.query(ConnectorReplayNonce).count())
        with self.factory() as db:
            threshold=db.query(SecurityAuditEvent).filter_by(action="replay_detection_threshold").one();self.assertEqual("1",threshold.resource_id);self.assertNotIn("z"*16,threshold.metadata_json);self.assertTrue(verify_integrity(db)["valid_chain"])

    def test_inbound_rejections_are_generic_bounded_and_create_no_domain_records(self):
        secret="q"*32;valid_body=b'{"event_type":"soc.alert.created","title":"safe"}'
        with self.factory() as db:
            connector=self.connector(db,"generic_hmac_webhook_inbound","Rejecting inbound",{});service.set_credential(db,connector,"hmac_signing",{"signing_secret":secret},self.admin["id"]);endpoint=ConnectorInboundEndpoint(endpoint_uuid="33333333-3333-4333-8333-333333333333",connector_id=connector.id,name="Rejecting",maximum_body_bytes=1024,allowed_event_types_json='["soc.alert.created"]',created_by_user_id=self.admin["id"]);db.add(endpoint);db.commit();endpoint_id=endpoint.id
        def signed(body,event_id,stamp=None,content_type="application/json",schema="1.0"):
            stamp=stamp or str(int(time.time()));return {"Content-Type":content_type,"X-ThreatScope-Timestamp":stamp,"X-ThreatScope-Event-ID":event_id,"X-ThreatScope-Schema-Version":schema,"X-ThreatScope-Signature":sign_hmac(secret,stamp,body)}
        now=int(time.time());oversized=b'{"padding":"'+b"x"*1100+b'"}'
        cases=[
            (valid_body,{"Content-Type":"application/json"}),
            (valid_body,{**signed(valid_body,"invalid-signature"),"X-ThreatScope-Signature":"sha256="+"0"*64}),
            (valid_body,signed(valid_body,"expired",str(now-1000))),
            (valid_body,signed(valid_body,"future",str(now+1000))),
            (valid_body,signed(valid_body,"wrong-content",content_type="text/plain")),
            (b"{invalid",signed(b"{invalid","invalid-json")),
            (valid_body,signed(valid_body,"schema","",schema="2.0")),
            (b'{"event_type":"unsupported.event"}',signed(b'{"event_type":"unsupported.event"}',"unsupported")),
            (oversized,signed(oversized,"oversized")),
        ]
        with patch.dict(rate_limit.DEFAULT_LIMITS,{"global":(100,60),"endpoint":(100,60),"source":(100,60),"invalid":(100,300),"signature":(100,300),"replay":(100,300)}):
            for body,headers in cases:
                response=self.client.post("/api/integrations/inbound/33333333-3333-4333-8333-333333333333",content=body,headers=headers);self.assertEqual(401,response.status_code,response.text);self.assertEqual("Inbound authentication failed",response.json()["detail"])
            with self.factory() as db:endpoint=db.get(ConnectorInboundEndpoint,endpoint_id);endpoint.enabled=False;db.commit()
            disabled=self.client.post("/api/integrations/inbound/33333333-3333-4333-8333-333333333333",content=valid_body,headers=signed(valid_body,"disabled"));self.assertEqual(401,disabled.status_code);self.assertEqual("Inbound authentication failed",disabled.json()["detail"])
        with self.factory() as db:self.assertEqual(0,db.query(ConnectorInboundEvent).count());self.assertEqual(0,db.query(ConnectorReplayNonce).count());self.assertFalse(any("203.0.113" in row.key_hash for row in db.query(ConnectorInboundRateCounter)))

    def test_rate_counter_cleanup(self):
        with self.factory() as db:
            rate_limit.consume(db,"global",None,"x",now=1,limit=2,window=2);self.assertEqual(1,rate_limit.cleanup(db,now=datetime.utcnow()+timedelta(days=1)));self.assertEqual(0,db.query(ConnectorInboundRateCounter).count())

    def test_rate_counter_is_atomic_across_concurrent_sqlite_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            engine=create_engine(f"sqlite:///{os.path.join(directory,'rate.db')}",connect_args={"check_same_thread":False,"timeout":10})
            ConnectorInboundRateCounter.__table__.create(engine);factory=sessionmaker(bind=engine);barrier=Barrier(4)
            def attempt(_):
                with factory() as db:
                    barrier.wait()
                    try:rate_limit.consume(db,"endpoint",7,"private-source",now=100,limit=3,window=60);return "allowed"
                    except rate_limit.RateLimitExceeded:return "limited"
            with ThreadPoolExecutor(max_workers=4) as workers:results=list(workers.map(attempt,range(4)))
            self.assertEqual(3,results.count("allowed"));self.assertEqual(1,results.count("limited"))
            with factory() as db:self.assertEqual(3,db.query(ConnectorInboundRateCounter).one().request_count)
            engine.dispose()

    def test_authenticated_lifecycle_csrf_audit_and_database_state(self):
        response=self.client.post("/api/integrations/connectors",json={"connector_type":"local_test_sink","name":"API TEST SINK","configuration":{}});self.assertEqual(201,response.status_code,response.text);item=response.json()
        self.assertEqual(409,self.client.post(f"/api/integrations/connectors/{item['id']}/activate",json={"optimistic_lock_version":item["optimistic_lock_version"]}).status_code)
        missing=self.client.headers.pop("X-CSRF-Token");self.assertEqual(403,self.client.post("/api/integrations/connectors",json={"connector_type":"local_test_sink","name":"NO CSRF","configuration":{}}).status_code);self.client.headers["X-CSRF-Token"]=missing
        self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{item['id']}/move-to-testing",json={"optimistic_lock_version":item["optimistic_lock_version"]}).status_code)
        self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{item['id']}/test").status_code)
        current=self.client.get(f"/api/integrations/connectors/{item['id']}").json();activated=self.client.post(f"/api/integrations/connectors/{item['id']}/activate",json={"optimistic_lock_version":current["optimistic_lock_version"]});self.assertEqual(200,activated.status_code,activated.text)
        queued=self.client.post("/api/integrations/deliveries",json={"connector_id":item["id"],"event_type":"soc.alert.created","external_operation":"notify","payload":{"title":"safe"},"idempotency_key":"lifecycle-delivery"});self.assertEqual(201,queued.status_code);self.assertEqual(1,self.client.post("/api/integrations/process-due",json={"batch_size":10}).json()["deliveries_processed"])
        current=self.client.get(f"/api/integrations/connectors/{item['id']}").json();disabled=self.client.post(f"/api/integrations/connectors/{item['id']}/disable",json={"optimistic_lock_version":current["optimistic_lock_version"]});self.assertEqual(200,disabled.status_code);self.assertEqual(409,self.client.post("/api/integrations/deliveries",json={"connector_id":item["id"],"event_type":"soc.alert.created","external_operation":"notify","payload":{"title":"blocked"},"idempotency_key":"disabled-delivery"}).status_code)
        current=disabled.json();self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{item['id']}/move-to-testing",json={"optimistic_lock_version":current["optimistic_lock_version"]}).status_code);self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{item['id']}/test").status_code);current=self.client.get(f"/api/integrations/connectors/{item['id']}").json();self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{item['id']}/activate",json={"optimistic_lock_version":current["optimistic_lock_version"]}).status_code)
        current=self.client.get(f"/api/integrations/connectors/{item['id']}").json();self.assertEqual(409,self.client.patch(f"/api/integrations/connectors/{item['id']}",json={"optimistic_lock_version":current["optimistic_lock_version"]-1,"description":"stale"}).status_code);disabled=self.client.post(f"/api/integrations/connectors/{item['id']}/disable",json={"optimistic_lock_version":current["optimistic_lock_version"]});self.assertEqual(200,disabled.status_code);archived=self.client.post(f"/api/integrations/connectors/{item['id']}/archive",json={"optimistic_lock_version":disabled.json()["optimistic_lock_version"]});self.assertEqual(200,archived.status_code)
        self.assertEqual(409,self.client.post("/api/integrations/deliveries",json={"connector_id":item["id"],"event_type":"soc.alert.created","external_operation":"notify","payload":{"title":"blocked"},"idempotency_key":"archived-delivery"}).status_code)
        with self.factory() as db:
            stored=db.get(ConnectorInstance,item["id"]);self.assertFalse(stored.enabled);self.assertEqual("archived",stored.lifecycle_status);self.assertEqual("succeeded",db.query(ConnectorDelivery).filter_by(idempotency_key="lifecycle-delivery").one().status)
            actions={x.action for x in db.query(SecurityAuditEvent).filter_by(event_type="integration_operation")};self.assertTrue({"connector_create","connector_move_to_testing","connector_test","connector_activate","connector_disable","connector_archive","delivery_queue","delivery_process_due"}.issubset(actions));self.assertTrue(verify_integrity(db)["valid_chain"])

    def test_operation_audit_mapping_covers_each_mutation_family(self):
        matrix={
            ("POST","/api/integrations/connectors"):"connector_create",
            ("PATCH","/api/integrations/connectors/9"):"connector_update",
            ("POST","/api/integrations/connectors/9/validate"):"configuration_validate",
            ("PUT","/api/integrations/connectors/9/credentials"):"credential_replace",
            ("DELETE","/api/integrations/connectors/9/credentials"):"credential_remove",
            ("PATCH","/api/integrations/connectors/9/network-policy"):"network_policy_update",
            ("DELETE","/api/integrations/subscriptions/8"):"subscription_delete",
            ("POST","/api/integrations/mappings/7/validate"):"mapping_validate",
            ("POST","/api/integrations/deliveries"):"delivery_queue",
            ("POST","/api/integrations/dead-letters/6/replay"):"dead_letter_replay",
            ("POST","/api/integrations/inbound-endpoints/5/disable"):"inbound_endpoint_disable",
            ("POST","/api/integrations/inbound-events/4/promote"):"inbound_promote",
            ("POST","/api/integrations/stix/import/preview"):"stix_preview",
            ("POST","/api/integrations/connectors/3/taxii/pull"):"taxii_pull",
            ("GET","/api/integrations/reports/2/download"):"report_export",
            ("POST","/api/integrations/process-due"):"delivery_process_due",
        }
        for request,expected in matrix.items():self.assertEqual(expected,_integration_operation(*request)[0],request)

    def test_anonymous_and_registered_user_denied(self):
        self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None);self.assertEqual(401,self.client.get("/api/integrations/connectors").status_code)
        with self.factory() as db:create_user(db,username="registered.integration",display_name="Registered",password="Strong-Registered-Value-82!",role_keys=["registered_user"],must_change_password=False)
        self.assertEqual(200,self.client.post("/api/auth/login",json={"username":"registered.integration","password":"Strong-Registered-Value-82!"}).status_code);self.assertEqual(403,self.client.get("/api/integrations/connectors").status_code)

    def test_authenticated_role_matrix_enforces_aggregate_and_mutation_boundaries(self):
        password="Role-Matrix-Test-Value-73!"
        with self.factory() as db:
            connector=self.connector(db,active=True);report=service.generate_report(db,"Role matrix report","integration_summary",{},self.admin["id"])
            for username,role in (("analyst.integration","security_analyst"),("auditor.integration","auditor"),("executive.integration","executive_viewer")):create_user(db,username=username,display_name=role,password=password,role_keys=[role],must_change_password=False)
            connector_id,report_id=connector.id,report.id
        def login(username):
            self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None);self.assertEqual(200,self.client.post("/api/auth/login",json={"username":username,"password":password}).status_code);csrf=self.client.get("/api/auth/csrf");self.assertEqual(200,csrf.status_code);self.client.headers["X-CSRF-Token"]=csrf.json()["csrf_token"]
        login("analyst.integration");self.assertEqual(200,self.client.get("/api/integrations/connectors").status_code);self.assertEqual(200,self.client.post(f"/api/integrations/connectors/{connector_id}/test").status_code);self.assertEqual(403,self.client.put(f"/api/integrations/connectors/{connector_id}/credentials",json={"credential_type":"hmac_signing","secret":{"signing_secret":"never-processed"},"confirmation":"STORE WRITE ONLY"}).status_code);self.assertEqual(403,self.client.patch(f"/api/integrations/connectors/{connector_id}/network-policy",json={}).status_code)
        login("auditor.integration");self.assertEqual(200,self.client.get("/api/integrations/connectors").status_code);self.assertEqual(403,self.client.post("/api/integrations/connectors",json={"connector_type":"local_test_sink","name":"forbidden","configuration":{}}).status_code);self.assertEqual(200,self.client.get(f"/api/integrations/reports/{report_id}/download").status_code)
        login("executive.integration");overview=self.client.get("/api/integrations/overview");self.assertEqual(200,overview.status_code);self.assertNotIn("connector_types",overview.json());self.assertEqual(403,self.client.get("/api/integrations/connectors").status_code);dashboard=self.client.get("/api/dashboard/summary");self.assertEqual(200,dashboard.status_code);self.assertIsNotNone(dashboard.json()["integrations"]);self.assertNotIn("connector_types",dashboard.json()["integrations"])

    def test_credentials_ciphertext_rotation_metadata_and_fail_closed(self):
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_outbound","HMAC",{"url":"https://example.test/hook"});value="bounded-test-value-not-reported"
            one=service.set_credential(db,item,"hmac_signing",{"signing_secret":value},self.admin["id"]);two=service.set_credential(db,item,"hmac_signing",{"signing_secret":value+"2"},self.admin["id"],rotate=True)
            stored=db.query(ConnectorCredential).filter_by(connector_id=item.id).one();self.assertNotIn(value,stored.encrypted_payload);self.assertEqual(2,two["version"]);self.assertIsNotNone(stored.rotated_at);self.assertIsNone(item.last_test_status)
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(IntegrationSecurityError):service.encrypt_secret({"token":"x"})

    def test_inbound_secret_rotation_has_only_a_bounded_encrypted_overlap(self):
        body=b'{"event_type":"soc.alert.created","title":"safe"}';stamp=str(int(time.time()))
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_inbound","Rotating inbound",{});old="o"*32;new="n"*32;service.set_credential(db,item,"hmac_signing",{"signing_secret":old},self.admin["id"]);endpoint=ConnectorInboundEndpoint(endpoint_uuid="22222222-2222-4222-8222-222222222222",connector_id=item.id,name="Rotating",allowed_event_types_json='["soc.alert.created"]',created_by_user_id=self.admin["id"]);db.add(endpoint);db.commit();service.set_credential(db,item,"hmac_signing",{"signing_secret":new},self.admin["id"],rotate=True)
            def headers(secret,event_id):return {"content-type":"application/json","x-threatscope-timestamp":stamp,"x-threatscope-event-id":event_id,"x-threatscope-schema-version":"1.0","x-threatscope-signature":sign_hmac(secret,stamp,body)}
            self.assertEqual("quarantined",service.ingest_inbound(db,endpoint,body,headers(old,"overlap-old"),"203.0.113.4").status);self.assertEqual("quarantined",service.ingest_inbound(db,endpoint,body,headers(new,"overlap-new"),"203.0.113.4").status)
            credential=db.query(ConnectorCredential).filter_by(connector_id=item.id).one();envelope=service.decrypt_secret(credential.encrypted_payload);self.assertNotIn(old,credential.encrypted_payload);envelope["_previous_valid_until"]=(datetime.utcnow()-timedelta(seconds=1)).isoformat();credential.encrypted_payload=service.encrypt_secret(envelope);db.commit()
            with self.assertRaises(IntegrationSecurityError) as caught:service.ingest_inbound(db,endpoint,body,headers(old,"overlap-expired"),"203.0.113.4")
            self.assertEqual("CONNECTOR_SIGNATURE_INVALID",caught.exception.code)

    def test_notifications_are_recipient_specific_deduplicated_and_redacted(self):
        with self.factory() as db:
            create_user(db,username="notification.registered",display_name="Registered",password="Notification-Test-Value-72!",role_keys=["registered_user"],must_change_password=False)
            item=self.connector(db,active=True);service.emit_notification(db,"connector_activated",item,"integration_connector",item.id,"Activated with token=never-store",self.admin["id"]);service.emit_notification(db,"connector_activated",item,"integration_connector",item.id,"duplicate",self.admin["id"])
            rows=db.query(root_models.Notification).all();self.assertEqual(1,len(rows));self.assertEqual(self.admin["id"],rows[0].recipient_user_id);self.assertNotIn("never-store",rows[0].message)

    def test_notification_matrix_and_rollback_safety(self):
        with self.factory() as db:
            item=self.connector(db,active=True)
            for index,event in enumerate(service.NOTIFICATION_MATRIX,1):service.emit_notification(db,event,item,"integration_connector",index,f"Safe aggregate event {index}",self.admin["id"])
            self.assertEqual(len(service.NOTIFICATION_MATRIX),db.query(root_models.Notification).count())
            item.description="uncommitted source mutation"
            with self.assertRaises(RuntimeError):service.emit_notification(db,"connector_unhealthy",item,"integration_connector",999,"must not exist",self.admin["id"])
            db.rollback();self.assertFalse(db.query(root_models.Notification).filter_by(entity_id=999).first())

    def test_hmac_transport_contract(self):
        url,method,body,headers,_=adapters.build_http_request("generic_hmac_webhook_outbound",{"url":"https://example.test/hook"},{"signing_secret":"x"*32},{"title":"safe"},"event-1","idem-1")
        self.assertEqual(("https://example.test/hook","POST"),(url,method));self.assertTrue(verify_hmac("x"*32,headers["X-ThreatScope-Timestamp"],body,headers["X-ThreatScope-Signature"]));self.assertEqual("idem-1",headers["Idempotency-Key"])

    def test_slack_and_teams_payloads_are_bounded_and_inert(self):
        for kind in ("slack_incoming_webhook","microsoft_teams_webhook"):
            _,_,body,headers,_=adapters.build_http_request(kind,{"url":"https://example.test/hook"},{"webhook_url":"https://example.test/hook"},{"summary":"<script> https://hostile.invalid"},"e","i")
            self.assertNotIn(b"<script>",body);self.assertIn(b"hxxps://",body);self.assertNotIn("Authorization",headers)

    def test_slack_and_teams_mocked_delivery_transitions_never_use_real_network(self):
        with self.factory() as db:
            for index,kind in enumerate(("slack_incoming_webhook","microsoft_teams_webhook"),1):
                item=self.connector(db,kind,f"Mocked channel {index}",{"url":"https://example.test/hook"},active=True);service.set_credential(db,item,"webhook_url",{"webhook_url":"https://example.test/hook"},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["example.test"]';db.commit()
                success=service.queue_delivery(db,item,{"summary":"TEST <b>safe</b>"},"soc.alert.created","notify",f"channel-success-{index}",self.admin["id"]);db.commit();service.deliver(db,success,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(200,b"ok",1));self.assertEqual("succeeded",success.status)
                retry=service.queue_delivery(db,item,{"summary":"TEST safe"},"soc.alert.created","notify",f"channel-retry-{index}",self.admin["id"]);retry.maximum_attempts=2;db.commit();service.deliver(db,retry,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(503,b"temporary",1));self.assertEqual("waiting_retry",retry.status);service.deliver(db,retry,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(200,b"ok",1));self.assertEqual("succeeded",retry.status)
                terminal=service.queue_delivery(db,item,{"summary":"TEST safe"},"soc.alert.created","notify",f"channel-terminal-{index}",self.admin["id"]);db.commit();service.deliver(db,terminal,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(400,b"withheld",1));self.assertEqual("dead_letter",terminal.status)

    def test_jira_servicenow_and_splunk_fixed_boundaries(self):
        jira={"base_url":"https://jira.example.test","project_key":"SEC","issue_type":"Task","transition_ids":["31"]};credential={"api_token":"x"}
        url,method,_,_,_=adapters.build_http_request("jira_issue",jira,credential,{"action":"create","summary":"Safe"},"e","i");self.assertEqual(("https://jira.example.test/rest/api/2/issue","POST"),(url,method))
        url,method,_,_,_=adapters.build_http_request("jira_issue",jira,credential,{"action":"update","external_reference":"SEC-1","description":"Safe"},"e","i");self.assertEqual(("https://jira.example.test/rest/api/2/issue/SEC-1","PUT"),(url,method))
        url,method,_,_,_=adapters.build_http_request("jira_issue",jira,credential,{"action":"transition","external_reference":"SEC-1","transition_id":"31"},"e","i");self.assertEqual("https://jira.example.test/rest/api/2/issue/SEC-1/transitions",url);self.assertEqual("POST",method)
        with self.assertRaises(IntegrationSecurityError):adapters.build_http_request("jira_issue",jira,credential,{"action":"create","summary":"Safe","jql":"project=SEC"},"e","i")
        snow={"base_url":"https://snow.example.test","table":"incident","assignment_groups":["SOC"]};url,method,_,_,_=adapters.build_http_request("servicenow_incident",snow,{"token":"x"},{"short_description":"Safe","assignment_group":"SOC"},"e","i");self.assertEqual(("https://snow.example.test/api/now/table/incident","POST"),(url,method));url,method,_,_,_=adapters.build_http_request("servicenow_incident",snow,{"token":"x"},{"external_reference":"sys-id","work_notes":"Safe"},"e","i");self.assertEqual("PATCH",method)
        with self.assertRaises(IntegrationSecurityError):adapters.build_http_request("servicenow_incident",snow,{"token":"x"},{"delete":True},"e","i")
        with self.assertRaises(IntegrationSecurityError):adapters.build_http_request("servicenow_incident",{"base_url":"https://snow.example.test","table":"users"},{"token":"x"},{},"e","i")
        url,method,_,headers,_=adapters.build_http_request("splunk_hec",{"url":"https://splunk.example.test","index_allowlist":["security"],"source":"threatscope","sourcetype":"threatscope:event","acknowledgements_enabled":True},{"hec_token":"x"},{"index":"security","title":"Safe"},"e","i");self.assertEqual(("https://splunk.example.test/services/collector/event","POST"),(url,method));self.assertIn("Authorization",headers);self.assertEqual("e",headers["X-Splunk-Request-Channel"])
        with self.assertRaises(IntegrationSecurityError):adapters.build_http_request("splunk_hec",{"url":"https://splunk.example.test","index_allowlist":["security"]},{"hec_token":"x"},{"index":"admin"},"e","i")

    def test_splunk_acknowledgement_uses_only_fixed_mocked_hec_paths(self):
        with self.factory() as db:
            item=self.connector(db,"splunk_hec","Splunk ack",{"url":"https://splunk.example.test","index_allowlist":["security"],"acknowledgements_enabled":True},active=True);service.set_credential(db,item,"bearer_token",{"hec_token":"hidden"},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["splunk.example.test"]';db.commit();delivery=service.queue_delivery(db,item,{"index":"security","title":"safe"},"soc.alert.created","publish_event","splunk-ack",self.admin["id"]);db.commit();transport=Mock(side_effect=[adapters.AdapterResponse(200,b'{"ackId":7}',1),adapters.AdapterResponse(200,b'{"acks":{"7":true}}',1)]);service.deliver(db,delivery,resolver=lambda *a,**k:PUBLIC,transport=transport);self.assertEqual("succeeded",delivery.status);self.assertEqual(2,transport.call_count);self.assertTrue(transport.call_args_list[0].args[0].url.endswith("/services/collector/event"));self.assertTrue(transport.call_args_list[1].args[0].url.endswith("/services/collector/ack"))

    def test_smtp_uses_tls_allowlist_and_mock_transport(self):
        client=Mock();factory=Mock(return_value=client);response=adapters.send_smtp({"host":"smtp.example.test","port":587,"tls_mode":"starttls","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{"username":"svc","password":"hidden"},{"recipients":["analyst@example.test"],"subject":"TEST","body":"safe"},factory)
        self.assertEqual(250,response.status_code);client.starttls.assert_called_once();client.send_message.assert_called_once()
        with self.assertRaises(IntegrationSecurityError):adapters.send_smtp({"host":"x","port":587,"tls_mode":"starttls","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{},{"recipients":["person@invalid.test"]},factory)
        with self.assertRaises(IntegrationSecurityError):adapters.send_smtp({"host":"x","port":25,"tls_mode":"cleartext","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{},{"recipients":["analyst@example.test"]},factory)
        with self.assertRaises(IntegrationSecurityError):adapters.send_smtp({"host":"x","port":587,"tls_mode":"starttls","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{},{"recipients":["analyst@example.test"],"attachments":["forbidden"]},factory)
        temporary=Mock();temporary.send_message.side_effect=smtplib.SMTPServerDisconnected("temporary")
        with self.assertRaises(IntegrationSecurityError) as caught:adapters.send_smtp({"host":"smtp.example.test","port":587,"tls_mode":"starttls","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{},{"recipients":["analyst@example.test"]},Mock(return_value=temporary))
        self.assertEqual("CONNECTOR_TIMEOUT",caught.exception.code)
        authentication=Mock();authentication.login.side_effect=smtplib.SMTPAuthenticationError(535,b"denied")
        with self.assertRaises(IntegrationSecurityError) as caught:adapters.send_smtp({"host":"smtp.example.test","port":587,"tls_mode":"starttls","sender_address":"security@example.test","allowed_recipient_domains":["example.test"]},{"username":"svc","password":"hidden"},{"recipients":["analyst@example.test"]},Mock(return_value=authentication))
        self.assertEqual("CONNECTOR_AUTHENTICATION_FAILED",caught.exception.code)

    def test_retry_circuit_dead_letter_and_manual_replay_state(self):
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_outbound","Retry webhook",{"url":"https://example.test/hook"},active=True);service.set_credential(db,item,"hmac_signing",{"signing_secret":"x"*32},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["example.test"]';db.commit()
            delivery=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","retry-state",self.admin["id"]);delivery.maximum_attempts=1;db.commit();service.deliver(db,delivery,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(503,b"temporary",1))
            self.assertEqual("dead_letter",delivery.status);dead=db.query(ConnectorDeadLetter).one();self.assertEqual("not_requested",dead.replay_status);self.assertNotIn("secret",dead.payload_summary_json.casefold())

    def test_retry_after_is_capped_and_auth_tls_failures_are_terminal(self):
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_outbound","Transport boundaries",{"url":"https://example.test/hook"},active=True);service.set_credential(db,item,"hmac_signing",{"signing_secret":"x"*32},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;item.retry_limit=3;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["example.test"]';db.commit();resolver=Mock(return_value=PUBLIC)
            retry=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","retry-after-bound",self.admin["id"]);retry.maximum_attempts=3;db.commit();service.deliver(db,retry,resolver=resolver,transport=lambda *a:adapters.AdapterResponse(429,b"bounded",1,headers={"retry-after":"99999"}));attempt=db.query(ConnectorDeliveryAttempt).filter_by(delivery_id=retry.id).one();self.assertEqual("waiting_retry",retry.status);self.assertEqual(3600,attempt.retry_after_seconds)
            service.deliver(db,retry,resolver=resolver,transport=lambda *a:adapters.AdapterResponse(200,b"ok",1));self.assertEqual("succeeded",retry.status);self.assertEqual(2,resolver.call_count)
            auth=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","auth-terminal",self.admin["id"]);db.commit();service.deliver(db,auth,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(401,b"denied",1));self.assertEqual("dead_letter",auth.status);self.assertEqual("CONNECTOR_AUTHENTICATION_FAILED",auth.error_code)
            tls=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","tls-terminal",self.admin["id"]);db.commit();service.deliver(db,tls,resolver=lambda *a,**k:PUBLIC,transport=Mock(side_effect=IntegrationSecurityError("CONNECTOR_TLS_FAILED","TLS validation failed")));self.assertEqual("dead_letter",tls.status);self.assertEqual("CONNECTOR_TLS_FAILED",tls.error_code)

    def test_circuit_open_half_open_single_probe_recovery_and_reopen(self):
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_outbound","Circuit webhook",{"url":"https://example.test/hook"},active=True);service.set_credential(db,item,"hmac_signing",{"signing_secret":"x"*32},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["example.test"]'
            deliveries=[service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify",f"circuit-{index}",self.admin["id"]) for index in range(7)]
            for delivery in deliveries:delivery.maximum_attempts=1
            db.commit()
            for delivery in deliveries[:5]:service.deliver(db,delivery,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(503,b"temporary",1))
            self.assertEqual("open",item.circuit_state);self.assertEqual("unhealthy",item.health_status);self.assertEqual(1,db.query(root_models.Notification).filter_by(title="Connector circuit opened").count())
            blocked=deliveries[5];transport=Mock(return_value=adapters.AdapterResponse(200,b"ok",1));service.deliver(db,blocked,resolver=lambda *a,**k:PUBLIC,transport=transport);self.assertEqual("waiting_retry",blocked.status);self.assertEqual(0,blocked.attempt_count);transport.assert_not_called()
            item.circuit_state="half_open";db.commit();service.deliver(db,blocked,resolver=lambda *a,**k:PUBLIC,transport=transport);transport.assert_not_called();self.assertEqual(0,blocked.attempt_count)
            item.circuit_state="open";item.circuit_retry_at=datetime.utcnow()-timedelta(seconds=1);db.commit();service.deliver(db,blocked,resolver=lambda *a,**k:PUBLIC,transport=transport);self.assertEqual("succeeded",blocked.status);self.assertEqual("closed",item.circuit_state);self.assertEqual("healthy",item.health_status);self.assertEqual(1,db.query(root_models.Notification).filter_by(title="Connector circuit half-open").count());self.assertEqual(1,db.query(root_models.Notification).filter_by(title="Connector recovered").count())
            failed_probe=deliveries[6];item.circuit_state="open";item.health_status="unhealthy";item.consecutive_failures=5;item.circuit_retry_at=datetime.utcnow()-timedelta(seconds=1);db.commit();service.deliver(db,failed_probe,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(503,b"temporary",1));self.assertEqual("open",item.circuit_state);self.assertEqual("dead_letter",failed_probe.status)

    def test_dead_letter_replay_is_idempotent_revalidated_and_reports_failure_once(self):
        with self.factory() as db:
            item=self.connector(db,"generic_hmac_webhook_outbound","Replay webhook",{"url":"https://example.test/hook"},active=True);service.set_credential(db,item,"hmac_signing",{"signing_secret":"x"*32},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["example.test"]';db.commit()
            original=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","replay-original",self.admin["id"]);db.commit();service.deliver(db,original,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(401,b"denied",1));dead=db.query(ConnectorDeadLetter).filter_by(delivery_id=original.id).one()
            with patch.object(service,"validate_configuration",return_value={"activation_eligible":True}):
                replay=service.replay_dead_letter(db,dead,self.admin["id"],"Explicit replay review");same=service.replay_dead_letter(db,dead,self.admin["id"],"Repeated request")
            self.assertEqual(replay.id,same.id);self.assertEqual(2,db.query(ConnectorDelivery).count());service.deliver(db,replay,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(401,b"denied",1));self.assertEqual("failed",dead.replay_status);self.assertEqual(1,db.query(root_models.Notification).filter_by(title="Dead-letter replay failed").count())
            another=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","replay-disabled",self.admin["id"]);db.commit();service.deliver(db,another,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(401,b"denied",1));other_dead=db.query(ConnectorDeadLetter).filter_by(delivery_id=another.id).one();item.enabled=False;item.lifecycle_status="disabled";db.commit()
            for _ in range(2):
                with self.assertRaises(IntegrationSecurityError):service.replay_dead_letter(db,other_dead,self.admin["id"],"Explicit disabled replay review")
            self.assertEqual(1,db.query(root_models.Notification).filter_by(title="Dead-letter replay failed",entity_id=other_dead.id).count());self.assertIsNone(other_dead.replayed_delivery_id)

    def test_outbox_is_redacted_idempotent_and_linked(self):
        with self.factory() as db:
            item=self.connector(db,active=True);sub=ConnectorSubscription(subscription_uuid="sub-1",connector_id=item.id,name="alerts",event_type="soc.alert.created",filter_json="{}",created_by_user_id=self.admin["id"]);db.add(sub)
            event=service.canonical_event("soc.alert.created","soc","alert",1,"Title","Summary",{"password":"hidden"},event_id="event-1");outbox=service.enqueue_outbox(db,event);db.commit();result=service.process_due(db,self.admin["id"])
            delivery=db.query(ConnectorDelivery).one();self.assertEqual(outbox.id,delivery.outbox_event_id);self.assertNotIn("hidden",outbox.canonical_event_json);self.assertEqual(1,result["outbox_processed"])

    def test_stix_preview_then_promotion_is_explicit(self):
        bundle={"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[{"type":"indicator","id":"indicator--11111111-1111-4111-8111-111111111111","name":"<script>alert(1)</script>","pattern":"[domain-name:value = 'example.test']","pattern_type":"stix","valid_from":"2025-01-01T00:00:00Z"},{"type":"x-unsupported","id":"x-unsupported--22222222-2222-4222-8222-222222222222","external_references":[{"url":"https://never-fetched.invalid"}]}]}
        with self.factory() as db:
            with self.assertRaises(IntegrationSecurityError):service.stix_preview(db,{"type":"not-a-bundle"},self.admin["id"])
            run=service.stix_preview(db,bundle,self.admin["id"]);self.assertEqual("preview",run.status);self.assertEqual(1,run.quarantined_count);self.assertEqual(0,db.query(root_models.ThreatIndicator).count());self.assertFalse(json.loads(run.preview_json)["external_references_fetched"])
            promoted=service.stix_promote(db,run,self.admin["id"]);self.assertEqual("promoted",promoted.status);self.assertEqual(1,db.query(root_models.ThreatIndicator).count());service.stix_promote(db,run,self.admin["id"]);self.assertEqual(1,db.query(root_models.ThreatIndicator).count())
            with self.assertRaises(IntegrationSecurityError):service.stix_preview(db,{"type":"bundle","objects":[{}]*5001},self.admin["id"])

    def test_taxii_pull_uses_mock_and_advances_cursor_only_on_success(self):
        with self.factory() as db:
            item=self.connector(db,"taxii_21_collection_pull","TAXII",{"api_root_url":"https://taxii.example.test/api","collection_id":"collection-1"});service.set_credential(db,item,"bearer_token",{"token":"hidden"},self.admin["id"]);item.last_test_status="passed";db.commit()
            policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["taxii.example.test"]';db.commit()
            response=adapters.AdapterResponse(200,b'{"objects":[]}',1,headers={"x-taxii-date-added-last":"cursor-1"});result=service.taxii_pull(db,item,self.admin["id"],resolver=lambda *a,**k:PUBLIC,transport=lambda *a:response)
            self.assertTrue(result["cursor_advanced"]);self.assertEqual("cursor-1",db.query(ConnectorSyncCursor).one().cursor_value_encrypted_or_hashed)
            prior=db.query(ConnectorSyncCursor).one().cursor_value_encrypted_or_hashed
            for _ in range(2):
                with self.assertRaises(IntegrationSecurityError):service.taxii_pull(db,item,self.admin["id"],resolver=lambda *a,**k:PUBLIC,transport=lambda *a:adapters.AdapterResponse(503,b"withheld",1))
            self.assertEqual(prior,db.query(ConnectorSyncCursor).one().cursor_value_encrypted_or_hashed);self.assertEqual(1,db.query(root_models.Notification).filter_by(title="TAXII synchronization failed").count())

    def test_external_reference_links_case_without_closure(self):
        with self.factory() as db:
            case=root_models.IncidentCase(case_key="CASE-EXT-1",title="Case",summary="Safe",case_type="incident",severity="high",priority="P2",confidence="medium",risk_score=60,status="investigating",source_module_count=1,evidence_count=0,tags_json="[]");db.add(case);db.flush()
            item=self.connector(db,"jira_issue","Jira",{"base_url":"https://jira.example.test","project_key":"SEC","issue_type":"Task"},active=True);service.set_credential(db,item,"bearer_token",{"api_token":"hidden"},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;db.commit()
            delivery=service.queue_delivery(db,item,{"case_id":case.id,"summary":"Case summary"},"case.updated","create_ticket","case-ticket-1",self.admin["id"]);db.commit();mock=adapters.AdapterResponse(201,b"{}",1,external_reference="SEC-10",external_reference_url="https://jira.example.test/browse/SEC-10")
            service.deliver(db,delivery,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:mock);reference=db.query(ConnectorExternalReference).one();self.assertEqual(str(case.id),reference.linked_entity_id);self.assertEqual("investigating",case.status)
            self.assertEqual(1,db.query(root_models.IncidentTimelineEvent).filter_by(case_id=case.id,event_type="external_ticket_synchronized").count())
            duplicate=service.queue_delivery(db,item,{"case_id":case.id,"summary":"Case summary"},"case.updated","create_ticket","case-ticket-duplicate",self.admin["id"]);db.commit();service.deliver(db,duplicate,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:mock)
            self.assertEqual(1,db.query(ConnectorExternalReference).count());self.assertEqual(1,db.query(root_models.IncidentTimelineEvent).filter_by(case_id=case.id,event_type="external_ticket_synchronized").count())
            case.summary="Newer local analyst update";db.commit()
            update=service.queue_delivery(db,item,{"case_id":case.id,"external_reference":"SEC-10","summary":"Approved external summary"},"case.updated","update_ticket","case-ticket-update",self.admin["id"]);db.commit();transport=Mock(side_effect=AssertionError("conflicting update must not leave ThreatScope"));service.deliver(db,update,resolver=lambda *a,**k:PUBLIC,transport=transport)
            self.assertEqual("dead_letter",update.status);self.assertEqual("CONNECTOR_SYNC_CONFLICT",update.error_code);transport.assert_not_called();self.assertEqual("investigating",case.status);self.assertEqual("Newer local analyst update",case.summary);self.assertEqual(1,db.query(root_models.IncidentTimelineEvent).filter_by(case_id=case.id,event_type="external_sync_conflict").count())

    def test_servicenow_mocked_ticket_reference_links_exact_case_safely(self):
        with self.factory() as db:
            case=root_models.IncidentCase(case_key="CASE-SNOW-1",title="Case",summary="Safe",case_type="incident",severity="high",priority="P2",confidence="medium",risk_score=60,status="investigating",source_module_count=1,evidence_count=0,tags_json="[]");db.add(case);db.flush();item=self.connector(db,"servicenow_incident","ServiceNow",{"base_url":"https://snow.example.test","table":"incident","assignment_groups":["SOC"]},active=True);service.set_credential(db,item,"bearer_token",{"token":"hidden"},self.admin["id"]);item.lifecycle_status="active";item.enabled=True;policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=item.id).one();policy.allowed_hosts_json='["snow.example.test"]';db.commit()
            delivery=service.queue_delivery(db,item,{"case_id":case.id,"short_description":"Safe case"},"case.updated","create_ticket","snow-case-ticket",self.admin["id"]);db.commit();response=adapters.AdapterResponse(201,b"{}",1,external_reference="sys-id-10",external_reference_url="https://snow.example.test/nav_to.do?uri=incident.do?sys_id=sys-id-10");service.deliver(db,delivery,resolver=lambda *a,**k:PUBLIC,transport=lambda *a:response);reference=db.query(ConnectorExternalReference).one();self.assertEqual(("incident_case",str(case.id)),(reference.linked_entity_type,reference.linked_entity_id));self.assertTrue(reference.safe_external_url.startswith("https://snow.example.test/"));self.assertEqual("investigating",case.status)

    def test_soar_connector_delivery_is_queued_idempotently_then_records_outcome(self):
        with self.factory() as db:
            actor=db.get(UserAccount,self.admin["id"]);connector=self.connector(db,active=True)
            playbook=SoarPlaybook(playbook_uuid="soar-remediation-playbook",name="Connector delivery",normalized_name="connector-delivery",lifecycle_status="active",created_by_user_id=actor.id)
            db.add(playbook);db.flush()
            execution=SoarExecution(execution_uuid="soar-remediation-execution",playbook_id=playbook.id,playbook_version=1,trigger_source_type="manual",idempotency_key="soar-delivery-execution",mode="live_local",status="running",requested_by_user_id=actor.id)
            db.add(execution);db.flush()
            step=SoarStepExecution(execution_id=execution.id,step_key="notify",step_name="Notify",step_type="action",action_key="queue_connector_notification",sequence_number=1,idempotency_key="soar-delivery-step",status="running",redacted_input_summary="Safe connector request")
            db.add(step);db.flush();action=ACTION_CATALOG["queue_connector_notification"]
            first=_dispatch(db,execution,step,action,{"connector_id":connector.id,"title":"Safe SOAR notification"},actor)
            second=_dispatch(db,execution,step,action,{"connector_id":connector.id,"title":"Safe SOAR notification"},actor)
            db.commit();self.assertEqual(first["record_id"],second["record_id"]);self.assertEqual(1,db.query(ConnectorDelivery).filter_by(soar_execution_id=execution.id).count())
            delivery=db.get(ConnectorDelivery,first["record_id"])
            with patch("socket.create_connection",side_effect=AssertionError("network")),patch("subprocess.run",side_effect=AssertionError("command")):service.deliver(db,delivery)
            self.assertEqual("succeeded",delivery.status)
            events=db.query(SoarExecutionEvent).filter_by(execution_id=execution.id,event_type="connector_delivery_succeeded").all();self.assertEqual(1,len(events));self.assertIn(delivery.delivery_uuid[:12],events[0].summary)

    def test_local_sink_performs_no_network_or_command(self):
        with self.factory() as db:
            item=self.connector(db,active=True);delivery=service.queue_delivery(db,item,{"title":"safe"},"soc.alert.created","notify","offline-1",self.admin["id"]);db.commit()
            blocked=["socket.create_connection","socket.getaddrinfo","urllib.request.urlopen","httpx.Client.send","httpx.AsyncClient.send","subprocess.run","subprocess.Popen","subprocess.call","subprocess.check_call","subprocess.check_output","os.system","os.popen"]
            if importlib.util.find_spec("requests"):blocked.append("requests.sessions.Session.request")
            with ExitStack() as stack:
                for target in blocked:stack.enter_context(patch(target,side_effect=AssertionError(f"unsafe operation: {target}")))
                service.deliver(db,delivery)
            self.assertEqual("succeeded",delivery.status)


if __name__=="__main__":unittest.main()
