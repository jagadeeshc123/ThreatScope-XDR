import copy
import hashlib
import json
import os
import socket
import subprocess
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from app.modules.access_control.models import UserAccount
from app.modules.access_control.user_service import create_user
from app.modules.detection_engineering import evaluator, execution_service
from app.modules.detection_engineering.report_service import SECTIONS
from app.modules.detection_engineering.service import seed_catalog_and_packs
from tests.access_helpers import authenticate_admin


class DetectionEngineeringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
        cls.factory=sessionmaker(bind=cls.engine)
        def override():
            with cls.factory() as db:yield db
        app.dependency_overrides[get_db]=override;cls.client=TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close();app.dependency_overrides.clear();cls.engine.dispose()

    def setUp(self):
        Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine);authenticate_admin(self.client,self.factory)
        with self.factory() as db:seed_catalog_and_packs(db)

    def login(self,username,role):
        password="Valid-Detection-Password-83!"
        with self.factory() as db:
            if not db.query(UserAccount).filter_by(username_normalized=username).first():create_user(db,username=username,display_name=username,password=password,role_keys=[role],must_change_password=False)
        self.client.cookies.clear();self.client.headers.pop("X-CSRF-Token",None);response=self.client.post("/api/auth/login",json={"username":username,"password":password});self.assertEqual(response.status_code,200,response.text);self.client.headers["X-CSRF-Token"]=self.client.get("/api/auth/csrf").json()["csrf_token"]

    def create_rule(self,title="Authentication failure",selection=None,condition="failed"):
        payload={"title":title,"description":"Bounded stored-event test rule.","severity":"high","confidence":80,"selections":selection or {"failed":{"event.category":"authentication","event.outcome":"failure"}},"condition":condition,"tags":["unit-test"],"technique_ids":["T1110"],"lifecycle_status":"draft"}
        response=self.client.post("/api/detections/rules",json=payload);self.assertEqual(response.status_code,200,response.text);return response.json()

    def add_tests(self,rule_id,positive=True):
        expected={"event.category":"authentication","event.outcome":"failure"} if positive else {"event.category":"authentication","event.outcome":"success"}
        result=self.client.post(f"/api/detections/rules/{rule_id}/tests",json={"name":"Positive","event_payload":expected,"expected_match":positive,"enabled":True});self.assertEqual(result.status_code,200,result.text)
        negative=self.client.post(f"/api/detections/rules/{rule_id}/tests",json={"name":"Negative","event_payload":{"event.category":"authentication","event.outcome":"success"},"expected_match":False,"enabled":True});self.assertEqual(negative.status_code,200,negative.text)

    def test_native_rule_versioning_validation_tests_activation_and_rollback(self):
        rule=self.create_rule();self.assertEqual(rule["current_version"],1);self.assertEqual(rule["lifecycle_status"],"draft");self.assertEqual(len(rule["versions"]),1)
        self.assertEqual(self.client.post(f"/api/detections/rules/{rule['id']}/activate").status_code,422)
        self.add_tests(rule["id"]);run=self.client.post(f"/api/detections/rules/{rule['id']}/tests/run");self.assertEqual(run.status_code,200,run.text);self.assertTrue(run.json()["passed"])
        activation=self.client.post(f"/api/detections/rules/{rule['id']}/activate");self.assertEqual(activation.status_code,200,activation.text);self.assertEqual(activation.json()["lifecycle_status"],"active")
        updated=self.client.patch(f"/api/detections/rules/{rule['id']}",json={"description":"Changed safely","change_summary":"Document behavior"});self.assertEqual(updated.status_code,200,updated.text);self.assertEqual(updated.json()["current_version"],2);self.assertEqual(updated.json()["lifecycle_status"],"testing")
        versions=self.client.get(f"/api/detections/rules/{rule['id']}/versions").json();self.assertEqual(len(versions),2);self.assertEqual(versions[-1]["version_number"],1)
        original_hash=versions[-1]["content_sha256"];self.assertEqual(original_hash,hashlib.sha256(json.dumps(versions[-1]["rule_content"],sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest())
        rolled=self.client.post(f"/api/detections/rules/{rule['id']}/rollback",json={"version_number":1,"change_summary":"Restore baseline"});self.assertEqual(rolled.status_code,200,rolled.text);self.assertEqual(rolled.json()["current_version"],3);self.assertEqual(len(rolled.json()["versions"]),3)

    def test_safe_sigma_yaml_json_import_and_unsafe_inputs(self):
        sigma="""title: Sigma auth\nid: 22222222-2222-2222-2222-222222222222\nlevel: high\ntags: [attack.t1110, attack.t9999]\nlogsource: {category: authentication}\ndetection:\n  failed:\n    EventType: authentication\n    Outcome: failure\n  condition: failed\n"""
        preview=self.client.post("/api/detections/imports/validate",json={"content":sigma,"filename":"../safe.yaml","duplicate_action":"skip"});self.assertEqual(preview.status_code,200,preview.text);self.assertTrue(preview.json()["previews"][0]["valid"]);self.assertEqual(preview.json()["filename"],"safe.yaml")
        imported=self.client.post("/api/detections/imports",json={"content":sigma,"filename":"safe.yaml","duplicate_action":"skip"});self.assertEqual(imported.status_code,200,imported.text);self.assertEqual(len(imported.json()["created_rule_ids"]),1)
        duplicate=self.client.post("/api/detections/imports",json={"content":sigma,"filename":"safe.yaml","duplicate_action":"skip"});self.assertEqual(len(duplicate.json()["skipped"]),1)
        sigma_json=json.dumps({"title":"JSON Sigma","id":"33333333-3333-3333-3333-333333333333","detection":{"selection":{"SourceIp|cidr":"192.0.2.0/24"},"condition":"selection"}})
        self.assertEqual(self.client.post("/api/detections/imports/validate",json={"content":sigma_json,"filename":"rule.json"}).status_code,200)
        for unsafe in ["a: &x [1,2]\nb: *x", "!!python/object/apply:os.system ['whoami']"]:
            self.assertEqual(self.client.post("/api/detections/imports/validate",json={"content":unsafe,"filename":"bad.yaml"}).status_code,422)
        malformed=self.client.post("/api/detections/imports/validate",json={"content":"title: malformed\ndetection: {condition: missing}","filename":"bad.yaml"});self.assertEqual(malformed.status_code,200);self.assertFalse(malformed.json()["previews"][0]["valid"])
        with self.factory() as db:self.assertFalse(hasattr(db.query(models.DetectionRule).first(),"uploaded_file_content"))

    def test_evaluator_all_operators_boolean_conditions_and_bounds(self):
        event={field:None for field in evaluator.ALLOWED_FIELDS};event.update({"event.category":"Authentication","event.message":"Login failed for admin","event.action":"user-login","event.outcome":"failure","event.severity":"high","source.ip":"192.0.2.10","http.status_code":403,"user.name":"administrator","tags":["security"]})
        selections={"selection_exact":{"event.category":"authentication"},"selection_contains":{"event.message|contains":"failed"},"selection_starts":{"event.action|startswith":"user"},"selection_ends":{"event.action|endswith":"login"},"selection_numeric":{"http.status_code|gte":400},"selection_exists":{"source.ip|exists":True},"selection_cidr":{"source.ip|cidr":"192.0.2.0/24"},"selection_listed":{"event.outcome":{"operator":"in","value":["failure","denied"]}},"selection_wild":{"user.name|wildcard":"admin*"}}
        result=evaluator.validate({"selections":selections,"condition":"all of selection*"});self.assertTrue(result["valid"],result);matched,fields,names=evaluator.evaluate(result["normalized"],event);self.assertTrue(matched);self.assertEqual(len(names),len(selections));self.assertIn("source.ip",fields)
        self.assertFalse(evaluator._match_value("Authentication","exact","authentication"));self.assertTrue(evaluator._match_value("Authentication","iexact","authentication"))
        one=evaluator.validate({"selections":{"selection1":{"event.outcome":"success"},"selection2":{"event.outcome":"failure"}},"condition":"1 of selection* and not selection1"});self.assertTrue(evaluator.evaluate(one["normalized"],event)[0])
        self.assertFalse(evaluator.evaluate(result["normalized"],{field:None for field in evaluator.ALLOWED_FIELDS})[0])
        deep={"selections":{"s":{"event.category":"x"}},"condition":"("*10+"s"+")"*10};self.assertFalse(evaluator.validate(deep)["valid"])
        wild={"selections":{"s":{"event.message|wildcard":"*"*21}},"condition":"s"};self.assertFalse(evaluator.validate(wild)["valid"])
        nested={};cursor=nested
        for _ in range(7):cursor["child"]={};cursor=cursor["child"]
        with self.assertRaisesRegex(ValueError,"nesting depth"):execution_service.synthetic_event({"event.message":nested})

    def test_historical_execution_idempotency_suppression_and_source_immutability(self):
        rule=self.create_rule();self.add_tests(rule["id"]);self.client.post(f"/api/detections/rules/{rule['id']}/activate")
        with self.factory() as db:
            source=models.SocLogSource(name="Detection test logs",source_type="file",parser_type="json",enabled=True);db.add(source);db.flush();event=models.SocEvent(source_id=source.id,event_time=datetime.now(timezone.utc),event_type="authentication",action="login",outcome="failure",severity="high",source_ip="192.0.2.77",username="analyst",message="Stored failed login",normalized_json='{"tags":["test"]}',raw_event_hash="d"*64);db.add(event);db.commit();event_id=event.id;before={c.name:getattr(event,c.name) for c in event.__table__.columns}
        run=self.client.post("/api/detections/executions",json={"rule_ids":[rule["id"]],"maximum_records":100});self.assertEqual(run.status_code,200,run.text);self.assertEqual(run.json()["matches_found"],1)
        second=self.client.post("/api/detections/executions",json={"rule_ids":[rule["id"]],"maximum_records":100});self.assertEqual(second.status_code,200);self.assertEqual(second.json()["matches_found"],1)
        with self.factory() as db:self.assertEqual(db.query(models.DetectionMatch).count(),1);after={c.name:getattr(db.get(models.SocEvent,event_id),c.name) for c in models.SocEvent.__table__.columns};self.assertEqual(before,after);match=db.query(models.DetectionMatch).first();match_id=match.id
        reviewed=self.client.post(f"/api/detections/matches/{match_id}/review",json={"status":"false_positive","analyst_note":"Known test"});self.assertEqual(reviewed.status_code,200,reviewed.text)
        self.client.post("/api/detections/executions",json={"rule_ids":[rule["id"]],"maximum_records":100});self.assertEqual(self.client.get(f"/api/detections/matches/{match_id}").json()["status"],"false_positive")
        suppression=self.client.post("/api/detections/suppressions",json={"name":"Test source","description":"Known benign local test event","rule_id":rule["id"],"field_conditions":{"source.ip":"192.0.2.77"},"enabled":True});self.assertEqual(suppression.status_code,200,suppression.text)
        self.assertEqual(self.client.post("/api/detections/suppressions",json={"name":"Unsafe","description":"Must be scoped","field_conditions":{"unknown.field":"x"}}).status_code,422)
        self.assertEqual(self.client.post("/api/detections/suppressions",json={"name":"Unsafe","description":"Must be scoped","field_conditions":{"source.ip":" "}}).status_code,422)
        self.assertEqual(self.client.post("/api/detections/executions",json={"rule_ids":[rule["id"]],"source_modules":["unknown"]}).status_code,422)
        with self.factory() as db:db.query(models.DetectionMatch).delete();db.commit()
        suppressed=self.client.post("/api/detections/executions",json={"rule_ids":[rule["id"]],"maximum_records":100});self.assertEqual(suppressed.json()["suppressed_matches"],1)
        with self.factory() as db:self.assertEqual(db.query(models.DetectionMatch).first().status,"suppressed");self.assertEqual(db.get(models.SocEvent,event_id).message,"Stored failed login")

    def test_match_review_alert_case_promotion_packs_coverage_and_reports(self):
        with self.factory() as db:
            self.assertEqual(db.query(models.AttackTechnique).count(),27);self.assertEqual(db.query(models.DetectionRulePack).filter_by(system_owned=True).count(),4)
            match=models.DetectionMatch(execution_id=self._execution(db),rule_id=db.query(models.DetectionRule).first().id,rule_version=1,source_module="soc",source_entity_type="soc_event",source_entity_id=1,event_timestamp=datetime.now(timezone.utc),matched_fields_json='{"event.message":"<script>alert(1)</script> https://evil.example"}',evidence_summary="<script>alert(1)</script> password=hunter2 https://evil.example",severity="high",confidence=80,risk_score=75,status="new",fingerprint="e"*64);db.add(match);db.commit();match_id=match.id
        self.assertEqual(self.client.post(f"/api/detections/matches/{match_id}/create-alert",json={"confirmed":False}).status_code,422)
        alert=self.client.post(f"/api/detections/matches/{match_id}/create-alert",json={"confirmed":True,"analyst_note":"Explicit promotion"});self.assertEqual(alert.status_code,200,alert.text)
        self.assertEqual(self.client.post(f"/api/detections/matches/{match_id}/escalate-case",json={"confirmed":False}).status_code,422)
        case=self.client.post(f"/api/detections/matches/{match_id}/escalate-case",json={"confirmed":True,"case_title":"Detection escalation"});self.assertEqual(case.status_code,200,case.text)
        coverage=self.client.get("/api/detections/coverage");self.assertEqual(coverage.status_code,200);self.assertIn("bounded",coverage.json()["catalog_scope"].lower())
        report=self.client.post("/api/detections/reports",json={"title":"Detection <Safe> Report","filters":{}});self.assertEqual(report.status_code,200,report.text);content=self.client.get(f"/api/detections/reports/{report.json()['id']}").json()["html_content"]
        import html
        for section in SECTIONS:self.assertIn(html.escape(section),content)
        self.assertNotIn("<script>alert",content);self.assertNotIn("<a ",content);self.assertNotIn("src=",content);self.assertNotIn("https://evil.example",content)

    def _execution(self,db):
        rule=db.query(models.DetectionRule).first();source=db.query(models.SocLogSource).first()
        if not source:source=models.SocLogSource(name="Promotion source",source_type="file",parser_type="json",enabled=True);db.add(source);db.flush()
        if not db.query(models.SocDetectionRule).first():db.add(models.SocDetectionRule(rule_code="PROMOTE",name="Promotion bridge",description="Local bridge",rule_type="threshold",enabled=True,severity="high",confidence="high",window_seconds=60,threshold=1,group_by="source_ip",conditions_json="{}",remediation="Review",is_default=True));db.flush()
        execution=models.DetectionExecution(rule_id=rule.id,status="completed",mode="targeted",records_scanned=1,matches_found=1,requested_by_user_id=rule.created_by_user_id,started_at=datetime.now(timezone.utc),completed_at=datetime.now(timezone.utc),parameters_json="{}");db.add(execution);db.flush();return execution.id

    def test_rbac_csrf_dashboard_search_and_offline_no_execution_contract(self):
        authenticate_admin(self.client,self.factory);self.client.headers.pop("X-CSRF-Token",None);self.assertEqual(self.client.post("/api/detections/rules",json={}).status_code,403)
        self.client.cookies.clear();self.assertEqual(self.client.get("/api/detections/overview").status_code,401)
        self.login("registered.det","registered_user");self.assertEqual(self.client.get("/api/detections/overview").status_code,403)
        self.login("auditor.det","auditor");self.assertEqual(self.client.get("/api/detections/overview").status_code,200);self.assertEqual(self.client.post("/api/detections/rules",json={}).status_code,403)
        self.login("analyst.det","security_analyst");self.assertEqual(self.client.get("/api/detections/overview").status_code,200)
        authenticate_admin(self.client,self.factory);failure=RuntimeError("external or executable interface forbidden")
        with patch("socket.create_connection",side_effect=failure),patch("socket.getaddrinfo",side_effect=failure),patch("subprocess.run",side_effect=failure),patch("subprocess.Popen",side_effect=failure),patch("os.system",side_effect=failure),patch("urllib.request.urlopen",side_effect=failure):
            rule=self.create_rule("Offline proof");self.add_tests(rule["id"]);self.assertEqual(self.client.post(f"/api/detections/rules/{rule['id']}/tests/run").status_code,200);self.assertEqual(self.client.post("/api/detections/reports",json={"title":"Offline proof","filters":{}}).status_code,200)
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code,200);search=self.client.get("/api/search/",params={"q":"Offline proof"});self.assertEqual(search.status_code,200);self.assertGreaterEqual(len(search.json()["detection_rules"]),1)


if __name__=="__main__":unittest.main()
