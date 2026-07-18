import os
import socket
import subprocess
import unittest
import urllib.request
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.modules.access_control.models import UserAccount
from app.modules.access_control.role_service import seed_roles_and_permissions
from app.modules.soar import report_service, service
from app.modules.soar.catalog import ACTION_CATALOG, SAFETY_CLASSIFICATIONS, catalog_response
from app.modules.soar.conditions import evaluate, resolve_reference
from app.modules.soar.models import SoarActionPolicy, SoarApproval, SoarExecution, SoarPlaybook, SoarPlaybookVersion, SoarStepExecution
from app.modules.soar.validation import MAX_DEFINITION_BYTES, content_hash, validate_definition


def definition(action="load_soc_alert_context"):
    return {"start_step":"start","variables":{},"constants":{},"steps":[{"key":"start","type":"action","name":"Start","action_key":action,"position":0,"on_success":"end","on_failure":"failed","max_retries":0},{"key":"end","type":"end","name":"End","position":1},{"key":"failed","type":"end","name":"Failed","position":2,"configuration":{"outcome":"failed"}}]}


class SoarPlaybookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=create_engine("sqlite:///:memory:",connect_args={"check_same_thread":False},poolclass=StaticPool)
        Base.metadata.create_all(cls.engine);cls.Session=sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db=self.Session()
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in {"user_accounts","soar_action_policies","soar_playbooks","soar_playbook_versions","soar_playbook_steps","soar_executions","soar_step_executions","soar_execution_events","soar_approvals","soar_approval_decisions","soar_analyst_inputs","soar_execution_evidence","soar_rollback_records","soar_reports","soar_trigger_rules","soar_trigger_evaluation_runs"}:self.db.execute(table.delete())
        self.user=UserAccount(username="admin",username_normalized="admin",display_name="Administrator",email="admin@example.test",email_normalized="admin@example.test",password_hash="not-a-real-password",status="active",is_system_admin=True)
        self.db.add(self.user);self.db.commit();seed_roles_and_permissions(self.db);service.seed_defaults(self.db)

    def tearDown(self):self.db.close()

    def test_catalog_is_server_owned_complete_and_classified(self):
        catalog=catalog_response();self.assertGreaterEqual(len(catalog),70);self.assertEqual(len(catalog),len(ACTION_CATALOG));self.assertTrue(all(x["safety_classification"] in SAFETY_CLASSIFICATIONS for x in catalog));self.assertTrue(all("input_schema" in x and "audit_event_type" in x for x in catalog))

    def test_simulation_actions_never_allow_live_local(self):
        actions=[x for x in ACTION_CATALOG.values() if x.simulation_only];self.assertEqual(15,len(actions));self.assertTrue(all("live_local" not in x.allowed_execution_modes and x.warning_message.startswith("SIMULATION ONLY") for x in actions))

    def test_sensitive_protections_are_mandatory(self):
        sensitive=[x for x in ACTION_CATALOG.values() if x.safety_classification=="sensitive_local"];self.assertEqual(4,len(sensitive));self.assertTrue(all(x.administrator_approval_required and x.requester_approver_separation_required and not x.automatic_local_eligible for x in sensitive))

    def test_seed_is_idempotent_and_preserves_policy(self):
        count=self.db.query(SoarActionPolicy).count();policy=self.db.query(SoarActionPolicy).first();policy.enabled=False;self.db.commit();service.seed_defaults(self.db);self.assertEqual(count,self.db.query(SoarActionPolicy).count());self.assertFalse(self.db.get(SoarActionPolicy,policy.id).enabled);self.assertEqual(10,self.db.query(SoarPlaybook).filter_by(system_owned=True).count())

    def test_valid_definition(self):self.assertTrue(validate_definition(definition())["valid"])

    def test_validation_missing_start_duplicate_unknown_destination(self):
        value=definition();value["start_step"]="missing";self.assertFalse(validate_definition(value)["valid"])
        value=definition();value["steps"].append(dict(value["steps"][0]));self.assertFalse(validate_definition(value)["valid"])
        value=definition();value["steps"][0]["on_success"]="unknown";self.assertFalse(validate_definition(value)["valid"])

    def test_validation_unreachable_no_terminal_self_loop_cycle(self):
        value=definition();value["steps"].append({"key":"orphan","type":"end","position":4});self.assertFalse(validate_definition(value)["valid"])
        value={"start_step":"a","variables":{},"steps":[{"key":"a","type":"condition","condition":{"operator":"equals","left":1,"right":1},"on_success":"a","position":0}]};self.assertFalse(validate_definition(value)["valid"])
        value={"start_step":"a","variables":{},"steps":[{"key":"a","type":"condition","condition":{"operator":"equals","left":1,"right":1},"on_success":"b","position":0},{"key":"b","type":"condition","condition":{"operator":"equals","left":1,"right":1},"on_success":"a","position":1}]};self.assertFalse(validate_definition(value)["valid"])

    def test_validation_bounds(self):
        value=definition();value["steps"]=[{"key":f"s{x}","type":"end","position":x} for x in range(51)];value["start_step"]="s0";self.assertFalse(validate_definition(value)["valid"])
        value=definition();value["variables"]={f"v{x}":x for x in range(101)};self.assertFalse(validate_definition(value)["valid"])
        value=definition();value["steps"][0]["max_retries"]=4;self.assertFalse(validate_definition(value)["valid"])
        value=definition();value["steps"].insert(1,{"key":"delay","type":"delay","position":5,"configuration":{"delay_seconds":86401},"on_success":"end"});value["steps"][0]["on_success"]="delay";self.assertFalse(validate_definition(value)["valid"])

    def test_validation_forbids_executable_and_network_fields(self):
        for field in ("command","shell","url","webhook","callable","module","python","javascript","sql","script"):
            value=definition();value["steps"][0]["configuration"]={field:"unsafe"};self.assertFalse(validate_definition(value)["valid"],field)

    def test_sensitive_requires_approval_and_automatic_local_is_safe(self):
        result=validate_definition(definition("temporarily_disable_user"));self.assertFalse(result["valid"]);self.assertTrue(any(x["code"]=="SOAR_APPROVAL_REQUIRED" for x in result["errors"]))
        self.assertFalse(validate_definition(definition("create_incident_case"),trigger_mode="automatic_local")["valid"])
        self.assertFalse(validate_definition(definition("capture_evidence_snapshot"),trigger_mode="automatic_local")["valid"])
        self.assertTrue(validate_definition(definition("capture_evidence_snapshot"),trigger_mode="automatic_local",policy_automatic={"capture_evidence_snapshot":True})["valid"])

    def test_conditions_all_supported_families(self):
        context={"trigger":{"severity":"High","score":80,"tags":["urgent"],"flag":True}}
        cases=[({"operator":"equals","left":"${trigger.score}","right":80},True),({"operator":"contains","left":"${trigger.tags}","right":"urgent"},True),({"operator":"starts_with","left":"${trigger.severity}","right":"Hi"},True),({"operator":"ends_with","left":"${trigger.severity}","right":"gh"},True),({"operator":"in","left":"High","right":["High"]},True),({"operator":"greater_than","left":"${trigger.score}","right":70},True),({"operator":"exists","left":"${trigger.score}"},True),({"operator":"not_exists","left":"${trigger.missing}"},True),({"operator":"is_true","left":"${trigger.flag}"},True),({"operator":"is_false","left":False},True)]
        for condition,expected in cases:self.assertEqual(expected,evaluate(condition,context).matched)

    def test_conditions_composition_missing_type_and_explanation(self):
        condition={"operator":"all","conditions":[{"operator":"equals","left":1,"right":1},{"operator":"not","condition":{"operator":"equals","left":"1","right":1}}]};result=evaluate(condition,{});self.assertTrue(result.matched);self.assertIn("all",result.explanation);self.assertFalse(evaluate({"operator":"greater_than","left":"9","right":2},{}).matched);self.assertFalse(evaluate({"operator":"equals","left":"${trigger.missing}","right":None},{"trigger":{}}).matched)

    def test_variable_roots_and_dunder_are_bounded(self):
        context={"trigger":{"severity":"high"}};self.assertEqual("high",resolve_reference("${trigger.severity}",context));self.assertIsNot(resolve_reference("${environment.PATH}",context),os.environ.get("PATH"));self.assertFalse(validate_definition({**definition(),"variables":{"bad":"${trigger.__class__}"}})["valid"])

    def test_sensitive_action_approval_pause_and_resume(self):
        value={"start_step":"approve","variables":{},"constants":{},"steps":[{"key":"approve","type":"approval","name":"Approve","position":0,"configuration":{"reason":"review"},"on_success":"disable"},{"key":"disable","type":"action","name":"Disable","action_key":"temporarily_disable_user","position":1,"configuration":{"source_id":self.user.id,"reason":"bounded simulation"},"on_success":"end"},{"key":"end","type":"end","name":"End","position":2}]}
        payload=SimpleNamespace(name="Approval",description="test",category="identity",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=value,change_summary="v1",demo_owned=False);playbook,_=service.create_playbook(self.db,payload,self.user);playbook=service.lifecycle(self.db,playbook,"testing",self.user,playbook.optimistic_lock_version)
        request=SimpleNamespace(idempotency_key="approval-flow",trigger_source_type="manual",trigger_source_id=self.user.id,input_context={},mode="simulation");execution=service.create_execution(self.db,playbook,request,self.user);self.assertEqual("waiting_approval",execution.status)
        first=self.db.query(SoarApproval).filter_by(execution_id=execution.id,status="pending").one();service.decide_approval(self.db,first,self.user,"approve","reviewed");self.db.refresh(execution);self.assertEqual("waiting_approval",execution.status)
        second=self.db.query(SoarApproval).filter_by(execution_id=execution.id,status="pending").one();service.decide_approval(self.db,second,self.user,"approve","approved simulation");self.db.refresh(execution);self.assertEqual("completed",execution.status);self.assertEqual("active",self.user.status)

    def test_persistent_delay_resumes_without_sleep(self):
        value={"start_step":"wait","variables":{},"constants":{},"steps":[{"key":"wait","type":"delay","name":"Wait","position":0,"configuration":{"delay_seconds":1},"on_success":"end"},{"key":"end","type":"end","name":"End","position":1}]}
        payload=SimpleNamespace(name="Delay",description="test",category="workflow",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=value,change_summary="v1",demo_owned=False);playbook,_=service.create_playbook(self.db,payload,self.user);playbook=service.lifecycle(self.db,playbook,"testing",self.user,playbook.optimistic_lock_version)
        request=SimpleNamespace(idempotency_key="delay-flow",trigger_source_type="manual",trigger_source_id=None,input_context={},mode="simulation");execution=service.create_execution(self.db,playbook,request,self.user);self.assertEqual("waiting_delay",execution.status);execution.next_resume_at=service.utcnow()-timedelta(seconds=1);self.db.commit();result=service.process_due(self.db,self.user,10);self.db.refresh(execution);self.assertEqual(1,result["processed_count"]);self.assertEqual("completed",execution.status)

    def test_create_versions_validate_and_unchanged_noop(self):
        payload=SimpleNamespace(name="Local triage",description="test",category="soc",trigger_mode="manual",severity_threshold=None,owner_user_id=self.user.id,definition=definition(),change_summary="version one",demo_owned=False)
        item,result=service.create_playbook(self.db,payload,self.user);self.assertTrue(result["valid"]);self.assertEqual(1,item.current_version)
        update=SimpleNamespace(name=None,description=None,category=None,trigger_mode=None,severity_threshold=None,owner_user_id=None,definition=definition(),change_summary="unchanged",optimistic_lock_version=item.optimistic_lock_version)
        item,result,versioned=service.update_playbook(self.db,item,update,self.user);self.assertFalse(versioned);self.assertEqual(1,item.current_version);self.assertEqual(1,self.db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id).count())

    def test_version_rollback_creates_new_immutable_version(self):
        payload=SimpleNamespace(name="Version test",description="test",category="soc",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=definition(),change_summary="v1",demo_owned=False);item,_=service.create_playbook(self.db,payload,self.user)
        changed=definition();changed["variables"]={"priority":"high"};update=SimpleNamespace(name=None,description=None,category=None,trigger_mode=None,severity_threshold=None,owner_user_id=None,definition=changed,change_summary="v2",optimistic_lock_version=item.optimistic_lock_version);item,_,_=service.update_playbook(self.db,item,update,self.user);service.version_rollback(self.db,item,1,"rollback creates v3",self.user,item.optimistic_lock_version);self.assertEqual(3,item.current_version);self.assertEqual(3,self.db.query(SoarPlaybookVersion).filter_by(playbook_id=item.id).count())

    def test_lifecycle_rejects_direct_activation(self):
        payload=SimpleNamespace(name="Lifecycle",description="test",category="soc",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=definition(),change_summary="v1",demo_owned=False);item,_=service.create_playbook(self.db,payload,self.user)
        with self.assertRaises(Exception):service.lifecycle(self.db,item,"active",self.user,item.optimistic_lock_version)
        item=service.lifecycle(self.db,item,"testing",self.user,item.optimistic_lock_version);item=service.lifecycle(self.db,item,"active",self.user,item.optimistic_lock_version);self.assertEqual("active",item.lifecycle_status)

    def test_dry_run_completes_without_local_mutation(self):
        payload=SimpleNamespace(name="Dry run",description="test",category="soc",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=definition("create_internal_notification"),change_summary="v1",demo_owned=False);playbook,_=service.create_playbook(self.db,payload,self.user);playbook=service.lifecycle(self.db,playbook,"testing",self.user,playbook.optimistic_lock_version)
        request=SimpleNamespace(idempotency_key="dry-run-0001",trigger_source_type="manual",trigger_source_id=None,input_context={},mode="dry_run");execution=service.create_execution(self.db,playbook,request,self.user);self.assertEqual("completed",execution.status);self.assertEqual(0,execution.records_created);self.assertTrue(all(x.status in {"skipped","succeeded"} for x in self.db.query(SoarStepExecution).filter_by(execution_id=execution.id)))

    def test_execution_idempotency_returns_existing(self):
        payload=SimpleNamespace(name="Idempotent",description="test",category="soc",trigger_mode="manual",severity_threshold=None,owner_user_id=None,definition=definition(),change_summary="v1",demo_owned=False);playbook,_=service.create_playbook(self.db,payload,self.user);playbook=service.lifecycle(self.db,playbook,"testing",self.user,playbook.optimistic_lock_version);request=SimpleNamespace(idempotency_key="same-request",trigger_source_type="manual",trigger_source_id=None,input_context={},mode="dry_run");a=service.create_execution(self.db,playbook,request,self.user);b=service.create_execution(self.db,playbook,request,self.user);self.assertEqual(a.id,b.id)

    def test_report_has_all_sections_and_safe_html(self):
        item=report_service.generate(self.db,"<script>alert(1)</script>","soar_summary",{"q":"<a href='https://evil'>x</a>"},self.user.id);self.assertEqual(41,report_service.details(item)["section_count"]);self.assertNotIn("<script>",item.html_content);self.assertNotIn("href=",item.html_content);self.assertNotIn("http",item.html_content);self.assertIn("NO EXTERNAL ACTION",item.html_content)

    def test_offline_safety_patches_are_never_called(self):
        blockers=[patch("socket.create_connection",side_effect=AssertionError("network")),patch("socket.getaddrinfo",side_effect=AssertionError("dns")),patch("urllib.request.urlopen",side_effect=AssertionError("url")),patch("subprocess.run",side_effect=AssertionError("process")),patch("subprocess.Popen",side_effect=AssertionError("process")),patch("subprocess.call",side_effect=AssertionError("process")),patch("subprocess.check_call",side_effect=AssertionError("process")),patch("subprocess.check_output",side_effect=AssertionError("process")),patch("os.system",side_effect=AssertionError("shell")),patch("os.popen",side_effect=AssertionError("shell"))]
        for blocker in blockers:blocker.start()
        try:self.assertTrue(validate_definition(definition())["valid"]);self.assertTrue(validate_definition(definition("simulate_block_ip"))["valid"]);report_service.generate(self.db,"Offline proof","soar_summary",{},self.user.id)
        finally:
            for blocker in reversed(blockers):blocker.stop()


if __name__=="__main__":unittest.main()
