import unittest
from datetime import datetime,timezone,timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base,get_db
from app.main import app
from tests.access_helpers import authenticate_admin


class FinalAuditRegressionTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool);cls.factory=sessionmaker(bind=cls.engine)
  def override():
   db=cls.factory()
   try:yield db
   finally:db.close()
  app.dependency_overrides[get_db]=override;cls.client=TestClient(app)
 @classmethod
 def tearDownClass(cls):cls.client.close();app.dependency_overrides.clear();cls.engine.dispose()
 def setUp(self):Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine);authenticate_admin(self.client,self.factory)
 def risk(self):
  response=self.client.post("/api/governance/risks",json={"title":"Audit risk","description":"Bounded local evidence","category":"governance","likelihood":3,"impact":4})
  self.assertEqual(response.status_code,200,response.text);return response.json()

 def test_from_source_failure_is_atomic(self):
  with self.factory() as db:before=(db.query(models.IncidentCase).count(),db.query(models.SocActivity).count(),db.query(models.Notification).count())
  response=self.client.post("/api/correlation/cases/from-source",json={"title":"Must roll back","source_module":"web_exposure","source_record_type":"finding","source_record_id":999999})
  self.assertEqual(response.status_code,404,response.text)
  with self.factory() as db:after=(db.query(models.IncidentCase).count(),db.query(models.SocActivity).count(),db.query(models.Notification).count())
  self.assertEqual(after,before)

 def test_correlation_rejects_invalid_state_and_returns_child_404s(self):
  case=self.client.post("/api/correlation/cases",json={"title":"Boundary case"}).json();cid=case["id"]
  for method,path in (("delete",f"/api/correlation/cases/{cid}/evidence/999"),("patch",f"/api/correlation/cases/{cid}/notes/999"),("delete",f"/api/correlation/cases/{cid}/notes/999"),("patch",f"/api/correlation/cases/{cid}/actions/999"),("delete",f"/api/correlation/cases/{cid}/actions/999")):
   response=self.client.patch(path,json={}) if method=="patch" else self.client.delete(path)
   self.assertEqual(response.status_code,404,path)
  self.assertEqual(self.client.post(f"/api/correlation/cases/{cid}/actions",json={"title":"Invalid date","due_at":"not-a-date"}).status_code,422)
  self.assertEqual(self.client.patch(f"/api/correlation/cases/{cid}",json={"status":"teleported"}).status_code,422)
  self.assertEqual(self.client.get("/api/correlation/reports/999/download").status_code,404)
  rules=self.client.get("/api/correlation/rules").json();rule=rules[0]
  self.assertEqual(self.client.patch(f"/api/correlation/rules/{rule['id']}",json={"enabled":"false"}).status_code,422)

 def test_governance_lifecycle_and_reference_boundaries(self):
  risk=self.risk();rid=risk["id"]
  for payload in ({"status":"teleported"},{"treatment_strategy":"execute"},{"confidence":"certain"}):self.assertEqual(self.client.patch(f"/api/governance/risks/{rid}",json=payload).status_code,422)
  self.assertEqual(self.client.get(f"/api/governance/risks/{rid}").json()["status"],"identified")
  treatment=self.client.post(f"/api/governance/risks/{rid}/treatments",json={"title":"Review","strategy":"monitor"}).json()
  self.assertEqual(self.client.patch(f"/api/governance/risks/{rid}/treatments/{treatment['id']}",json={"status":"teleported"}).status_code,422)
  self.assertEqual(self.client.patch(f"/api/governance/risks/{rid}/treatments/{treatment['id']}",json={"expected_residual_impact":"not-a-score"}).status_code,422)
  done=self.client.patch(f"/api/governance/risks/{rid}/treatments/{treatment['id']}",json={"status":"completed","completion_summary":"Reviewed"}).json();self.assertIsNotNone(done["completed_at"])
  reopened=self.client.patch(f"/api/governance/risks/{rid}/treatments/{treatment['id']}",json={"status":"in_progress"}).json();self.assertIsNone(reopened["completed_at"])
  exception=self.client.post(f"/api/governance/risks/{rid}/exceptions",json={"justification":"Bounded decision"}).json()
  self.assertEqual(self.client.patch(f"/api/governance/exceptions/{exception['id']}",json={"status":"teleported"}).status_code,422)
  self.assertEqual(self.client.post("/api/governance/evidence-packages",json={"title":"Orphan","framework_id":999999}).status_code,404)
  package=self.client.post("/api/governance/evidence-packages",json={"title":"Audit package"}).json()
  self.assertEqual(self.client.patch(f"/api/governance/evidence-packages/{package['id']}",json={"status":"teleported"}).status_code,422)
  invalid_item={"source_module":"governance","source_record_type":"risk","source_record_id":rid,"risk_id":999999}
  self.assertEqual(self.client.post(f"/api/governance/evidence-packages/{package['id']}/items",json=invalid_item).status_code,404)
  start=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat();end=datetime.now(timezone.utc).isoformat()
  self.assertEqual(self.client.post("/api/governance/reviews",json={"title":"Bad review","review_type":"surprise","period_start":start,"period_end":end}).status_code,422)
  review=self.client.post("/api/governance/reviews",json={"title":"Audit review","review_type":"periodic","period_start":start,"period_end":end}).json()
  self.assertEqual(self.client.patch(f"/api/governance/reviews/{review['id']}",json={"status":"teleported"}).status_code,422)

 def test_governance_sync_normalizes_naive_and_aware_timestamps(self):
  observed=datetime.now()-timedelta(minutes=1);since=datetime.now(timezone.utc)-timedelta(hours=1)
  row={"source_module":"web_exposure","source_record_type":"finding","source_record_id":7,"category":"web_exposure","title":"Local candidate","evidence":"Bounded","severity":"medium","confidence":"medium","route":"/findings/7","observed_at":observed}
  with patch("app.modules.governance.risk_service.ADAPTERS",{"web_exposure":lambda db,limit:[row]}):response=self.client.post("/api/governance/risks/sync",params={"source_module":"web_exposure","since":since.isoformat()})
  self.assertEqual(response.status_code,200,response.text);body=response.json();self.assertEqual(body["safe_errors"],[]);self.assertEqual(body["risks_created"],1)

 def test_governance_risk_frontend_route_parameter_contract(self):
  source=(Path(__file__).parents[2]/"frontend"/"src"/"pages"/"governance"/"RiskDetails.tsx").read_text(encoding="utf-8")
  self.assertIn("const { riskId } = useParams()",source)
  self.assertNotIn("Number(id)",source)

 def test_integrated_correlation_governance_source_preservation(self):
  now=datetime.now(timezone.utc)
  with self.factory() as db:
   target=models.Target(name="Integrated target",base_url="https://example.com",domain="example.com",environment="test",authorization_confirmed=True);db.add(target);db.flush()
   scan=models.Scan(target_id=target.id,profile="safe",status="completed");db.add(scan);db.flush();db.add(models.Finding(scan_id=scan.id,target_id=target.id,title="Bounded exposure",category="headers",severity="high",confidence="high",evidence="Local",description="Local",remediation="Review"))
   assessment=models.ApiAssessment(name="Integrated API",source_type="openapi",status="completed",base_url="https://example.com");db.add(assessment);db.flush();db.add(models.ApiFinding(assessment_id=assessment.id,title="API review",description="Local",evidence="Local",impact="Review",remediation="Review",source="openapi",fingerprint="integrated-api",severity="high",confidence="high"))
   db.add(models.SocAlert(rule_id=1,title="Integrated alert",description="Local",severity="high",confidence="high",first_seen=now,last_seen=now,event_count=1,correlation_key="integrated",evidence_summary="Local",fingerprint="integrated-soc",status="open"))
   db.add(models.DocumentFinding(analysis_id=1,rule_code="DOC-INT",title="Document review",category="active_content",severity="high",confidence="high",description="Local",evidence_summary="Local",technical_impact="Review",possible_business_impact="Review",remediation="Review",fingerprint="integrated-doc"))
   db.add(models.PhishingFinding(analysis_id=1,rule_code="PH-INT",title="Phishing review",category="credential",severity="high",confidence="high",description="Local",evidence_summary="Local",technical_impact="Review",possible_business_impact="Review",remediation="Review",fingerprint="integrated-phish"));db.commit()
   before=(db.query(models.Target).count(),db.query(models.ApiAssessment).count(),db.query(models.SocAlert).count(),db.query(models.DocumentFinding).count(),db.query(models.PhishingFinding).count())
  first_sync=self.client.post("/api/correlation/entities/sync").json();self.assertGreater(first_sync["observations_created"],0);self.assertEqual(self.client.post("/api/correlation/entities/sync").json()["observations_created"],0)
  first_run=self.client.post("/api/correlation/matches/run").json();self.assertGreater(first_run["matches_created"],0);self.assertEqual(self.client.post("/api/correlation/matches/run").json()["matches_created"],0)
  match=self.client.get("/api/correlation/matches").json()[0];case=self.client.post(f"/api/correlation/matches/{match['id']}/create-case").json();cid=case["id"]
  self.client.post(f"/api/correlation/cases/{cid}/notes",json={"note_text":"Integrated review"});past=(now-timedelta(hours=1)).isoformat();self.client.post(f"/api/correlation/cases/{cid}/actions",json={"title":"Review","due_at":past});self.assertGreaterEqual(self.client.post("/api/correlation/actions/check-overdue").json()["notifications_created"],1);self.assertEqual(self.client.post("/api/correlation/actions/check-overdue").json()["notifications_created"],0)
  self.assertGreater(self.client.post("/api/governance/frameworks/seed").json()["frameworks_created"],0);self.assertEqual(self.client.post("/api/governance/frameworks/seed").json()["frameworks_created"],0)
  governance=self.client.post("/api/governance/risks/sync").json();self.assertGreater(governance["risks_created"],0);self.assertEqual(self.client.post("/api/governance/risks/sync").json()["risks_created"],0)
  self.assertGreater(self.client.post("/api/governance/mappings/generate").json()["candidates_created"],0);self.assertEqual(self.client.post("/api/governance/mappings/generate").json()["candidates_created"],0)
  risk=self.client.get("/api/governance/risks").json()["items"][0];framework=self.client.get("/api/governance/frameworks").json()[0];package=self.client.post("/api/governance/evidence-packages",json={"title":"Integrated evidence","framework_id":framework["id"]}).json();self.assertEqual(self.client.post(f"/api/governance/evidence-packages/{package['id']}/items",json={"source_module":"governance","source_record_type":"risk","source_record_id":risk["id"]}).status_code,200)
  self.assertEqual(self.client.post(f"/api/correlation/cases/{cid}/reports").status_code,200);self.assertEqual(self.client.post("/api/governance/reports/executive").status_code,200)
  self.assertEqual(self.client.delete(f"/api/governance/risks/{risk['id']}").json()["source_records_deleted"],0);self.assertEqual(self.client.delete(f"/api/correlation/cases/{cid}").status_code,200)
  with self.factory() as db:after=(db.query(models.Target).count(),db.query(models.ApiAssessment).count(),db.query(models.SocAlert).count(),db.query(models.DocumentFinding).count(),db.query(models.PhishingFinding).count())
  self.assertEqual(after,before)


if __name__=="__main__":unittest.main()
