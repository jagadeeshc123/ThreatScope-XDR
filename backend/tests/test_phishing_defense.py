import io,json,os,socket,subprocess,unittest,webbrowser,smtplib,imaplib,poplib,tempfile
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import models
from app.database import Base,get_db
from app.main import app
from app.modules.phishing_defense.model_service import info,predict
from app.modules.phishing_defense.url_analyzer import analyze_url

FIX=Path(__file__).parent/"fixtures"/"phishing_defense"
class PhishingDefenseTests(unittest.TestCase):
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
 def setUp(self):Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine);self.client.get("/api/phishing-defense/overview")
 def email(self,**changes):
  payload={"subject":"Scheduled review","sender":"Team <team@example.com>","body_text":"Please attend the scheduled project review.","body_html":"","headers":"Message-ID: <safe@example.com>\nAuthentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass"};payload.update(changes);return self.client.post("/api/phishing-defense/analyses/email-text",json=payload)

 def test_empty_overview_validation_and_model_info(self):
  o=self.client.get("/api/phishing-defense/overview").json();self.assertEqual(o["total_analyses"],0);self.assertEqual(o["recent_analyses"],[])
  self.assertEqual(self.client.post("/api/phishing-defense/analyses/email-text",json={"subject":"","sender":"","body_text":""}).status_code,422)
  self.assertEqual(self.client.post("/api/phishing-defense/analyses/url",json={"url":""}).status_code,422)
  meta=self.client.get("/api/phishing-defense/model-info");self.assertEqual(meta.status_code,200);self.assertIn("TF-IDF",meta.json()["model_type"]);self.assertIsNone(meta.json()["demonstration_metrics"]);self.assertEqual(info()["model_version"],meta.json()["model_version"])

 def test_pasted_email_header_html_url_and_duplicate(self):
  r=self.email(subject="URGENT verify account",sender="Example <sender@example.com>",reply_to="review@example.net",body_text="Send password and OTP immediately. Payment gift card required.",body_html="<form><input type='password'><a href='https://192.0.2.20/login?token=FAKE_TEST_SECRET'>https://example.com/login</a></form>",headers="Return-Path: <bounce@example.org>\nAuthentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\nMessage-ID: <x@example.com>")
  self.assertEqual(r.status_code,200,r.text);x=r.json();self.assertGreaterEqual(x["final_risk_score"],45);detail=self.client.get(f"/api/phishing-defense/analyses/{x['id']}").json();codes={f["rule_code"] for f in detail["findings"]};self.assertTrue({"PHISH-001","PHISH-002","PHISH-003","PHISH-012","PHISH-013","PHISH-021"}.issubset(codes));self.assertNotIn("FAKE_TEST_SECRET",json.dumps(detail));self.assertEqual(detail["sender_display_redacted"],"Example");self.assertFalse(any("<a" in i["display_value_redacted"] for i in detail["indicators"]))
  duplicate=self.email(subject="URGENT verify account",sender="Example <sender@example.com>",reply_to="review@example.net",body_text="Send password and OTP immediately. Payment gift card required.",body_html="<form><input type='password'><a href='https://192.0.2.20/login?token=FAKE_TEST_SECRET'>https://example.com/login</a></form>",headers="Return-Path: <bounce@example.org>\nAuthentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail\nMessage-ID: <x@example.com>").json();self.assertTrue(duplicate["duplicate_existing"]);self.assertEqual(duplicate["id"],x["id"])

 def test_eml_attachment_metadata_no_retention_and_validation(self):
  data=(FIX/"inert-lure.eml").read_bytes();r=self.client.post("/api/phishing-defense/analyses/eml",files={"file":("inert-lure.eml",data,"message/rfc822")});self.assertEqual(r.status_code,200,r.text);x=r.json();self.assertEqual(len(x["source_hash"]),64);detail=self.client.get(f"/api/phishing-defense/analyses/{x['id']}").json();self.assertEqual(len(detail["attachments"]),1);a=detail["attachments"][0];self.assertTrue(a["double_extension"]);self.assertTrue(a["executable_like"]);self.assertEqual(len(a["sha256"]),64)
  with self.factory() as db:self.assertFalse(any(hasattr(row,"raw_email") or hasattr(row,"body_text") or hasattr(row,"attachment_bytes") or hasattr(row,"file_path") for row in db.query(models.PhishingAnalysis).all()))
  self.assertEqual(self.client.get(f"/api/phishing-defense/attachments/{a['id']}/download").status_code,404);self.assertEqual(self.client.post("/api/phishing-defense/analyses/eml",files={"file":("bad.txt",b"test","text/plain")}).status_code,422);self.assertEqual(self.client.post("/api/phishing-defense/analyses/eml",files={"file":("../bad.eml",data,"message/rfc822")}).status_code,422);self.assertEqual(self.client.post("/api/phishing-defense/analyses/eml",files={"file":("large.eml",b"a"*(5*1024*1024+1),"message/rfc822")}).status_code,413)

 def test_url_lexical_redaction_and_benign_behavior(self):
  benign=self.client.post("/api/phishing-defense/analyses/url",json={"url":"https://example.com/help"}).json();self.assertLess(benign["final_risk_score"],45)
  risky=self.client.post("/api/phishing-defense/analyses/url",json={"url":"https://user:pass@192.0.2.44:8080/login?token=FAKE_TEST_SECRET"}).json();detail=self.client.get(f"/api/phishing-defense/analyses/{risky['id']}").json();serialized=json.dumps(detail);self.assertNotIn("user:pass",serialized);self.assertNotIn("FAKE_TEST_SECRET",serialized);self.assertIn("%5BREDACTED%5D",serialized);self.assertTrue(any(f["rule_code"]=="PHISH-008" for f in detail["findings"]));self.assertTrue(analyze_url("https://micros0ft.example/login")["flags"]["lookalike"])

 def test_disposition_watchlist_report_dashboard_search_notifications(self):
  x=self.email(subject="Urgent gift card",body_text="Buy gift cards immediately and keep this secret.").json();original=x["final_risk_score"];updated=self.client.patch(f"/api/phishing-defense/analyses/{x['id']}",json={"analyst_disposition":"phishing","analyst_notes":"token=fake-note-secret"});self.assertEqual(updated.status_code,200);self.assertEqual(updated.json()["final_risk_score"],original);self.assertNotIn("fake-note-secret",updated.json()["analyst_notes"])
  w=self.client.post("/api/phishing-defense/watchlist",json={"indicator_type":"domain","normalized_value":"example.net","reason":"Local test only","source_analysis_id":x["id"]});self.assertEqual(w.status_code,200);wid=w.json()["id"];matched=self.client.post("/api/phishing-defense/analyses/url",json={"url":"https://example.net/inert"}).json();matched_findings=self.client.get(f"/api/phishing-defense/analyses/{matched['id']}/findings").json();self.assertTrue(any(f["rule_code"]=="PHISH-024" for f in matched_findings));self.assertEqual(self.client.patch(f"/api/phishing-defense/watchlist/{wid}",json={"status":"expired"}).status_code,200);self.assertEqual(self.client.patch(f"/api/phishing-defense/watchlist/{wid}",json={"status":"active"}).status_code,200);self.assertIn("does not block",self.client.delete(f"/api/phishing-defense/watchlist/{wid}").json()["disclaimer"])
  report=self.client.post(f"/api/phishing-defense/analyses/{x['id']}/reports");self.assertEqual(report.status_code,200,report.text);html=report.json()["html_content"];sections=report.json()["summary_json"]["sections"];self.assertEqual(len(sections),16);self.assertNotIn("<a ",html);self.assertIn("not a definitive",html);self.assertNotIn("fake-note-secret",html);self.assertEqual(self.client.get(f"/api/phishing-defense/reports/{report.json()['id']}/download").status_code,200)
  dash=self.client.get("/api/dashboard/summary").json();self.assertEqual(dash["phishing_total_analyses"],2);search=self.client.get("/api/search/",params={"q":"gift"}).json();self.assertTrue(search["phishing_analyses"] or search["phishing_findings"]);self.assertTrue(any(n["entity_type"].startswith("phishing_") for n in self.client.get("/api/notifications/").json()))

 def test_classifier_deterministic_synthetic_only(self):
  a=predict("verify password immediately"),predict("verify password immediately");self.assertEqual(a[0],a[1]);self.assertGreater(a[0]["probability"],predict("scheduled project meeting notes")["probability"]);raw=(Path(__file__).parents[1]/"app/modules/phishing_defense/rules/synthetic_training_data.csv").read_text();self.assertNotIn("http://",raw);self.assertNotIn("https://",raw);self.assertNotIn("@gmail.com",raw)

 def test_forbidden_interfaces_never_called(self):
  fail=RuntimeError("forbidden external or execution interface")
  with patch("socket.create_connection",side_effect=fail),patch("socket.getaddrinfo",side_effect=fail),patch("subprocess.run",side_effect=fail),patch("subprocess.Popen",side_effect=fail),patch("os.system",side_effect=fail),patch("webbrowser.open",side_effect=fail),patch("httpx.get",side_effect=fail),patch("httpx.post",side_effect=fail),patch("urllib.request.urlopen",side_effect=fail),patch("smtplib.SMTP",side_effect=fail),patch("imaplib.IMAP4",side_effect=fail),patch("poplib.POP3",side_effect=fail),patch("tempfile.NamedTemporaryFile",side_effect=fail),patch("tempfile.mkstemp",side_effect=fail):
   x=self.email(subject="Urgent verification",body_text="Verify password immediately at https://192.0.2.20/?token=FAKE").json();self.assertEqual(self.client.post(f"/api/phishing-defense/analyses/{x['id']}/reports").status_code,200);self.assertEqual(self.client.get("/api/dashboard/summary").status_code,200);self.assertEqual(self.client.get("/api/search/",params={"q":"Urgent"}).status_code,200)
 def test_unexpected_failure_is_bounded_and_notified(self):
  with patch("app.modules.phishing_defense.service.predict",side_effect=RuntimeError("token=FAKE_INTERNAL_DETAIL")):
   response=self.email(subject="Unique safe failure fixture")
  self.assertEqual(response.status_code,422);overview=self.client.get("/api/phishing-defense/overview").json();self.assertEqual(overview["failed_analyses"],1)
  with self.factory() as db:
   item=db.query(models.PhishingAnalysis).filter_by(analysis_status="failed").one();self.assertNotIn("FAKE_INTERNAL_DETAIL",item.error_summary)
  self.assertTrue(any(n["title"]=="Phishing Analysis Failed" for n in self.client.get("/api/notifications/").json()))
if __name__=="__main__":unittest.main()
