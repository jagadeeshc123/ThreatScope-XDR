import io,json,os,socket,subprocess,unittest,webbrowser
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from pypdf import PdfWriter
from pypdf.generic import ArrayObject,DictionaryObject,NameObject,TextStringObject
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import models
from app.database import Base,get_db
from app.main import app
from app.modules.document_threats.redaction import redact,sanitize_url

def pdf_bytes(markers=(),uri=None,attachment=None,metadata=None,encrypted=False,multiple_eof=False):
    writer=PdfWriter();writer.add_blank_page(width=612,height=792)
    if uri:writer.add_uri(0,uri,(10,10,300,30))
    if attachment:writer.add_attachment(attachment[0],attachment[1])
    if metadata:writer.add_metadata(metadata)
    root=writer._root_object
    if "javascript" in markers:root[NameObject("/OpenAction")]=DictionaryObject({NameObject("/S"):NameObject("/JavaScript"),NameObject("/JS"):TextStringObject("inert-static-marker")})
    if "open_action" in markers:root[NameObject("/OpenAction")]=DictionaryObject({NameObject("/S"):NameObject("/GoTo")})
    if "aa" in markers:root[NameObject("/AA")]=DictionaryObject({NameObject("/WC"):DictionaryObject({NameObject("/S"):NameObject("/GoTo")})})
    if "launch" in markers:root[NameObject("/OpenAction")]=DictionaryObject({NameObject("/S"):NameObject("/Launch"),NameObject("/F"):TextStringObject("inert-demo.exe")})
    if "acroform" in markers:root[NameObject("/AcroForm")]=DictionaryObject({NameObject("/Fields"):ArrayObject()})
    if "xfa" in markers:root[NameObject("/AcroForm")]=DictionaryObject({NameObject("/Fields"):ArrayObject(),NameObject("/XFA"):TextStringObject("inert-xfa-reference")})
    if "signature" in markers:root[NameObject("/StaticSignatureMarker")]=NameObject("/Sig")
    if encrypted:writer.encrypt("authorized-test-password")
    stream=io.BytesIO();writer.write(stream);data=stream.getvalue()
    if multiple_eof:data+=b"\n% inert incremental marker\nstartxref\n0\n%%EOF\n"
    return data

class DocumentThreatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool);cls.factory=sessionmaker(autocommit=False,autoflush=False,bind=cls.engine)
        def override():
            db=cls.factory()
            try:yield db
            finally:db.close()
        app.dependency_overrides[get_db]=override;cls.client=TestClient(app)
    @classmethod
    def tearDownClass(cls):cls.client.close();app.dependency_overrides.clear();cls.engine.dispose()
    def setUp(self):
        Base.metadata.drop_all(self.engine);Base.metadata.create_all(self.engine)
        with self.factory() as db:db.add(models.AppSettings());db.add(models.UserProfile(full_name="Doc Analyst",email="doc@example.test",organization="ThreatScope",role="Analyst",avatar_initials="DA"));db.commit()
    def upload(self,data,name="sample.pdf"):
        return self.client.post("/api/document-threats/analyses",files={"file":(name,data,"application/pdf")})

    def test_empty_overview_and_upload_validation(self):
        overview=self.client.get("/api/document-threats/overview").json();self.assertEqual(overview["total_analyses"],0);self.assertEqual(overview["recent_analyses"],[])
        self.assertEqual(self.upload(b"", "empty.pdf").status_code,422)
        self.assertEqual(self.upload(b"not pdf","fake.pdf").status_code,422)
        self.assertEqual(self.upload(pdf_bytes(),"fake.txt").status_code,422)
        self.assertEqual(self.upload(pdf_bytes(),"../escape.pdf").status_code,422)
        self.assertEqual(self.upload(b"%PDF-1.7\nbroken","broken.pdf").status_code,422)
        self.assertEqual(self.upload(b"%PDF-1.7\n"+b"x"*(15*1024*1024),"large.pdf").status_code,413)

    def test_minimal_identity_structure_duplicate_and_no_retention(self):
        data=pdf_bytes(metadata={"/Title":"Safe synthetic document"});response=self.upload(data,"safe sample.pdf");self.assertEqual(response.status_code,200,response.text);item=response.json()
        self.assertEqual(item["page_count"],1);self.assertEqual(len(item["file_hash"]),64);self.assertEqual(item["classification"],"low_observed_risk");self.assertEqual(item["analysis_status"],"completed")
        duplicate=self.upload(data,"safe-copy.pdf").json();self.assertTrue(duplicate["duplicate_existing"]);self.assertEqual(duplicate["id"],item["id"])
        with self.factory() as db:self.assertEqual(db.query(models.DocumentAnalysis).count(),1);self.assertFalse(any(hasattr(row,"original_bytes") for row in db.query(models.DocumentAnalysis).all()))
        self.assertFalse(Path("safe sample.pdf").exists())

    def test_actions_forms_signature_and_incremental_indicators(self):
        cases=[(("javascript",),"has_javascript","DOC-001"),(("open_action",),"has_open_action","DOC-002"),(("aa",),"has_additional_actions","DOC-002"),(("launch",),"has_launch_action","DOC-003"),(("acroform",),"has_acroform","DOC-008"),(("xfa",),"has_xfa","DOC-008"),(("signature",),None,"DOC-015")]
        for index,(markers,flag,rule) in enumerate(cases):
            result=self.upload(pdf_bytes(markers=markers),f"action-{index}.pdf");self.assertEqual(result.status_code,200,result.text)
            if flag:self.assertTrue(result.json()[flag])
            findings=self.client.get(f"/api/document-threats/analyses/{result.json()['id']}/findings").json();self.assertIn(rule,{f["rule_code"] for f in findings})
        inc=self.upload(pdf_bytes(multiple_eof=True),"incremental.pdf").json();codes={f["rule_code"] for f in self.client.get(f"/api/document-threats/analyses/{inc['id']}/findings").json()};self.assertIn("DOC-010",codes)

    def test_uri_sanitization_and_no_external_resolution(self):
        uri="https://user:pass@192.0.2.10/path?token=fake-secret&mode=review";item=self.upload(pdf_bytes(uri=uri),"uri.pdf").json();indicators=self.client.get(f"/api/document-threats/analyses/{item['id']}/indicators").json();serialized=json.dumps(indicators)
        self.assertNotIn("user:pass",serialized);self.assertNotIn("fake-secret",serialized);self.assertIn("%5BREDACTED%5D",serialized);self.assertTrue(any(i["indicator_type"]=="ip" for i in indicators))
        unsafe=self.upload(pdf_bytes(uri="file:///C:/inert/demo.txt"),"unsafe-uri.pdf").json();codes={f["rule_code"] for f in self.client.get(f"/api/document-threats/analyses/{unsafe['id']}/findings").json()};self.assertIn("DOC-007",codes)
        puny=self.upload(pdf_bytes(uri="https://xn--demo-9ta.example/review"),"punycode.pdf");self.assertEqual(puny.status_code,200)

    def test_embedded_artifacts_metadata_only_and_no_download(self):
        cases=[("notes.txt",b"inert text"),("invoice.pdf.exe",b"MZ-not-executable-demo"),("review.js",b"inert marker"),("sheet.xlsm",b"inert office marker")]
        found=[]
        for index,attachment in enumerate(cases):
            item=self.upload(pdf_bytes(attachment=attachment),f"embedded-{index}.pdf").json();arts=self.client.get(f"/api/document-threats/analyses/{item['id']}/embedded-artifacts").json();self.assertEqual(len(arts),1);self.assertEqual(len(arts[0]["sha256"]),64);found.append((attachment[0],arts[0]))
            self.assertEqual(self.client.get(f"/api/document-threats/embedded-artifacts/{arts[0]['id']}/download").status_code,404)
        self.assertTrue(found[1][1]["executable_like"]);self.assertTrue(found[2][1]["script_like"]);self.assertTrue(found[3][1]["office_macro_like"])
        with self.factory() as db:self.assertFalse(any(hasattr(a,"bytes") or hasattr(a,"file_path") for a in db.query(models.DocumentEmbeddedArtifact).all()))

    def test_encryption_is_limited_not_high_risk(self):
        item=self.upload(pdf_bytes(encrypted=True),"encrypted.pdf").json();self.assertEqual(item["analysis_status"],"limited");self.assertTrue(item["is_encrypted"]);self.assertLess(item["risk_score"],20);self.assertNotEqual(item["classification"],"high_risk")

    def test_redaction_risk_fingerprints_overview_search_notifications_activity(self):
        metadata={"/Title":"password=fake-password","/Author":"authorization=Bearer fake-token","/Subject":"urgent payment verify your account"}
        item=self.upload(pdf_bytes(markers=("javascript","aa"),uri="javascript:inert-marker",attachment=("invoice.pdf.exe",b"inert"),metadata=metadata),"risky.pdf").json();self.assertGreaterEqual(item["risk_score"],45);self.assertIn("not a definitive malware verdict",item["methodology"].lower());self.assertNotIn("is malware",item["methodology"].lower())
        detail=self.client.get(f"/api/document-threats/analyses/{item['id']}").json();serialized=json.dumps(detail);self.assertNotIn("fake-password",serialized);self.assertNotIn("fake-token",serialized);self.assertIn("[REDACTED]",serialized)
        fingerprints=[f["fingerprint"] for f in detail["findings"]];self.assertEqual(len(fingerprints),len(set(fingerprints)))
        overview=self.client.get("/api/document-threats/overview").json();self.assertEqual(overview["total_analyses"],1);self.assertGreater(overview["total_findings"],0);self.assertTrue(overview["recent_activity"])
        dashboard=self.client.get("/api/dashboard/summary").json();self.assertEqual(dashboard["document_total_analyses"],1);self.assertGreater(dashboard["document_high_critical_findings"],0)
        search=self.client.get("/api/search/",params={"q":"risky"}).json();self.assertEqual(len(search["document_analyses"]),1)
        notifications=self.client.get("/api/notifications/").json();self.assertTrue(any(n["entity_type"]=="document_analysis" for n in notifications))

    def test_report_sections_escaping_and_download(self):
        item=self.upload(pdf_bytes(uri="https://example.test/?password=fake-secret",metadata={"/Title":"<script>inert</script>"}),"report.pdf").json();report=self.client.post(f"/api/document-threats/analyses/{item['id']}/reports");self.assertEqual(report.status_code,200,report.text);body=report.json()["html_content"]
        required=["Executive Summary","File Identity and SHA-256","Analysis Scope","Risk Classification","PDF Structure Summary","Active Content Indicators","External Link and URI Review","Embedded Artifact Review","Forms and Action Review","Metadata and Structural Anomalies","Text-Based Risk Indicators","Detailed Findings","Recommended Analyst Actions","Methodology and Limitations","Safe Static-Analysis Disclaimer"]
        for section in required:self.assertIn(section,body)
        self.assertNotIn("fake-secret",body);self.assertNotIn("<script>inert</script>",body);self.assertIn("no document content was executed",body)
        download=self.client.get(f"/api/document-threats/reports/{report.json()['id']}/download");self.assertEqual(download.status_code,200);self.assertIn("attachment",download.headers["content-disposition"])

    def test_safety_interfaces_never_called(self):
        fail=RuntimeError("forbidden interface")
        with patch("socket.create_connection",side_effect=fail),patch("socket.getaddrinfo",side_effect=fail),patch("subprocess.run",side_effect=fail),patch("subprocess.Popen",side_effect=fail),patch("os.system",side_effect=fail),patch("webbrowser.open",side_effect=fail),patch("httpx.get",side_effect=fail),patch("httpx.post",side_effect=fail),patch("urllib.request.urlopen",side_effect=fail):
            item=self.upload(pdf_bytes(markers=("javascript",),uri="https://192.0.2.20/inert",attachment=("demo.exe",b"inert")),"safety.pdf");self.assertEqual(item.status_code,200,item.text)
            self.assertEqual(self.client.post(f"/api/document-threats/analyses/{item.json()['id']}/reports").status_code,200)
            self.assertEqual(self.client.get("/api/search/",params={"q":"safety"}).status_code,200);self.assertEqual(self.client.get("/api/dashboard/summary").status_code,200)

if __name__=="__main__":unittest.main()
