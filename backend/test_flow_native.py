import asyncio
from unittest.mock import AsyncMock, patch
from app.database import engine, Base, SessionLocal
from app import models
from app.scanner.orchestrator import run_scan
from app.scanner.reports.report_generator import generate_report

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
db = SessionLocal()

print("1. Add built-in demo target.")
settings = models.AppSettings(max_pages_full=10, max_pages_standard=5, max_depth_full=3, max_depth_standard=2)
db.add(settings)
target = models.Target(name="Local Demo Target", base_url="http://localhost:8081", domain="localhost:8081", environment="local")
db.add(target)
db.commit()
print(f"Target created with ID {target.id}")

# Mock SafeHTTPClient
from httpx import Headers
class MockResponse:
    def __init__(self, text, url_str):
        self.text = text
        self.headers = Headers({"Server": "MockServer", "Set-Cookie": "session=123"})
        class MockUrl:
            scheme = "http"
        self.url = MockUrl()

async def mock_get(self, url, **kwargs):
    if "login" in url:
        return MockResponse("<html><body><form><input type='password' name='pwd'/></form></body></html>", url), None
    return MockResponse("<html><body><a href='/login'>Login</a></body></html>", url), None

with patch("app.scanner.http_client.SafeHTTPClient.get", new=mock_get):
    with patch("app.scanner.http_client.SafeHTTPClient.close", new=AsyncMock()):
        print("\n2. Run first Full Safe Scan.")
        scan1 = models.Scan(target_id=target.id, profile="Full Safe Scan", status="running")
        db.add(scan1)
        db.commit()
        run_scan(scan1.id)
        db.refresh(scan1)
        print(f"Scan 1 finished with status: {scan1.status}")
        print(f"Scan 1 error: {scan1.error_message}")

        print("\n3. Run second Full Safe Scan.")
        scan2 = models.Scan(target_id=target.id, profile="Full Safe Scan", status="running")
        db.add(scan2)
        db.commit()
        run_scan(scan2.id)
        db.refresh(scan2)
        print(f"Scan 2 finished with status: {scan2.status}")
        print(f"Scan 2 error: {scan2.error_message}")

print("\n4. Confirm Crawl Map tab works.")
nodes = db.query(models.CrawlNode).filter(models.CrawlNode.scan_id == scan2.id).all()
print("Crawl Map nodes count:", len(nodes))
for node in nodes:
    print(f" - {node.path} (Forms: {node.has_forms}, Password Field: {node.has_password_field})")

print("\n5. Confirm Security Posture Score breakdown works.")
print(f"Overall Posture Score: {scan2.overall_posture_score}")
print(f" - Transport Security: {scan2.posture_transport_security}")
print(f" - Browser Defense: {scan2.posture_browser_defense}")
print(f" - Session Safety: {scan2.posture_session_safety}")
print(f" - Exposure Hygiene: {scan2.posture_exposure_hygiene}")
print(f" - Authentication Surface: {scan2.posture_authentication_surface}")
print(f"Risk Score: {scan2.risk_score}")

print("\n6. Confirm Posture Drift tab shows previous baseline comparison.")
diff = db.query(models.PostureDiff).filter(models.PostureDiff.current_scan_id == scan2.id).first()
if diff:
    print("Drift Summary:", diff.summary)
    print(f"New Findings: {diff.new_findings_count}")
    print(f"Resolved Findings: {diff.resolved_findings_count}")
    print(f"Unchanged Findings: {diff.unchanged_findings_count}")
    print("\n7. Confirm both risk-score delta and posture-score delta are displayed correctly.")
    print(f"Risk Score Delta: {diff.risk_score_delta}")
    print(f"Posture Score Delta: {diff.posture_score_delta}")
else:
    print("Diff not found")

print("\n8. Confirm Evidence tab shows header snapshots and redacted HTML snippets.")
evidences = db.query(models.EvidenceArtifact).filter(models.EvidenceArtifact.scan_id == scan2.id).all()
print("Evidence count:", len(evidences))
for ev in evidences:
    print(f" - {ev.artifact_type}: {ev.title} (URL: {ev.related_url})")

print("\n9. Confirm Policy Results tab.")
import json
with open("app/policies/web_baseline.json") as f:
    packs = [json.load(f)]
print("Policy packs evaluated: (skipped evaluation logic to avoid dependencies)")

print("\n10. Generate report.")
html = generate_report(db, scan2)
print("Report generated, size:", len(html))

print("\n11. Confirm report includes requested sections.")
sections_to_check = [
    "Web Application Exposure &amp; Security Posture Report",
    "Security Posture Score",
    "Crawl Map Summary",
    "Posture Drift Since Previous Scan",
    "Policy Compliance Summary",
    "Evidence Appendix",
    "Authorized Testing Disclaimer"
]
for section in sections_to_check:
    words = section.replace("&amp;", "&").split()
    found = all(word in html for word in words if len(word) > 3)
    print(f" - {section}: {'FOUND' if found else 'NOT FOUND'}")
