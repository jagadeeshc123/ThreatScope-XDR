import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from app.database import engine, Base, SessionLocal
from app import models
from app.scanner.orchestrator import run_scan
from app.scanner.reports.report_generator import generate_report
import json

# --- Demo Target Server ---
class DemoTargetHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'VulnScope-Demo')
        self.send_header('Set-Cookie', 'session=123')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', 'VulnScope-Demo')
        self.send_header('Set-Cookie', 'session=123') # Insecure cookie
        self.end_headers()
        
        if self.path == '/':
            html = "<html><body><h1>Welcome</h1><a href='/login'>Go to Login</a></body></html>"
        elif self.path == '/login':
            html = "<html><body><h2>Login</h2><form action='/login' method='post'>User: <input type='text' name='user'/><br/>Pass: <input type='password' name='pwd'/><br/><input type='submit'/></form></body></html>"
        else:
            html = "<html><body>Not Found</body></html>"
            
        self.wfile.write(html.encode())

def run_server():
    server = HTTPServer(('127.0.0.1', 8081), DemoTargetHandler)
    server.serve_forever()

server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
time.sleep(1) # wait for server to start

# --- Database & Setup ---
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
db = SessionLocal()

print("1. DB reset complete.")
settings = models.AppSettings(max_pages_full=10, max_pages_standard=5, max_depth_full=3, max_depth_standard=2)
db.add(settings)
target = models.Target(name="Local Demo Target", base_url="http://127.0.0.1:8081", domain="127.0.0.1:8081", environment="local")
db.add(target)
db.commit()
print(f"2. Created demo target: {target.base_url}")

# --- Scans ---
print("\n--- Running First Full Safe Scan ---")
scan1 = models.Scan(target_id=target.id, profile="Full Safe Scan", status="running")
db.add(scan1)
db.commit()
run_scan(scan1.id)
db.refresh(scan1)
print(f"Scan 1 Status: {scan1.status}")

print("\n--- Running Second Full Safe Scan ---")
scan2 = models.Scan(target_id=target.id, profile="Full Safe Scan", status="running")
db.add(scan2)
db.commit()
run_scan(scan2.id)
db.refresh(scan2)
print(f"Scan 2 Status: {scan2.status}")

# --- Output Results ---
print("\n=== VERIFICATION RESULTS ===")
findings = db.query(models.Finding).filter(models.Finding.scan_id == scan2.id).all()
print(f"\n[Findings Count]: {len(findings)}")
for f in findings:
    print(f" - [{f.severity.upper()}] {f.title} ({f.category})")

print(f"\n[Risk Score]: {scan2.risk_score}")

print("\n[Posture Score Breakdown]")
print(f" - Overall Posture Score: {scan2.overall_posture_score}")
print(f" - Transport Security: {scan2.posture_transport_security}")
print(f" - Browser Defense: {scan2.posture_browser_defense}")
print(f" - Session Safety: {scan2.posture_session_safety}")
print(f" - Exposure Hygiene: {scan2.posture_exposure_hygiene}")
print(f" - Authentication Surface: {scan2.posture_authentication_surface}")

print("\n[Crawl Nodes]")
nodes = db.query(models.CrawlNode).filter(models.CrawlNode.scan_id == scan2.id).all()
for node in nodes:
    print(f" - {node.path} (Forms: {node.has_forms}, Password Field: {node.has_password_field})")

print("\n[Posture Drift Deltas (After 2 Scans)]")
diff = db.query(models.PostureDiff).filter(models.PostureDiff.current_scan_id == scan2.id).first()
if diff:
    print(f" - Summary: {diff.summary}")
    print(f" - Risk Score Delta: {diff.risk_score_delta}")
    print(f" - Posture Score Delta: {diff.posture_score_delta}")
else:
    print(" - No drift found.")

print("\n[Evidence Artifacts]")
evidences = db.query(models.EvidenceArtifact).filter(models.EvidenceArtifact.scan_id == scan2.id).all()
for ev in evidences:
    print(f" - {ev.artifact_type}: {ev.title}")
    
print("\n[Policy Results]")
from app.routers.scans import get_scan_policy_results
results = get_scan_policy_results(scan2.id, db)
for pack in results:
    print(f" - {pack['title']}")
    for check in pack['checks']:
        print(f"   -> {check['title']}: {check['status']} (Violations: {len(check['violating_findings'])})")

print("\n[Report Generation]")
html = generate_report(db, scan2)
print(f" - Report Generated Successfully (Size: {len(html)} bytes)")

sections_to_check = [
    "Web Application Exposure &amp; Security Posture Report",
    "Security Posture Score",
    "Crawl Map Summary",
    "Posture Drift Since Previous Scan",
    "Policy Compliance Summary",
    "Evidence Appendix",
    "Authorized Testing Disclaimer"
]
print(" - Validating Sections:")
for section in sections_to_check:
    words = section.replace("&amp;", "&").split()
    found = all(word in html for word in words if len(word) > 3)
    print(f"   * {section}: {'FOUND' if found else 'NOT FOUND'}")
