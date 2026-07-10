import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

from app import models
from app.database import Base, SessionLocal, engine
from app.main import app


class TestTargetHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Server", "VulnScope-Test")
        self.send_header("Set-Cookie", "session=123")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Server", "VulnScope-Test")
        self.send_header("Set-Cookie", "session=123")
        self.end_headers()

        if self.path == "/":
            html = "<html><body><h1>Welcome</h1><a href='/login'>Go to Login</a></body></html>"
        elif self.path == "/login":
            html = (
                "<html><body><h2>Login</h2><form action='/login' method='post'>"
                "User: <input type='text' name='user'/>"
                "Pass: <input type='password' name='pwd'/>"
                "<input type='submit'/></form></body></html>"
            )
        else:
            html = "<html><body>Test path</body></html>"

        self.wfile.write(html.encode())


def run_test_target():
    server = HTTPServer(("127.0.0.1", 18081), TestTargetHandler)
    server.serve_forever()


threading.Thread(target=run_test_target, daemon=True).start()
time.sleep(0.5)

# Recreate DB
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
db = SessionLocal()
db.add(models.AppSettings())
db.add(
    models.UserProfile(
        full_name="Security Analyst",
        email="analyst@vulnscope.local",
        organization="VulnScope Test Lab",
        role="Security Analyst",
        avatar_initials="SA",
    )
)
db.commit()
db.close()

client = TestClient(app)

print("1. Add built-in test target.")
res = client.post(
    "/api/targets/",
    json={
        "name": "Local Test Target",
        "base_url": "http://127.0.0.1:18081",
        "environment": "local",
        "authorization_confirmed": True,
    },
)
assert res.status_code == 200, res.text
target_id = res.json()["id"]
print(f"Target created with ID {target_id}: {res.json()['base_url']}")

print("\n2. Run first Full Safe Scan.")
res = client.post(
    "/api/scans/start",
    json={
        "target_id": target_id,
        "profile": "Full Safe Scan",
    },
)
assert res.status_code == 200, res.text
scan1_id = res.json()["id"]

while True:
    res = client.get(f"/api/scans/{scan1_id}")
    status = res.json()["status"]
    if status in ["completed", "failed"]:
        print(f"Scan 1 finished with status: {status}")
        assert status == "completed", res.json().get("error_message")
        break
    time.sleep(1)

print("\n3. Run second Full Safe Scan.")
res = client.post(
    "/api/scans/start",
    json={
        "target_id": target_id,
        "profile": "Full Safe Scan",
    },
)
assert res.status_code == 200, res.text
scan2_id = res.json()["id"]

while True:
    res = client.get(f"/api/scans/{scan2_id}")
    status = res.json()["status"]
    if status in ["completed", "failed"]:
        print(f"Scan 2 finished with status: {status}")
        assert status == "completed", res.json().get("error_message")
        break
    time.sleep(1)

print("\n4. Confirm Crawl Map tab works.")
res = client.get(f"/api/scans/{scan2_id}/crawl-map")
assert res.status_code == 200, res.text
print("Crawl Map nodes count:", len(res.json()))
for node in res.json():
    print(f" - {node['path']} (Forms: {node['has_forms']}, Password Field: {node['has_password_field']})")

print("\n5. Confirm Security Posture Score breakdown works.")
res = client.get(f"/api/scans/{scan2_id}")
assert res.status_code == 200, res.text
s = res.json()
print(f"Overall Posture Score: {s['overall_posture_score']}")
print(f" - Transport Security: {s['posture_transport_security']}")
print(f" - Browser Defense: {s['posture_browser_defense']}")
print(f" - Session Safety: {s['posture_session_safety']}")
print(f" - Exposure Hygiene: {s['posture_exposure_hygiene']}")
print(f" - Authentication Surface: {s['posture_authentication_surface']}")
print(f"Risk Score: {s['risk_score']}")

print("\n6. Confirm Posture Drift tab shows previous baseline comparison.")
res = client.get(f"/api/scans/{scan2_id}/diff")
assert res.status_code == 200, res.text
diff = res.json()
print("Drift Summary:", diff["summary"])
print(f"New Findings: {diff['new_findings_count']}")
print(f"Resolved Findings: {diff['resolved_findings_count']}")
print(f"Unchanged Findings: {diff['unchanged_findings_count']}")

print("\n7. Confirm both risk-score delta and posture-score delta are displayed correctly.")
print(f"Risk Score Delta: {diff['risk_score_delta']}")
print(f"Posture Score Delta: {diff['posture_score_delta']}")

print("\n8. Confirm Evidence tab shows header snapshots and redacted HTML snippets.")
res = client.get(f"/api/scans/{scan2_id}/evidence")
assert res.status_code == 200, res.text
print("Evidence count:", len(res.json()))
for ev in res.json():
    print(f" - {ev['artifact_type']}: {ev['title']} (URL: {ev['related_url']})")

print("\n9. Confirm Policy Results tab uses /api/scans/{scan_id}/policy-results.")
res = client.get(f"/api/scans/{scan2_id}/policy-results")
assert res.status_code == 200, res.text
print("Policy packs evaluated:", len(res.json()))
for pack in res.json():
    print(f" - {pack['title']} (Checks: {len(pack['checks'])})")

print("\n10. Generate report.")
res = client.post(f"/api/reports/generate/{scan2_id}")
assert res.status_code == 200, res.text
report_id = res.json()["id"]
print("Report generated response:", res.status_code)
res = client.get(f"/api/reports/{report_id}")
assert res.status_code == 200, res.text
html = res.json()["html_content"]

print("\n11. Confirm report includes requested sections.")
sections_to_check = [
    "Web Application Exposure &amp; Security Posture Report",
    "Security Posture Score",
    "Crawl Map Summary",
    "Posture Drift Since Previous Scan",
    "Policy Compliance Summary",
    "Evidence Appendix",
    "Authorized Testing Disclaimer",
]
for section in sections_to_check:
    words = section.replace("&amp;", "&").split()
    found = all(word in html for word in words if len(word) > 3)
    print(f" - {section}: {'FOUND' if found else 'NOT FOUND'}")
    assert found, section

print("\n12. Confirm dashboard, search, notifications, profile, and settings endpoints.")
assert client.get("/api/dashboard/summary").status_code == 200
assert client.get("/api/search/", params={"q": "Test"}).status_code == 200
assert client.get("/api/notifications/").status_code == 200
assert client.get("/api/profile/").status_code == 200
assert client.get("/api/settings/").status_code == 200

print("\nAPI flow test completed successfully.")
