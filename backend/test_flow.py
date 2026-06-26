import os
import time
import threading
import uvicorn
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app import models

# Recreate DB
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

client = TestClient(app)

print("1. Add built-in demo target.")
res = client.post("/api/targets/", json={
    "name": "Local Demo Target",
    "base_url": "http://localhost:8081",
    "environment": "local"
})
assert res.status_code == 200
target_id = res.json()["id"]
print(f"Target created with ID {target_id}: {res.json()['base_url']}")

print("\n2. Run first Full Safe Scan.")
res = client.post("/api/scans/start", json={
    "target_id": target_id,
    "profile": "Full Safe Scan"
})
assert res.status_code == 200
scan1_id = res.json()["id"]

# Wait for scan 1 to complete
while True:
    res = client.get(f"/api/scans/{scan1_id}")
    status = res.json()["status"]
    if status in ["completed", "failed"]:
        print(f"Scan 1 finished with status: {status}")
        break
    time.sleep(1)

print("\n3. Run second Full Safe Scan.")
res = client.post("/api/scans/start", json={
    "target_id": target_id,
    "profile": "Full Safe Scan"
})
assert res.status_code == 200
scan2_id = res.json()["id"]

# Wait for scan 2 to complete
while True:
    res = client.get(f"/api/scans/{scan2_id}")
    status = res.json()["status"]
    if status in ["completed", "failed"]:
        print(f"Scan 2 finished with status: {status}")
        break
    time.sleep(1)

print("\n4. Confirm Crawl Map tab works.")
res = client.get(f"/api/scans/{scan2_id}/crawl-map")
print("Crawl Map nodes count:", len(res.json()))
for node in res.json():
    print(f" - {node['path']} (Forms: {node['has_forms']}, Password Field: {node['has_password_field']})")

print("\n5. Confirm Security Posture Score breakdown works.")
res = client.get(f"/api/scans/{scan2_id}")
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
if res.status_code == 200:
    diff = res.json()
    print("Drift Summary:", diff["summary"])
    print(f"New Findings: {diff['new_findings_count']}")
    print(f"Resolved Findings: {diff['resolved_findings_count']}")
    print(f"Unchanged Findings: {diff['unchanged_findings_count']}")
    print("\n7. Confirm both risk-score delta and posture-score delta are displayed correctly.")
    print(f"Risk Score Delta: {diff['risk_score_delta']}")
    print(f"Posture Score Delta: {diff['posture_score_delta']}")
else:
    print("Diff not found or error:", res.status_code)

print("\n8. Confirm Evidence tab shows header snapshots and redacted HTML snippets.")
res = client.get(f"/api/scans/{scan2_id}/evidence")
print("Evidence count:", len(res.json()))
for ev in res.json():
    print(f" - {ev['artifact_type']}: {ev['title']} (URL: {ev['related_url']})")

print("\n9. Confirm Policy Results tab uses /api/scans/{scan_id}/policy-results.")
res = client.get(f"/api/scans/{scan2_id}/policy-results")
print("Policy packs evaluated:", len(res.json()))
for pack in res.json():
    print(f" - {pack['title']} (Checks: {len(pack['checks'])})")

print("\n10. Generate report.")
res = client.post(f"/api/reports/generate/{scan2_id}")
print("Report generated response:", res.status_code)
res = client.get(f"/api/reports/1")
html = res.json()["html_content"]

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
    # use replace amp because HTML templating might escape it, or we just check for words
    words = section.replace("&amp;", "&").split()
    found = all(word in html for word in words if len(word) > 3)
    print(f" - {section}: {'FOUND' if found else 'NOT FOUND'}")
