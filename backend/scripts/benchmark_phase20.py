"""Regression-oriented in-process benchmark for representative safe read APIs."""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
os.environ["DATABASE_URL"] = "sqlite://"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.database import Base, get_db
from app.main import app
from tests.access_helpers import authenticate_admin


REQUESTS_PER_ENDPOINT = 15
MAX_REQUEST_MS = 2_000.0
MAX_PAYLOAD_BYTES = 2_000_000


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def main() -> int:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    factory = sessionmaker(bind=engine)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    Base.metadata.create_all(engine)
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    authenticate_admin(client, factory)
    with factory() as db:
        target = models.Target(name="Benchmark target", base_url="https://example.test", domain="example.test", environment="synthetic", authorization_confirmed=True)
        db.add(target)
        db.flush()
        scan = models.Scan(target_id=target.id, profile="safe", status="completed", total_findings=10, risk_score=10.0, overall_posture_score=90)
        db.add(scan)
        db.flush()
        for index in range(10):
            db.add(models.Finding(scan_id=scan.id, target_id=target.id, title=f"Synthetic finding {index}", category="benchmark", severity="low", confidence="medium", evidence="Synthetic local evidence", description="Synthetic", impact="Review", remediation="Review", affected_url="https://example.test", risk_score=10.0))
        for index in range(25):
            db.add(models.Notification(title=f"Synthetic notification {index}", message="Synthetic local benchmark record", type="info", entity_type="scan", entity_id=scan.id))
        db.commit()
        scan_id = scan.id

    endpoints = {
        "public_liveness": "/api/health/live",
        "dashboard_summary": "/api/dashboard/summary",
        "notification_list": "/api/notifications/?limit=50",
        "global_search": "/api/search/?q=Synthetic",
        "findings_list": f"/api/scans/{scan_id}/findings",
        "cases_list": "/api/correlation/cases",
        "ioc_list": "/api/threat-intel/indicators",
        "detector_list": "/api/detections/rules",
        "vulnerability_list": "/api/vulnerability-management/vulnerabilities",
        "analytics_anomaly_list": "/api/analytics/anomalies",
        "production_readiness": "/api/operations/production/readiness",
    }
    results = {}
    failed = []
    for name, path in endpoints.items():
        client.get(path)
        elapsed: list[float] = []
        payload_sizes: list[int] = []
        statuses: list[int] = []
        for _ in range(REQUESTS_PER_ENDPOINT):
            started = time.perf_counter_ns()
            response = client.get(path)
            elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
            payload_sizes.append(len(response.content))
            statuses.append(response.status_code)
        item = {
            "requests": REQUESTS_PER_ENDPOINT,
            "status": sorted(set(statuses)),
            "median_ms": round(statistics.median(elapsed), 3),
            "p95_ms": round(percentile(elapsed, 0.95), 3),
            "maximum_ms": round(max(elapsed), 3),
            "maximum_payload_bytes": max(payload_sizes),
        }
        results[name] = item
        if item["status"] != [200] or item["maximum_ms"] > MAX_REQUEST_MS or item["maximum_payload_bytes"] > MAX_PAYLOAD_BYTES:
            failed.append(name)
    payload = {
        "environment": f"in-process TestClient; {platform.system()} {platform.release()}; Python {platform.python_version()}; SQLite in-memory",
        "dataset": {"targets": 1, "scans": 1, "findings": 10, "notifications": 25, "other_lists": "empty unless server defaults apply"},
        "thresholds": {"maximum_request_ms": MAX_REQUEST_MS, "maximum_payload_bytes": MAX_PAYLOAD_BYTES, "purpose": "severe local regression detection; not a production SLA"},
        "results": results,
        "failed": failed,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    client.close()
    app.dependency_overrides.clear()
    engine.dispose()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
