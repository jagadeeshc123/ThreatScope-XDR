import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


DISCLAIMER = "Synthetic demo events — no live systems contacted."
SCENARIOS = {"normal_activity", "single_source_brute_force", "distributed_password_spray", "repeated_401_403", "suspicious_admin_access", "path_probing", "blocked_indicator_activity", "mixed_demo"}
USERS = ["demo-alice", "demo-bob", "demo-analyst", "demo-admin", "demo-service"]


def ensure_utc(value: datetime | None) -> datetime:
    value = value or datetime(2025, 1, 1, tzinfo=timezone.utc)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def doc_ip(network: int, host: int) -> str:
    prefixes = {0: "192.0.2", 1: "198.51.100", 2: "203.0.113"}
    return f"{prefixes[network % 3]}.{max(1, min(254, host))}"


def generate(scenario: str, count: int, seed: int, start_time: datetime | None = None) -> List[Dict[str, Any]]:
    if scenario not in SCENARIOS:
        raise ValueError("Unsupported simulator scenario")
    rng = random.Random(seed)
    start = ensure_utc(start_time)
    events = []
    for index in range(count):
        effective = scenario
        if scenario == "mixed_demo":
            effective = ["normal_activity", "single_source_brute_force", "distributed_password_spray", "repeated_401_403", "suspicious_admin_access", "path_probing", "blocked_indicator_activity"][index % 7]
        event = {"timestamp": (start + timedelta(seconds=index * 8)).isoformat(), "severity": "info", "message": "Synthetic local demonstration event", "scenario": effective}
        if effective == "normal_activity":
            event.update(event_type="web_request", source_ip=doc_ip(rng.randrange(3), rng.randint(10, 50)), username=rng.choice(USERS[:3]), method="GET", path=rng.choice(["/", "/health", "/docs"]), status_code=200, outcome="success")
        elif effective == "single_source_brute_force":
            event.update(event_type="authentication", source_ip="192.0.2.66", username=rng.choice(USERS[:3]), action="login", outcome="failure", severity="medium")
        elif effective == "distributed_password_spray":
            event.update(event_type="authentication", source_ip=doc_ip(index % 3, 80 + index % 40), username="demo-alice", action="login", outcome="failure", severity="medium")
        elif effective == "repeated_401_403":
            event.update(event_type="web_request", source_ip="203.0.113.45", method="GET", path=f"/protected/{index % 3}", status_code=401 if index % 2 else 403, outcome="denied", severity="low")
        elif effective == "suspicious_admin_access":
            if index % 4 == 3:
                event.update(event_type="administrative_action", source_ip="192.0.2.90", username="demo-admin", method="GET", path="/admin/settings", status_code=200, outcome="success", severity="high")
            else:
                event.update(event_type="authentication", source_ip="192.0.2.90", username="demo-admin", action="login", outcome="failure", severity="medium")
        elif effective == "path_probing":
            event.update(event_type="web_request", source_ip="198.51.100.77", method="GET", path=f"/missing/demo-{index}", status_code=404, outcome="failure", severity="low")
        else:
            event.update(event_type="security_control", source_ip="203.0.113.99", action="application_blocklist_match", outcome="blocked", severity="high")
        events.append(event)
    return events
