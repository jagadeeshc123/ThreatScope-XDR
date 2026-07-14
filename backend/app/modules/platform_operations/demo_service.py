from sqlalchemy.orm import Session

from app.models import Target

from .configuration_service import get_operations_config
from .maintenance_service import add_activity, notify
from .models import utcnow

DEMO_TARGET_NAME = "ThreatScope Synthetic Demo Target"
SCENARIOS = ["Web Exposure", "API Authorization", "SOC Detection", "Document Threat", "Phishing", "Correlation", "Incident Case", "Governance Evidence"]


def require_demo_mode():
    if not get_operations_config().demo_mode: raise ValueError("Demo mode is not enabled")


def status(db: Session) -> dict:
    target = db.query(Target).filter_by(name=DEMO_TARGET_NAME).first()
    return {"demo_mode": get_operations_config().demo_mode, "seeded": bool(target), "record_counts": {"web_targets": 1 if target else 0}, "last_seed_time": target.created_at if target else None, "scenarios": SCENARIOS, "synthetic_data": True, "local_target_restriction": True, "demo_users_created": False}


def seed(db: Session) -> dict:
    require_demo_mode(); target = db.query(Target).filter_by(name=DEMO_TARGET_NAME).first()
    created = False
    if not target:
        target = Target(name=DEMO_TARGET_NAME, base_url="http://192.0.2.10", domain="demo.example.test", authorization_confirmed=True, environment="synthetic-demo")
        db.add(target); db.flush(); created = True
    add_activity(db, "demo_seeded", "Deterministic synthetic demo environment seeded locally.", "operational_demo", target.id); notify(db,"Demo seed succeeded","Synthetic local demo records are ready.","success","operational_demo",target.id); db.commit()
    return {**status(db), "created": created, "credentials_created": False}


def reset(db: Session) -> dict:
    require_demo_mode(); targets = db.query(Target).filter_by(name=DEMO_TARGET_NAME, environment="synthetic-demo").all(); count = len(targets)
    for target in targets: db.delete(target)
    add_activity(db, "demo_reset", f"Removed {count} demo-owned target records; analyst records were preserved.", "operational_demo", None); notify(db,"Demo reset succeeded",f"Removed {count} demo-owned records and preserved analyst data.","success","operational_demo",None); db.commit()
    return {**status(db), "deleted_demo_records": count, "non_demo_records_preserved": True}
