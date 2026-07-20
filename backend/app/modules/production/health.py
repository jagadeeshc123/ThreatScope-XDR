from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.version import SCHEMA_IDENTIFIER

from .config import get_runtime_config
from .models import ProductionRuntimeMetadata
from .preflight import run_preflight


def liveness() -> dict[str, str]:
    return {"status": "alive"}


def production_readiness(db: Session) -> dict:
    config = get_runtime_config()
    result = run_preflight(config=config, create_directories=False, db=db)
    try:
        db.execute(text("SELECT 1"))
        stored = db.query(ProductionRuntimeMetadata).filter_by(key="schema_identifier").first()
        schema_ok = bool(stored and stored.value == SCHEMA_IDENTIFIER)
    except Exception:
        schema_ok = False
    checks = list(result["checks"])
    checks.append({"name": "schema", "state": "pass" if schema_ok else "failure", "summary": "Schema metadata is current." if schema_ok else "Schema metadata is unavailable or incompatible.", "remediation_code": "schema_upgrade"})
    failures = sum(item["state"] == "failure" for item in checks)
    warnings = sum(item["state"] == "warning" for item in checks)
    return {"ready": failures == 0, "status": "ready" if failures == 0 else "not_ready", "failure_count": failures, "warning_count": warnings, "checks": checks}
