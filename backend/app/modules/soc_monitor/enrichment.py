import json
from pathlib import Path

from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.service import add_activity, notify, validate_indicator


DISCLAIMER = "This enrichment uses local demonstration intelligence and is not live reputation data."
CATALOG = json.loads((Path(__file__).parent / "rules" / "mock_threat_intel.json").read_text(encoding="utf-8"))


def enrich(db: Session, alert_id: int | None, indicator_type: str, indicator_value: str):
    value = validate_indicator(indicator_type, indicator_value)
    if alert_id and not db.query(models.SocAlert.id).filter(models.SocAlert.id == alert_id).first():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="SOC alert not found")
    match = CATALOG.get(f"{indicator_type}:{value}", {"reputation": "unknown", "confidence": "low", "tags": [], "explanation": "No match in local mock intelligence."})
    result = models.SocThreatIntelResult(alert_id=alert_id, indicator_type=indicator_type, indicator_value=value, reputation=match["reputation"], confidence=match["confidence"], tags_json=json.dumps(match["tags"]), source_name="local_mock_intelligence", explanation=match["explanation"])
    db.add(result); db.flush()
    add_activity(db, "local_enrichment_completed", f"Local mock enrichment completed for {indicator_type} indicator.", "soc_enrichment", result.id)
    notify(db, "Local SOC Enrichment Completed", DISCLAIMER, "info", "soc_alert", alert_id)
    db.commit(); db.refresh(result)
    return result

