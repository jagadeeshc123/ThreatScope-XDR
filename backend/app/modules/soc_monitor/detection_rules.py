import json
from pathlib import Path

from sqlalchemy.orm import Session

from app import models


CATALOG = Path(__file__).parent / "rules" / "default_detection_rules.json"


def seed_default_rules(db: Session):
    rules = json.loads(CATALOG.read_text(encoding="utf-8"))
    changed = False
    for item in rules:
        if db.query(models.SocDetectionRule).filter(models.SocDetectionRule.rule_code == item["rule_code"]).first():
            continue
        db.add(models.SocDetectionRule(**{**item, "conditions_json": json.dumps(item["conditions_json"], sort_keys=True), "enabled": True, "is_default": True}))
        changed = True
    if changed:
        db.commit()

