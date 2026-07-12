import hashlib, json
from datetime import datetime, timezone
from fastapi import HTTPException
from app import models
from .redaction import redact

DISCLAIMER = "ThreatScope XDR provides local evidence organization and framework mapping. It does not perform certification, legal assessment, regulatory approval, or an external compliance audit."


def now(): return datetime.now(timezone.utc)


def dump(obj):
    if obj is None: return None
    data={c.name:getattr(obj,c.name) for c in obj.__table__.columns}
    for key in ("summary_json","metrics_json","snapshot_json"):
        if key in data and isinstance(data[key],str):
            try:data[key.removesuffix("_json")]=json.loads(data[key])
            except Exception:data[key.removesuffix("_json")]=data[key]
    return data


def activity(db, action, message, entity_id=None):
    db.add(models.SocActivity(action=action,message=redact(message,500),entity_type="governance",entity_id=entity_id))


def notify_once(db,title,message,kind,entity_type,entity_id):
    title=redact(title,240);message=redact(message,500)
    item=db.query(models.Notification).filter_by(title=title,message=message,entity_type=entity_type,entity_id=entity_id).first()
    if item:return False
    db.add(models.Notification(title=title,message=message,type=kind,entity_type=entity_type,entity_id=entity_id));return True


def get_or_404(db, model, object_id, label):
    item=db.query(model).filter_by(id=object_id).first()
    if not item:raise HTTPException(404,f"{label} not found")
    return item


def key(prefix, value):return f"{prefix}-{hashlib.sha256(str(value).encode()).hexdigest()[:16]}"
