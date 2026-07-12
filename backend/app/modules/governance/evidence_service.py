import hashlib
from datetime import datetime,timezone
from fastapi import HTTPException
from app import models
from .adapters import ADAPTERS
from .redaction import redact,internal_route


def resolve(db,module,record_type,record_id):
    if module=="governance" and record_type=="risk":
        x=db.query(models.GovernanceRisk).filter_by(id=record_id).first()
        if x:return {"title":x.title,"evidence":x.description,"route":f"/governance/risks/{x.id}","observed_at":x.updated_at,"risk_id":x.id}
    for adapter in ADAPTERS.values():
        try:
            for row in adapter(db,1000):
                if row["source_module"]==module and row["source_record_type"]==record_type and row["source_record_id"]==record_id:return row|{"risk_id":None}
        except Exception:continue
    if module=="incident_case" and record_type=="incident_evidence":
        x=db.query(models.IncidentEvidence).filter_by(id=record_id).first()
        if x:return {"title":x.title_snapshot,"evidence":x.evidence_snapshot,"route":x.source_internal_route,"observed_at":x.added_at,"risk_id":None}
    if module=="unified_correlation" and record_type=="unified_entity":
        x=db.query(models.UnifiedEntity).filter_by(id=record_id).first()
        if x:return {"title":x.display_value_redacted,"evidence":f"Risk score {x.risk_score}; {x.observation_count} local observations.","route":f"/correlation/entities/{x.id}","observed_at":x.last_seen_at,"risk_id":None}
    raise HTTPException(404,"Allowlisted local evidence source not found")


def add_item(db,package,payload):
    module=payload.get("source_module");record_type=payload.get("source_record_type");record_id=payload.get("source_record_id")
    allowed={"web_exposure","api_security","soc_monitor","document_threat","phishing_defense","unified_correlation","incident_case","governance"}
    if module not in allowed or not isinstance(record_id,int):raise HTTPException(422,"Unsupported evidence source")
    source=resolve(db,module,record_type,record_id);fingerprint=hashlib.sha256(f"{package.id}:{module}:{record_type}:{record_id}".encode()).hexdigest();existing=db.query(models.GovernanceEvidenceItem).filter_by(package_id=package.id,evidence_fingerprint=fingerprint).first()
    if existing:return existing,False
    item=models.GovernanceEvidenceItem(package_id=package.id,risk_id=payload.get("risk_id") or source.get("risk_id"),control_id=payload.get("control_id"),source_module=module,source_record_type=record_type,source_record_id=record_id,source_internal_route=internal_route(source.get("route")),title_snapshot=redact(source["title"],500),evidence_snapshot=redact(source["evidence"],1500),evidence_fingerprint=fingerprint,evidence_strength=payload.get("evidence_strength","moderate"),observed_at=source.get("observed_at") or datetime.now(timezone.utc));db.add(item);db.flush();package.item_count=len(package.items);return item,True
