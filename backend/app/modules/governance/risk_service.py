import hashlib,time
from datetime import datetime,timezone
from app import models
from .adapters import ADAPTERS
from .redaction import redact,internal_route
from .scoring import calculate
from .service import activity,notify_once

RANK={"info":0,"low":1,"medium":2,"high":3,"critical":4}
DEFAULTS={"critical":(5,5),"high":(4,4),"medium":(3,3),"low":(2,2),"info":(1,1)}


def synchronize(db,source_module=None,minimum_source_severity="info",since=None,maximum_records_per_module=500,include_existing_closed_source_records=False):
    started=time.perf_counter();stats={"source_records_examined":0,"candidates_generated":0,"risks_created":0,"risks_updated":0,"risks_reused":0,"sources_created":0,"sources_reused":0,"records_skipped":0,"safe_errors":[],"per_module_counts":{}}
    for adapter_name,adapter in ADAPTERS.items():
        if source_module and source_module not in {adapter_name,"incident_case"}:continue
        try:rows=adapter(db,min(maximum_records_per_module,1000))
        except Exception as exc:stats["safe_errors"].append(redact(exc,200));continue
        for row in rows:
            if source_module and row["source_module"]!=source_module:continue
            stats["source_records_examined"]+=1;stats["per_module_counts"][row["source_module"]]=stats["per_module_counts"].get(row["source_module"],0)+1
            try:
                if RANK.get(row["severity"],1)<RANK.get(minimum_source_severity,0) or (since and row["observed_at"]<since):stats["records_skipped"]+=1;continue
                stats["candidates_generated"]+=1;risk_key="SYNC-"+hashlib.sha256(f"{row['source_module']}:{row['source_record_type']}:{row['source_record_id']}".encode()).hexdigest()[:20];risk=db.query(models.GovernanceRisk).filter_by(risk_key=risk_key).first();is_new=not risk
                if not risk:
                    likelihood,impact=DEFAULTS.get(row["severity"],(3,3));values=calculate(likelihood,impact,assessed=False);risk=models.GovernanceRisk(risk_key=risk_key,title=redact(row["title"],300),description=redact(row["evidence"],4000),origin="incident_case" if row["source_module"]=="incident_case" else "correlation_match" if row["source_record_type"]=="correlation_match" else "synchronized_candidate",category=row["category"],confidence=row["confidence"],**values);db.add(risk);db.flush();stats["risks_created"]+=1
                elif risk.status=="closed" and not include_existing_closed_source_records:stats["risks_reused"]+=1
                else:stats["risks_updated"]+=1
                fingerprint=hashlib.sha256(f"{risk.id}:{row['source_module']}:{row['source_record_type']}:{row['source_record_id']}".encode()).hexdigest();source=db.query(models.GovernanceRiskSource).filter_by(risk_id=risk.id,source_fingerprint=fingerprint).first()
                if source:stats["sources_reused"]+=1
                else:db.add(models.GovernanceRiskSource(risk_id=risk.id,source_module=row["source_module"],source_record_type=row["source_record_type"],source_record_id=row["source_record_id"],source_internal_route=internal_route(row["route"]),source_fingerprint=fingerprint,title_snapshot=redact(row["title"],500),evidence_snapshot=redact(row["evidence"],1500),source_severity=row["severity"],source_confidence=row["confidence"],observed_at=row["observed_at"]));stats["sources_created"]+=1
                db.flush();risk.source_record_count=db.query(models.GovernanceRiskSource).filter_by(risk_id=risk.id).count();risk.source_module_count=len({x.source_module for x in risk.sources})
                if is_new and risk.severity in {"high","critical"}:notify_once(db,"High Governance Risk Identified",f"{risk.risk_key}: {risk.title}","warning","governance_risk",risk.id)
                if is_new and risk.appetite_status=="exceeds_appetite":notify_once(db,"Governance Risk Exceeds Appetite",risk.risk_key,"danger","governance_risk",risk.id)
            except Exception as exc:stats["records_skipped"]+=1;stats["safe_errors"].append(redact(exc,200))
    activity(db,"governance_risk_sync",f"Governance synchronization created {stats['risks_created']} risks and {stats['sources_created']} sources.");db.commit();stats["duration_ms"]=round((time.perf_counter()-started)*1000,2);return stats
