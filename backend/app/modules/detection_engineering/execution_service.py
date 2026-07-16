import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.redaction import redact_text
from . import evaluator
from .models import DetectionExecution, DetectionMatch, DetectionRule, DetectionRulePackEntry, DetectionSuppression


def now(): return datetime.now(timezone.utc)


def _validate_nested_depth(value, depth=0):
    if depth > 6: raise ValueError("Test event exceeds maximum nesting depth of 6")
    if isinstance(value, dict):
        for nested in value.values(): _validate_nested_depth(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value: _validate_nested_depth(nested, depth + 1)


def synthetic_event(payload):
    if len(json.dumps(payload, default=str).encode()) > 65536: raise ValueError("Test event exceeds 64 KiB")
    if len(payload) > 64: raise ValueError("Test event exceeds 64 fields")
    _validate_nested_depth(payload)
    event={field: None for field in evaluator.ALLOWED_FIELDS}; event.update({evaluator.canonical_field(k): v for k,v in payload.items() if evaluator.canonical_field(k) in evaluator.ALLOWED_FIELDS})
    event.setdefault("tags", []); return event


def run_tests(db, rule):
    normalized=json.loads(rule.normalized_condition_json)
    results=[]
    for case in db.query(models.DetectionTestCase).filter_by(rule_id=rule.id,enabled=True).order_by(models.DetectionTestCase.id).all():
        try:
            matched, fields, selections=evaluator.evaluate(normalized,synthetic_event(json.loads(case.event_payload_json)))
            passed=matched == case.expected_match and (not case.expected_severity or case.expected_severity == rule.severity)
            results.append({"id":case.id,"name":case.name,"expected_match":case.expected_match,"actual_match":matched,"passed":passed,"matched_fields":fields,"matched_selections":selections})
        except (ValueError,TypeError,json.JSONDecodeError) as exc:
            results.append({"id":case.id,"name":case.name,"passed":False,"error":redact_text(str(exc),300)})
    return {"passed":bool(results) and all(x["passed"] for x in results),"total":len(results),"passed_count":sum(1 for x in results if x["passed"]),"results":results}


def _suppressed(db, rule_id, event):
    instant=now()
    query=db.query(DetectionSuppression).filter(DetectionSuppression.enabled.is_(True),or_(DetectionSuppression.rule_id.is_(None),DetectionSuppression.rule_id==rule_id))
    for item in query.order_by(DetectionSuppression.id).all():
        start=item.valid_from.replace(tzinfo=timezone.utc) if item.valid_from and item.valid_from.tzinfo is None else item.valid_from
        end=item.valid_until.replace(tzinfo=timezone.utc) if item.valid_until and item.valid_until.tzinfo is None else item.valid_until
        if start and instant < start or end and instant > end: continue
        conditions=json.loads(item.field_conditions_json)
        if all(str(event.get(evaluator.canonical_field(k)) or "").casefold() == str(v).casefold() for k,v in conditions.items()): return item
    return None


def risk_score(rule, event, suppressed=False):
    severity={"informational":5,"low":15,"medium":30,"high":45,"critical":60}.get(rule.severity,20)
    source_severity={"info":0,"informational":0,"low":3,"medium":7,"high":12,"critical":18}.get(str(event.get("event.severity") or "").lower(),0)
    score=severity + rule.confidence*.12 + rule.quality_score*.1 + source_severity + (5 if rule.lifecycle_status=="active" else 0)
    return round(max(0,min(100,score)),1)


def execute(db: Session, payload, user_id):
    rule_ids=list(payload.rule_ids)
    if payload.pack_id:
        rule_ids += [row.rule_id for row in db.query(DetectionRulePackEntry).filter_by(pack_id=payload.pack_id).all()]
    rules=db.query(DetectionRule).filter(DetectionRule.id.in_(sorted(set(rule_ids)))).order_by(DetectionRule.id).all()
    execution=DetectionExecution(rule_id=rules[0].id if len(rules)==1 else None,pack_id=payload.pack_id,status="running",mode="historical",requested_by_user_id=user_id,
        parameters_json=json.dumps(payload.model_dump(mode="json"),sort_keys=True)); db.add(execution); db.flush()
    query=db.query(models.SocEvent)
    if payload.start_at: query=query.filter(models.SocEvent.event_time>=payload.start_at)
    if payload.end_at: query=query.filter(models.SocEvent.event_time<=payload.end_at)
    events=query.order_by(models.SocEvent.event_time,models.SocEvent.id).limit(payload.maximum_records).all() if "soc" in payload.source_modules else []
    execution.records_scanned=len(events); matches=0; suppressed_count=0
    try:
        for rule in rules:
            normalized=json.loads(rule.normalized_condition_json)
            for source in events:
                event=evaluator.normalize_soc_event(source)
                if rule.source_module and rule.source_module not in {"soc","soc_monitor"}: continue
                matched,fields,_=evaluator.evaluate(normalized,event)
                if not matched: continue
                fingerprint=hashlib.sha256(f"{rule.id}:{rule.current_version}:soc:soc_event:{source.id}".encode()).hexdigest()
                existing=db.query(DetectionMatch).filter_by(fingerprint=fingerprint).first()
                if existing:
                    if existing.status=="false_positive": continue
                    matches += 1; continue
                suppression=_suppressed(db,rule.id,event); status="suppressed" if suppression else "new"
                if suppression: suppressed_count += 1
                timestamp=source.event_time
                evidence=redact_text(f"Rule {rule.title} matched stored SOC event {source.id}; fields: {', '.join(sorted(fields))}.",1000)
                db.add(DetectionMatch(execution_id=execution.id,rule_id=rule.id,rule_version=rule.current_version,source_module="soc",source_entity_type="soc_event",source_entity_id=source.id,
                    event_timestamp=timestamp,matched_fields_json=json.dumps(fields,sort_keys=True,default=str),evidence_summary=evidence,severity=rule.severity,confidence=rule.confidence,
                    risk_score=risk_score(rule,event,bool(suppression)),status=status,fingerprint=fingerprint)); matches += 1
            rule.last_executed_at=now()
        execution.matches_found=matches; execution.suppressed_matches=suppressed_count; execution.status="completed"; execution.completed_at=now(); db.commit(); db.refresh(execution)
    except Exception as exc:
        db.rollback(); execution=db.get(DetectionExecution,execution.id)
        if execution: execution.status="failed"; execution.errors_count=1; execution.error_summary=redact_text(str(exc),500); execution.completed_at=now(); db.commit()
        raise
    return execution
