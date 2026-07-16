import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.models import SocActivity
from app.modules.threat_intelligence.service import post_commit_event
from . import evaluator
from .models import AttackTechnique, DetectionRule, DetectionRulePack, DetectionRulePackEntry, DetectionRuleTechnique, DetectionRuleVersion


def now(): return datetime.now(timezone.utc)


def dump(item):
    if item is None: return None
    data={c.name: getattr(item, c.name) for c in item.__table__.columns if c.name != "html_content"}
    for key in list(data):
        if key.endswith("_json"):
            try: data[key[:-5]] = json.loads(data.pop(key) or "{}")
            except (TypeError, ValueError): data[key[:-5]] = None
    return data


def content_hash(content): return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def quality_score(rule, db):
    content=json.loads(rule.rule_content_json); validation=evaluator.validate(content)
    tests=db.query(models.DetectionTestCase).filter_by(rule_id=rule.id, enabled=True).all() if rule.id else []
    positives=sum(1 for t in tests if t.expected_match); negatives=len(tests)-positives
    score=20 + min(20, len(content.get("description", rule.description or ""))//20) + (15 if validation["valid"] else 0) + min(20, len(tests)*5) + (10 if positives else 0) + (10 if negatives else 0)
    if db.query(models.DetectionRuleTechnique).filter_by(rule_id=rule.id).count(): score += 5
    return max(0, min(100, score))


def add_version(db, rule, user_id, summary):
    version=DetectionRuleVersion(rule_id=rule.id, version_number=rule.current_version, change_summary=summary[:500], rule_content_json=rule.rule_content_json,
        normalized_condition_json=rule.normalized_condition_json, content_sha256=content_hash(json.loads(rule.rule_content_json)), created_by_user_id=user_id)
    db.add(version)


def create_rule(db, payload, user_id, *, system_owned=False, forced_uuid=None):
    content={"title": payload.get("title"), "description": payload.get("description", ""), "selections": payload["selections"], "condition": payload["condition"]}
    result=evaluator.validate(content)
    if not result["valid"]: raise HTTPException(422, result["errors"])
    requested=payload.get("lifecycle_status", "draft")
    if requested == "active": raise HTTPException(422, "Rules must pass validation and enabled tests before activation")
    rule=DetectionRule(rule_uuid=forced_uuid or payload.get("rule_uuid") or str(uuid.uuid4()), title=payload["title"], description=payload.get("description", ""),
        rule_format=payload.get("rule_format", "native"), lifecycle_status=requested, severity=payload.get("severity", "medium"), confidence=payload.get("confidence", 50),
        source_module=payload.get("source_module"), logsource_category=payload.get("logsource_category"), logsource_product=payload.get("logsource_product"), logsource_service=payload.get("logsource_service"),
        rule_content_json=json.dumps(content, sort_keys=True), normalized_condition_json=json.dumps(result["normalized"], sort_keys=True), false_positive_guidance=payload.get("false_positive_guidance"),
        tags_json=json.dumps(sorted({str(x)[:80] for x in payload.get("tags", [])})), enabled=False, system_owned=system_owned, current_version=1,
        owner_user_id=user_id, created_by_user_id=user_id)
    db.add(rule); db.flush(); add_version(db, rule, user_id, "Initial immutable version")
    map_techniques(db, rule.id, payload.get("technique_ids", []), user_id, "system_seed" if system_owned else "manual")
    rule.quality_score=quality_score(rule, db); return rule


def map_techniques(db, rule_id, external_ids, user_id, source="manual"):
    db.query(DetectionRuleTechnique).filter_by(rule_id=rule_id).delete()
    for external in sorted(set(external_ids)):
        technique=db.query(AttackTechnique).filter_by(external_id=str(external).upper()).first()
        if not technique: raise HTTPException(422, f"Unknown local ATT&CK technique: {external}")
        db.add(DetectionRuleTechnique(rule_id=rule_id, technique_id=technique.id, mapping_confidence=80, mapping_source=source, created_by_user_id=user_id))


TECHNIQUES=[
 ("T1059","Command and Scripting Interpreter","Execution"),("T1059.001","PowerShell","Execution"),("T1059.003","Windows Command Shell","Execution"),
 ("T1071","Application Layer Protocol","Command and Control"),("T1071.001","Web Protocols","Command and Control"),("T1110","Brute Force","Credential Access"),
 ("T1110.001","Password Guessing","Credential Access"),("T1110.003","Password Spraying","Credential Access"),("T1566","Phishing","Initial Access"),
 ("T1566.001","Spearphishing Attachment","Initial Access"),("T1566.002","Spearphishing Link","Initial Access"),("T1190","Exploit Public-Facing Application","Initial Access"),
 ("T1078","Valid Accounts","Defense Evasion"),("T1021","Remote Services","Lateral Movement"),("T1046","Network Service Discovery","Discovery"),
 ("T1087","Account Discovery","Discovery"),("T1082","System Information Discovery","Discovery"),("T1003","OS Credential Dumping","Credential Access"),
 ("T1055","Process Injection","Defense Evasion"),("T1105","Ingress Tool Transfer","Command and Control"),("T1204","User Execution","Execution"),
 ("T1204.001","Malicious Link","Execution"),("T1204.002","Malicious File","Execution"),("T1486","Data Encrypted for Impact","Impact"),
 ("T1490","Inhibit System Recovery","Impact"),("T1562","Impair Defenses","Defense Evasion"),("T1547","Boot or Logon Autostart Execution","Persistence"),
]


PACKS=[
 ("Authentication Monitoring","Stored authentication outcomes only", "Repeated failed authentication attempts", "high", {"failed":{"event.category":"authentication","event.outcome":"failure"}}, "failed", ["T1110"]),
 ("Web and API Threats","Stored web and API findings only", "High-severity API or web event", "high", {"web":{"event.severity":["high","critical"],"event.module":{"operator":"in","value":["soc","api_security","web_exposure"]}}}, "web", ["T1190"]),
 ("Phishing and Document Threats","Stored phishing and document findings only", "Suspicious phishing or document event", "high", {"phishing":{"event.category|contains":"phish"}}, "phishing", ["T1566"]),
 ("Threat Intelligence Matches","Stored IOC match events only", "Critical threat-intelligence match", "critical", {"ioc":{"threat.confidence|gte":75}}, "ioc", ["T1071"]),
]


def seed_catalog_and_packs(db: Session):
    user=db.query(models.UserAccount).filter_by(is_system_admin=True).order_by(models.UserAccount.id).first()
    if not user: return
    for external,name,tactic in TECHNIQUES:
        if not db.query(AttackTechnique).filter_by(external_id=external).first(): db.add(AttackTechnique(external_id=external,name=name,tactic=tactic,description="Local educational ATT&CK-style coverage mapping.",platform_tags_json="[]",system_owned=True))
    db.flush()
    for pack_name,desc,title,severity,selections,condition,techniques in PACKS:
        pack=db.query(DetectionRulePack).filter_by(name=pack_name).first()
        if not pack:
            pack=DetectionRulePack(name=pack_name,description=desc,version="1.0-demo",enabled=True,system_owned=True,created_by_user_id=user.id); db.add(pack); db.flush()
        rule_uuid="system-"+hashlib.sha256(pack_name.encode()).hexdigest()[:32]
        rule=db.query(DetectionRule).filter_by(rule_uuid=rule_uuid).first()
        if not rule:
            rule=create_rule(db,{"title":title,"description":desc+" Demonstration rule; no complete coverage claim.","selections":selections,"condition":condition,"severity":severity,"confidence":70,"tags":["threatscope-demo","system"],"technique_ids":techniques},user.id,system_owned=True,forced_uuid=rule_uuid)
        if not db.query(DetectionRulePackEntry).filter_by(pack_id=pack.id,rule_id=rule.id).first(): db.add(DetectionRulePackEntry(pack_id=pack.id,rule_id=rule.id,added_by_user_id=user.id))
    db.commit()
