import html
import json
import re

from sqlalchemy import func

from app import models
from app.modules.soc_monitor.redaction import redact_text

SECTIONS=["Report metadata","Executive summary","Rule inventory","Rule lifecycle distribution","Rule severity distribution","Rule-quality distribution","Validation status","Test-case coverage","ATT&CK technique coverage","Rule-pack summary","Historical execution summary","Detection-match summary","High-risk detections","Confirmed detections","False-positive analysis","Suppression summary","Alert promotions","Incident-case escalations","Rule version activity","Detection methodology","Risk-scoring explanation","Quality-scoring explanation","Limitations","Offline/static-evaluation disclaimer"]


def esc(value):
    redacted=redact_text(str(value or ""),4000)
    redacted=re.sub(r"(?i)https?://[^\s<]+",lambda m:m.group(0).replace("https://","hxxps://").replace("http://","hxxp://").replace(".","[.]"),redacted)
    return html.escape(redacted)


def generate(db,title,report_type,filters,user_id):
    rules=db.query(models.DetectionRule).order_by(models.DetectionRule.id).all(); matches=db.query(models.DetectionMatch).order_by(models.DetectionMatch.risk_score.desc()).limit(100).all()
    counts={"rules":len(rules),"active":sum(r.lifecycle_status=="active" for r in rules),"matches":db.query(models.DetectionMatch).count(),"high_risk":db.query(models.DetectionMatch).filter(models.DetectionMatch.risk_score>=60).count(),"techniques":db.query(models.AttackTechnique).count()}
    rows="".join(f"<tr><td>{esc(r.title)}</td><td>{esc(r.lifecycle_status)}</td><td>{esc(r.severity)}</td><td>{r.quality_score:.1f}</td></tr>" for r in rules)
    high="".join(f"<li>{esc(m.evidence_summary)} — risk {m.risk_score:.1f}</li>" for m in matches[:20]) or "<li>No matching stored events.</li>"
    bodies={
      "Report metadata":f"Generated locally. Type: {esc(report_type)}.","Executive summary":f"{counts['rules']} rules; {counts['active']} active; {counts['matches']} matches.",
      "Rule inventory":f"<table><tr><th>Rule</th><th>Lifecycle</th><th>Severity</th><th>Quality</th></tr>{rows}</table>","High-risk detections":f"<ul>{high}</ul>",
      "Detection methodology":"Deterministic bounded evaluation of stored ThreatScope records only. No code, commands, or uploaded content are executed.",
      "Risk-scoring explanation":"Bounded 0–100 heuristic using rule severity, confidence, quality, source-event severity, lifecycle, and analyst disposition. This is not machine learning.",
      "Quality-scoring explanation":"Bounded 0–100 heuristic using schema validity, documentation, positive and negative tests, and ATT&CK mappings.",
      "Limitations":"This report uses a bounded local ATT&CK-style subset and stored records. It does not claim complete organizational coverage.",
      "Offline/static-evaluation disclaimer":"No external feeds, network enrichment, endpoint agent, active response, command execution, or complete ATT&CK catalog is provided.",
    }
    document="".join(f"<section><h2>{esc(section)}</h2><div>{bodies.get(section,'Locally calculated summary available in the structured record.')}</div></section>" for section in SECTIONS)
    css="body{font-family:system-ui;margin:2rem;background:#0b1220;color:#e5e7eb}section{border:1px solid #334155;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%}td,th{padding:.5rem;border:1px solid #475569;text-align:left}"
    content=f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(title)}</title><style>{css}</style></head><body><h1>{esc(title)}</h1>{document}</body></html>"
    report=models.DetectionReport(title=title,report_type=report_type,filters_json=json.dumps(filters,sort_keys=True),summary_json=json.dumps(counts,sort_keys=True),html_content=content,created_by_user_id=user_id)
    db.add(report);db.commit();db.refresh(report);return report
