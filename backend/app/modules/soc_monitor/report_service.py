import html
import json
from collections import Counter

from sqlalchemy.orm import Session

from app import models
from app.modules.soc_monitor.redaction import redact_text
from app.modules.soc_monitor.service import add_activity, notify


TITLE = "SOC Monitoring and Alert Correlation Report"


def esc(value):
    return html.escape(redact_text(str(value or ""), 4000))


def generate(db: Session, report_type: str = "soc_summary"):
    sources = db.query(models.SocLogSource).order_by(models.SocLogSource.name).all()
    imports = db.query(models.SocLogImport).order_by(models.SocLogImport.created_at.desc()).all()
    alerts = db.query(models.SocAlert).order_by(models.SocAlert.first_seen).all()
    enrichments = db.query(models.SocThreatIntelResult).order_by(models.SocThreatIntelResult.created_at).all()
    blocklist = db.query(models.SocBlocklistEntry).order_by(models.SocBlocklistEntry.created_at).all()
    severity = Counter(alert.severity for alert in alerts)
    summary = {"total_events": db.query(models.SocEvent).count(), "total_sources": len(sources), "total_imports": len(imports), "total_alerts": len(alerts), "alerts_by_severity": dict(severity), "enrichments": len(enrichments), "blocklist_entries": len(blocklist)}
    source_rows = "".join(f"<tr><td>{esc(source.name)}</td><td>{esc(source.source_type)}</td><td>{source.event_count}</td><td>{'Enabled' if source.enabled else 'Disabled'}</td></tr>" for source in sources) or "<tr><td colspan='4'>No sources configured.</td></tr>"
    alert_rows = "".join(f"<article><h3>{esc(alert.title)}</h3><p><strong>{esc(alert.severity.upper())}</strong> · {esc(alert.status)} · {alert.event_count} events</p><p>{esc(alert.description)}</p><pre>{esc(alert.evidence_summary)}</pre></article>" for alert in alerts) or "<p>No alerts generated.</p>"
    enrichment_rows = "".join(f"<li>{esc(item.indicator_type)} {esc(item.indicator_value)}: {esc(item.reputation)} ({esc(item.source_name)}) — {esc(item.explanation)}</li>" for item in enrichments) or "<li>No local enrichment records.</li>"
    block_rows = "".join(f"<li>{esc(item.indicator_type)} {esc(item.indicator_value)} — {esc(item.status)}: {esc(item.reason)}</li>" for item in blocklist) or "<li>No simulated blocklist actions.</li>"
    sections = [
        ("Executive Summary", f"{summary['total_events']} events were evaluated and {summary['total_alerts']} alerts are recorded."),
        ("Monitoring Scope", "Local imported and synthetic demonstration security events stored in this application."),
        ("Log Sources", f"<table><thead><tr><th>Source</th><th>Type</th><th>Events</th><th>Status</th></tr></thead><tbody>{source_rows}</tbody></table>"),
        ("Event Ingestion Summary", f"{len(imports)} imports; {sum(item.accepted_events for item in imports)} accepted and {sum(item.rejected_events for item in imports)} rejected rows."),
        ("Detection Methodology", "Deterministic, deque-based bounded sliding windows evaluate enabled local rules in chronological order."),
        ("Alert Summary", f"{len(alerts)} alerts across {len(severity)} severity levels."),
        ("Alert Severity Distribution", " · ".join(f"{esc(key)}: {value}" for key, value in sorted(severity.items())) or "No alerts."),
        ("Alert Timeline", "".join(f"<p>{esc(alert.first_seen)} — {esc(alert.title)}</p>" for alert in alerts) or "<p>No timeline entries.</p>"),
        ("Detailed Alerts", alert_rows),
        ("Correlated Evidence", "Evidence summaries are redacted and reference normalized local event records; unredacted payloads are never included."),
        ("Local Threat-Intelligence Enrichment", f"<p>This enrichment uses local demonstration intelligence and is not live reputation data.</p><ul>{enrichment_rows}</ul>"),
        ("Local Blocklist Actions", f"<p>Local simulation only — this does not modify any real firewall or network control.</p><ul>{block_rows}</ul>"),
        ("Investigation Recommendations", "Validate event context, identity ownership, application behavior, and approved response procedures before escalation."),
        ("Methodology and Limitations", "Events may be imported or synthetic. No live infrastructure was contacted. Mock intelligence is not live reputation data."),
        ("Safe Simulation Disclaimer", "This defensive demonstration executes no imported content, performs no lookup, and makes no operating-system or firewall changes."),
    ]
    body = "".join(f"<section><h2>{title}</h2>{content if content.startswith(('<table','<article','<p','<ul')) else f'<p>{content}</p>'}</section>" for title, content in sections)
    document = f"<!doctype html><html><head><meta charset='utf-8'><title>{TITLE}</title><style>body{{font:14px/1.6 system-ui;margin:40px;color:#18212f}}h1{{color:#4338ca}}section{{margin:30px 0;break-inside:avoid}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #cbd5e1;padding:8px;text-align:left}}pre{{white-space:pre-wrap;background:#f1f5f9;padding:12px}}@media print{{body{{margin:15mm}}}}</style></head><body><h1>{TITLE}</h1><p>Generated from local ThreatScope SOC records.</p>{body}</body></html>"
    report = models.SocReport(title=TITLE, report_type=report_type, html_content=document, summary_json=json.dumps(summary, sort_keys=True))
    db.add(report); db.flush()
    add_activity(db, "soc_report_generated", f"SOC report {report.id} generated.", "soc_report", report.id)
    notify(db, "SOC Report Generated", f"SOC report #{report.id} is ready.", "success", "soc_report", report.id)
    db.commit(); db.refresh(report)
    return report

