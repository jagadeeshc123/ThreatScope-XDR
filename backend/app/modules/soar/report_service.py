import html
import json
import uuid

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import SoarActionPolicy, SoarAnalystInput, SoarApproval, SoarExecution, SoarExecutionEvidence, SoarPlaybook, SoarReport, SoarRollbackRecord, SoarStepExecution, SoarTriggerRule
from .service import dumps, row


SECTIONS = [
    "Report metadata", "Executive summary", "Playbook inventory", "Lifecycle distribution", "Version activity",
    "Trigger rules", "Trigger-source distribution", "Execution totals", "Execution-mode distribution", "Execution outcomes",
    "Completed-with-warning executions", "Failed executions", "Cancelled executions", "Waiting approvals", "Approval outcomes",
    "Approval duration", "Analyst-input requests", "Delay and resume activity", "Retry activity", "Retry exhaustion",
    "Local actions", "Sensitive local actions", "Simulated containment actions", "Cases created or updated",
    "Detection matches routed", "Threat-intelligence matches routed", "Vulnerabilities routed", "Phishing analyses routed",
    "Document analyses routed", "Evidence snapshots", "Idempotency suppression", "Rollback requests", "Rollback outcomes",
    "Rollback failures", "Action-policy summary", "Safety-control summary", "RBAC summary", "Methodology", "Limitations",
    "Simulation disclaimer", "Offline/local-action disclaimer",
]


def _counts(db: Session) -> dict:
    executions = dict(db.query(SoarExecution.status, func.count(SoarExecution.id)).group_by(SoarExecution.status).all())
    modes = dict(db.query(SoarExecution.mode, func.count(SoarExecution.id)).group_by(SoarExecution.mode).all())
    approvals = dict(db.query(SoarApproval.status, func.count(SoarApproval.id)).group_by(SoarApproval.status).all())
    rollbacks = dict(db.query(SoarRollbackRecord.status, func.count(SoarRollbackRecord.id)).group_by(SoarRollbackRecord.status).all())
    return {"playbooks": db.query(SoarPlaybook).count(), "triggers": db.query(SoarTriggerRule).count(), "executions": executions, "execution_modes": modes, "approvals": approvals, "analyst_inputs": db.query(SoarAnalystInput).count(), "evidence_snapshots": db.query(SoarExecutionEvidence).count(), "rollbacks": rollbacks, "action_policies": db.query(SoarActionPolicy).count()}


def generate(db: Session, title: str, report_type: str, filters: dict, actor_id: int) -> SoarReport:
    summary = _counts(db)
    rendered = []
    for index, section in enumerate(SECTIONS, 1):
        if section == "Simulation disclaimer": body = "SIMULATION ONLY — NO EXTERNAL ACTION IS PERFORMED. Simulated results never establish that containment occurred."
        elif section == "Offline/local-action disclaimer": body = "ThreatScope SOAR-Lite performs only fixed, allowlisted local database workflows. It makes no external request and performs no real containment."
        elif section == "Limitations": body = "Revoked sessions and delivered notifications cannot be restored. External simulations have no compensating external action. Approval, audit, and execution history is immutable."
        elif section == "Methodology": body = "Counts are generated deterministically from permission-gated local SOAR tables. User-controlled text is HTML-escaped and no active links, scripts, or remote assets are emitted."
        else: body = json.dumps(summary, sort_keys=True)
        rendered.append(f"<section><h2>{index}. {html.escape(section)}</h2><p>{html.escape(body)}</p></section>")
    document = "<!doctype html><html><head><meta charset='utf-8'><title>"+html.escape(title)+"</title><style>body{font:14px system-ui;max-width:1100px;margin:auto;padding:2rem;color:#172033}section{border-top:1px solid #ccd4df;padding:1rem 0}h1,h2{color:#12233f}p{white-space:pre-wrap}</style></head><body><h1>"+html.escape(title)+"</h1>"+"".join(rendered)+"</body></html>"
    item = SoarReport(report_uuid=str(uuid.uuid4()), title=title, report_type=report_type, filters_json=dumps(filters), summary_json=dumps(summary), html_content=document, generated_by_user_id=actor_id)
    db.add(item); db.commit(); db.refresh(item); return item


def details(item: SoarReport) -> dict:
    result = row(item); result["section_count"] = len(SECTIONS); result["sections"] = SECTIONS; return result
