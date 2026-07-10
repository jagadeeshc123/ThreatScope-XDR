import html
import json
from collections import Counter
from typing import Any

from app import models
from app.modules.api_security.inventory import loads_json
from app.modules.api_security.response_exposure import response_exposure_review


REPORT_TITLE = "API Security Assessment and Risk Intelligence Report"
SECTIONS = [
    "Executive Summary",
    "Assessment Scope",
    "Imported Definition Summary",
    "Endpoint Inventory",
    "Authentication Posture",
    "OWASP API Security Top 10 Coverage",
    "Response Exposure Review",
    "JWT Analysis Summary",
    "Authorization Model Summary",
    "Authorization Matrix Coverage",
    "Object-Level Review Summary",
    "Function-Level Review Summary",
    "Property-Level Review Summary",
    "Business Flow Inventory",
    "Business Flow Risk Review",
    "Manual Validation Backlog",
    "Detailed Findings",
    "Risk Distribution",
    "Remediation Roadmap",
    "Methodology and Limitations",
    "Authorized Testing Disclaimer",
]


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_report_payload(assessment: models.ApiAssessment) -> dict[str, Any]:
    findings = list(assessment.findings)
    coverage = list(assessment.owasp_coverage)
    exposures = response_exposure_review(assessment)
    severity_counts = Counter(finding.severity for finding in findings)
    executive_summary = (
        f"Assessment '{assessment.name}' contains {assessment.endpoint_count} imported endpoint(s), "
        f"{len(findings)} passive API finding(s), and {len(exposures)} response exposure indicator(s). "
        "No imported endpoint was contacted and no active testing was performed."
    )
    summary = {
        "assessment_id": assessment.id,
        "endpoint_count": assessment.endpoint_count,
        "finding_count": len(findings),
        "response_exposure_count": len(exposures),
        "jwt_analysis_count": len(assessment.jwt_analyses),
        "severity_distribution": dict(severity_counts),
        "sections": SECTIONS,
    }
    endpoint_rows = [[endpoint.method, endpoint.path, "Yes" if endpoint.auth_required else "No", endpoint.preliminary_risk_level] for endpoint in assessment.endpoints[:100]]
    finding_rows = [[finding.severity, finding.title, finding.owasp_category or "-", finding.source] for finding in findings]
    coverage_rows = [[row.category_id, row.category_title, row.status, row.finding_count, row.evidence_summary] for row in coverage]
    exposure_rows = [[item["method"], item["path"], item.get("status_code") or "-", item["field_path"], item["severity"]] for item in exposures]
    jwt_rows = [[analysis.id, analysis.algorithm or "-", analysis.expiration_status, analysis.risk_score, analysis.token_fingerprint[:16]] for analysis in assessment.jwt_analyses]
    roles = list(assessment.api_roles)
    matrix_entries = list(assessment.authorization_matrix_entries)
    reviews = list(assessment.authorization_reviews)
    flows = list(assessment.business_flows)
    flow_risks = [risk for flow in flows for risk in flow.risks]
    matrix_total = len(roles) * len(assessment.endpoints)
    reviewed_matrix = sum(1 for entry in matrix_entries if entry.review_status == "reviewed")
    matrix_coverage = round((reviewed_matrix / matrix_total) * 100, 1) if matrix_total else 0
    summary.update({
        "authorization_role_count": len(roles),
        "authorization_matrix_coverage": matrix_coverage,
        "authorization_review_count": len(reviews),
        "business_flow_count": len(flows),
        "business_flow_risk_count": len(flow_risks),
        "manual_validation_backlog": sum(1 for review in reviews if review.analyst_decision in {"open", "needs_testing"}) + sum(1 for risk in flow_risks if risk.status == "open"),
    })
    role_rows = [[role.name, role.privilege_level, role.description or "-"] for role in roles]
    review_rows = lambda kind: [[review.severity, review.expected_behavior, review.risk_indicator, review.confidence, review.analyst_decision] for review in reviews if review.review_type == kind]
    flow_rows = [[flow.name, flow.status, len(flow.steps), flow.risk_score, ", ".join(loads_json(flow.actor_roles_json, []))] for flow in flows]
    flow_risk_rows = [[risk.severity, risk.title, risk.owasp_category or "-", risk.confidence, risk.status, "Yes" if risk.manual_validation_required else "No"] for risk in flow_risks]
    backlog_rows = (
        [["Authorization", review.review_type, review.severity, review.risk_indicator] for review in reviews if review.analyst_decision in {"open", "needs_testing"}]
        + [["Business flow", risk.risk_type, risk.severity, risk.title] for risk in flow_risks if risk.status == "open"]
    )

    sections = {
        "Executive Summary": f"<p>{html.escape(executive_summary)}</p>",
        "Assessment Scope": f"<p>Assessment ID {assessment.id}. Base URL: {html.escape(assessment.base_url or 'Not declared')}. Version: {html.escape(assessment.api_version or 'Not declared')}.</p>",
        "Imported Definition Summary": _table(["Artifact", "Filename", "Summary"], [[artifact.artifact_type, artifact.filename, json.dumps(loads_json(artifact.parsed_summary_json, {}), sort_keys=True)] for artifact in assessment.artifacts]),
        "Endpoint Inventory": _table(["Method", "Path", "Auth", "Risk"], endpoint_rows),
        "Authentication Posture": f"<p>{assessment.unauthenticated_endpoint_count} endpoint(s) do not declare authentication. JWT analyses are decoded structure only; cryptographic signatures are not verified.</p>",
        "OWASP API Security Top 10 Coverage": _table(["Category", "Title", "Status", "Findings", "Evidence"], coverage_rows),
        "Response Exposure Review": _table(["Method", "Path", "Status", "Field", "Severity"], exposure_rows),
        "JWT Analysis Summary": _table(["ID", "Algorithm", "Expiration", "Risk", "Fingerprint"], jwt_rows),
        "Authorization Model Summary": _table(["Role", "Privilege", "Description"], role_rows),
        "Authorization Matrix Coverage": f"<p>{reviewed_matrix} of {matrix_total} expected role/endpoint decisions are analyst-reviewed ({matrix_coverage}%). Suggested cells are not confirmed access behavior.</p>",
        "Object-Level Review Summary": _table(["Severity", "Expected Behavior", "Indicator", "Confidence", "Decision"], review_rows("object_level")),
        "Function-Level Review Summary": _table(["Severity", "Expected Behavior", "Indicator", "Confidence", "Decision"], review_rows("function_level")),
        "Property-Level Review Summary": _table(["Severity", "Expected Behavior", "Indicator", "Confidence", "Decision"], review_rows("property_level")),
        "Business Flow Inventory": _table(["Flow", "Status", "Steps", "Risk Score", "Actors"], flow_rows),
        "Business Flow Risk Review": _table(["Severity", "Indicator", "OWASP", "Confidence", "Status", "Manual Validation"], flow_risk_rows),
        "Manual Validation Backlog": _table(["Source", "Type", "Severity", "Item"], backlog_rows),
        "Detailed Findings": _table(["Severity", "Title", "OWASP", "Source"], finding_rows),
        "Risk Distribution": _table(["Severity", "Count"], sorted(severity_counts.items())),
        "Remediation Roadmap": "<ul>" + "".join(f"<li><strong>{html.escape(finding.title)}</strong>: {html.escape(finding.remediation)}</li>" for finding in findings[:50]) + "</ul>",
        "Methodology and Limitations": "<p>This report uses imported API definitions, analyst-configured authorization expectations and business flows, static metadata, redacted JWT structures, and local schema review only. Metadata-derived indicators and analyst hypotheses are distinguished from accepted analyst findings. It does not execute requests, fuzz inputs, brute force credentials, or validate BOLA/BFLA at runtime.</p>",
        "Authorized Testing Disclaimer": "<p>Generated by ThreatScope XDR for authorized defensive assessment only.</p>",
    }
    html_content = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(REPORT_TITLE)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #172033; }}
    h1 {{ color: #312e81; }}
    h2 {{ margin-top: 28px; color: #3730a3; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 13px; }}
    th, td {{ border: 1px solid #d8dce8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2ff; }}
    @media print {{ body {{ margin: 16mm; }} }}
  </style>
</head>
<body>
  <h1>{html.escape(REPORT_TITLE)}</h1>
  {''.join(f'<section><h2>{html.escape(title)}</h2>{content}</section>' for title, content in sections.items())}
</body>
</html>
"""
    return {
        "title": REPORT_TITLE,
        "executive_summary": executive_summary,
        "html_content": html_content,
        "summary": summary,
    }
