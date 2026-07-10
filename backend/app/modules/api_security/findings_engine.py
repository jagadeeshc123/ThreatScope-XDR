import hashlib
import json
from typing import Any

from app import models
from app.modules.api_security.inventory import loads_json
from app.modules.api_security.remediation import remediation_for
from app.modules.api_security.response_exposure import response_exposure_review


STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_PATH_RE = ("admin", "user", "account", "payment", "billing", "password", "token", "secret", "internal", "export", "report", "profile", "role", "permission")


def fingerprint(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def _finding(
    assessment_id: int,
    endpoint_id: int | None,
    title: str,
    kind: str,
    owasp: str | None,
    severity: str,
    confidence: str,
    evidence: str,
    source: str,
) -> dict[str, Any]:
    guidance = remediation_for(kind)
    return {
        "assessment_id": assessment_id,
        "endpoint_id": endpoint_id,
        "title": title,
        "owasp_category": owasp,
        "severity": severity,
        "confidence": confidence,
        "description": guidance["description"],
        "evidence": evidence,
        "impact": guidance["impact"],
        "remediation": guidance["remediation"],
        "source": source,
        "fingerprint": fingerprint(assessment_id, endpoint_id, title, evidence),
    }


def candidate_findings(assessment: models.ApiAssessment) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    endpoints = list(assessment.endpoints)
    has_auth = any(endpoint.auth_required for endpoint in endpoints)
    has_unauth = any(not endpoint.auth_required for endpoint in endpoints)

    for endpoint in endpoints:
        lower_path = endpoint.path.lower()
        source = assessment.source_type if assessment.source_type in {"openapi", "postman"} else "inventory"
        if not endpoint.auth_required and endpoint.method in STATE_CHANGING:
            findings.append(_finding(
                assessment.id, endpoint.id, "Unauthenticated State-Changing API Endpoint",
                "unauthenticated_state_change", "API2:2023 Broken Authentication", "high", "medium",
                f"{endpoint.method} {endpoint.path} is documented without authentication.",
                source,
            ))
        if not endpoint.auth_required and any(keyword in lower_path for keyword in SENSITIVE_PATH_RE):
            findings.append(_finding(
                assessment.id, endpoint.id, "Sensitive Endpoint Without Documented Authentication",
                "sensitive_unauthenticated", "API2:2023 Broken Authentication", "high", "medium",
                f"{endpoint.method} {endpoint.path} contains sensitive path terms and no documented auth requirement.",
                source,
            ))
        if endpoint.deprecated:
            findings.append(_finding(
                assessment.id, endpoint.id, "Deprecated API Endpoint Still Present",
                "deprecated_endpoint", "API9:2023 Improper Inventory Management", "medium", "high",
                f"{endpoint.method} {endpoint.path} is marked deprecated in imported metadata.",
                source,
            ))
        if not endpoint.operation_id and not endpoint.summary:
            findings.append(_finding(
                assessment.id, endpoint.id, "Missing Operation Identifier and Summary",
                "missing_operation_id", "API9:2023 Improper Inventory Management", "info", "high",
                f"{endpoint.method} {endpoint.path} lacks operationId and summary.",
                "inventory",
            ))
        params = loads_json(endpoint.parameters_json, [])
        if any(any(term in str(param.get("name", "")).lower() for term in ("url", "uri", "callback", "webhook", "redirect")) for param in params):
            findings.append(_finding(
                assessment.id, endpoint.id, "External URL Parameter Requires SSRF Review",
                "sensitive_unauthenticated", "API7:2023 Server Side Request Forgery", "medium", "low",
                f"{endpoint.method} {endpoint.path} documents URL-like parameters. This is a potential risk indicator; manual validation required.",
                "inventory",
            ))

    if endpoints and not has_auth:
        findings.append(_finding(
            assessment.id, None, "Missing or Incomplete API Security Scheme",
            "missing_security_scheme", "API8:2023 Security Misconfiguration", "medium", "high",
            "No imported endpoint declares authentication.",
            "inventory",
        ))
    elif has_auth and has_unauth:
        findings.append(_finding(
            assessment.id, None, "Inconsistent Authentication Requirements",
            "inconsistent_auth", "API8:2023 Security Misconfiguration", "low", "medium",
            "Imported inventory contains both authenticated and unauthenticated endpoints.",
            "inventory",
        ))

    for artifact in assessment.artifacts:
        summary = loads_json(artifact.parsed_summary_json, {})
        server_urls = summary.get("server_urls", [])
        if any(str(url).lower().startswith("http://") for url in server_urls):
            findings.append(_finding(
                assessment.id, None, "Insecure HTTP Server URL Documented",
                "insecure_http_server", "API8:2023 Security Misconfiguration", "medium", "high",
                f"Server URLs include cleartext HTTP: {', '.join(str(url) for url in server_urls if str(url).lower().startswith('http://'))}.",
                artifact.artifact_type,
            ))
        redacted = artifact.redacted_content.lower()
        if "ratelimit" not in redacted and "rate-limit" not in redacted:
            findings.append(_finding(
                assessment.id, None, "Missing Rate-Limit Documentation",
                "missing_rate_limit", "API4:2023 Unrestricted Resource Consumption", "low", "medium",
                f"{artifact.filename} does not document rate-limit headers or constraints.",
                artifact.artifact_type,
            ))

    for exposure in response_exposure_review(assessment):
        findings.append(_finding(
            assessment.id, exposure.get("endpoint_id"), "Sensitive Response Field Documented",
            "sensitive_response_field", "API3:2023 Broken Object Property Level Authorization",
            exposure["severity"], "medium",
            f"{exposure['method']} {exposure['path']} documents field {exposure['field_path']}. Runtime exposure is not confirmed.",
            "response_schema",
        ))

    for analysis in assessment.jwt_analyses:
        for jwt_finding in loads_json(analysis.findings_json, []):
            severity = jwt_finding.get("severity", "low")
            findings.append(_finding(
                assessment.id, None, jwt_finding.get("title", "JWT Metadata Risk"),
                "jwt_risk", "API2:2023 Broken Authentication", severity, "medium",
                f"JWT fingerprint {analysis.token_fingerprint[:12]}: {jwt_finding.get('detail', 'Metadata risk observed.')}",
                "jwt",
            ))

    return findings


def upsert_findings(db, assessment: models.ApiAssessment) -> tuple[int, list[models.ApiFinding]]:
    created = 0
    for item in candidate_findings(assessment):
        existing = db.query(models.ApiFinding).filter(
            models.ApiFinding.assessment_id == assessment.id,
            models.ApiFinding.fingerprint == item["fingerprint"],
        ).first()
        if existing:
            continue
        db.add(models.ApiFinding(**item))
        created += 1
    db.flush()
    findings = db.query(models.ApiFinding).filter(models.ApiFinding.assessment_id == assessment.id).all()
    return created, findings

