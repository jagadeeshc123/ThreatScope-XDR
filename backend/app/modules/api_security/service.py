import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app import models
from app.modules.api_security import schemas
from app.modules.api_security.findings_engine import upsert_findings
from app.modules.api_security.inventory import dumps_json, loads_json, risk_score_for_levels
from app.modules.api_security.jwt_analyzer import DISCLAIMER, JwtAnalyzeError, analyze_jwt
from app.modules.api_security.owasp_mapping import build_coverage
from app.modules.api_security.parsers.openapi_parser import OpenApiParseError, parse_openapi
from app.modules.api_security.parsers.postman_parser import PostmanParseError, parse_postman
from app.modules.api_security.report_service import build_report_payload
from app.modules.api_security.response_exposure import response_exposure_review


def _notify(db: Session, title: str, message: str, kind: str, assessment_id: int | None = None) -> None:
    db.add(models.Notification(
        title=title,
        message=message,
        type=kind,
        entity_type="api_assessment",
        entity_id=assessment_id,
    ))


def _artifact_to_schema(artifact: models.ApiImportArtifact) -> dict[str, Any]:
    return {
        "id": artifact.id,
        "assessment_id": artifact.assessment_id,
        "artifact_type": artifact.artifact_type,
        "filename": artifact.filename,
        "parsed_summary": loads_json(artifact.parsed_summary_json, {}),
        "created_at": artifact.created_at,
    }


def endpoint_to_schema(endpoint: models.ApiEndpoint) -> dict[str, Any]:
    return {
        "id": endpoint.id,
        "assessment_id": endpoint.assessment_id,
        "path": endpoint.path,
        "method": endpoint.method,
        "operation_id": endpoint.operation_id,
        "summary": endpoint.summary,
        "description": endpoint.description,
        "auth_required": endpoint.auth_required,
        "auth_schemes": loads_json(endpoint.auth_schemes_json, []),
        "request_content_types": loads_json(endpoint.request_content_types_json, []),
        "response_content_types": loads_json(endpoint.response_content_types_json, []),
        "parameters": loads_json(endpoint.parameters_json, []),
        "tags": loads_json(endpoint.tags_json, []),
        "folder_path": endpoint.folder_path,
        "deprecated": endpoint.deprecated,
        "preliminary_risk_level": endpoint.preliminary_risk_level,
        "preliminary_risk_reasons": loads_json(endpoint.preliminary_risk_reasons_json, []),
        "created_at": endpoint.created_at,
    }


def jwt_to_schema(analysis: models.JwtAnalysis) -> dict[str, Any]:
    return {
        "id": analysis.id,
        "assessment_id": analysis.assessment_id,
        "token_fingerprint": analysis.token_fingerprint,
        "header": loads_json(analysis.header_json_redacted, {}),
        "payload": loads_json(analysis.payload_json_redacted, {}),
        "algorithm": analysis.algorithm,
        "issuer": analysis.issuer,
        "audience": loads_json(analysis.audience_json, []),
        "issued_at": analysis.issued_at,
        "expires_at": analysis.expires_at,
        "not_before": analysis.not_before,
        "expiration_status": analysis.expiration_status,
        "risk_score": analysis.risk_score,
        "findings": loads_json(analysis.findings_json, []),
        "disclaimer": DISCLAIMER,
        "created_at": analysis.created_at,
    }


def report_to_schema(report: models.ApiReport) -> dict[str, Any]:
    return {
        "id": report.id,
        "assessment_id": report.assessment_id,
        "title": report.title,
        "executive_summary": report.executive_summary,
        "html_content": report.html_content,
        "summary": loads_json(report.summary_json, {}),
        "created_at": report.created_at,
    }


def assessment_detail(assessment: models.ApiAssessment) -> dict[str, Any]:
    data = schemas.ApiAssessmentRead.model_validate(assessment).model_dump()
    data["artifacts"] = [_artifact_to_schema(artifact) for artifact in assessment.artifacts]
    return data


def create_assessment(db: Session, payload: schemas.ApiAssessmentCreate) -> models.ApiAssessment:
    assessment = models.ApiAssessment(
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description else None,
        source_type=payload.source_type,
        status="draft",
    )
    db.add(assessment)
    db.flush()
    _notify(db, "API assessment created", f"Created API assessment '{assessment.name}'.", "info", assessment.id)
    db.commit()
    db.refresh(assessment)
    return assessment


def get_assessment_or_404(db: Session, assessment_id: int) -> models.ApiAssessment:
    assessment = db.query(models.ApiAssessment).filter(models.ApiAssessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="API assessment not found.")
    return assessment


def delete_assessment(db: Session, assessment_id: int) -> None:
    assessment = get_assessment_or_404(db, assessment_id)
    db.delete(assessment)
    db.commit()


def _replace_inventory(
    db: Session,
    assessment: models.ApiAssessment,
    artifact_type: str,
    filename: str,
    parsed: dict[str, Any],
) -> tuple[models.ApiImportArtifact, list[models.ApiEndpoint]]:
    endpoint_ids = [row[0] for row in db.query(models.ApiEndpoint.id).filter(models.ApiEndpoint.assessment_id == assessment.id).all()]
    if endpoint_ids:
        db.query(models.AuthorizationReview).filter(models.AuthorizationReview.endpoint_id.in_(endpoint_ids)).delete(synchronize_session=False)
        db.query(models.AuthorizationMatrixEntry).filter(models.AuthorizationMatrixEntry.endpoint_id.in_(endpoint_ids)).delete(synchronize_session=False)
        db.query(models.ApiBusinessFlowStep).filter(models.ApiBusinessFlowStep.endpoint_id.in_(endpoint_ids)).update({models.ApiBusinessFlowStep.endpoint_id: None}, synchronize_session=False)
    db.query(models.ApiEndpoint).filter(models.ApiEndpoint.assessment_id == assessment.id).delete()
    db.query(models.ApiImportArtifact).filter(models.ApiImportArtifact.assessment_id == assessment.id).delete()

    artifact = models.ApiImportArtifact(
        assessment_id=assessment.id,
        artifact_type=artifact_type,
        filename=filename,
        redacted_content=parsed["redacted_content"],
        parsed_summary_json=json.dumps(parsed["summary"], ensure_ascii=True, sort_keys=True),
    )
    db.add(artifact)
    db.flush()

    endpoints: list[models.ApiEndpoint] = []
    for item in parsed["endpoints"]:
        endpoint = models.ApiEndpoint(
            assessment_id=assessment.id,
            path=item["path"],
            method=item["method"],
            operation_id=item.get("operation_id"),
            summary=item.get("summary"),
            description=item.get("description"),
            auth_required=bool(item.get("auth_required")),
            auth_schemes_json=dumps_json(item.get("auth_schemes")),
            request_content_types_json=dumps_json(item.get("request_content_types")),
            response_content_types_json=dumps_json(item.get("response_content_types")),
            parameters_json=dumps_json(item.get("parameters")),
            tags_json=dumps_json(item.get("tags")),
            folder_path=item.get("folder_path"),
            deprecated=bool(item.get("deprecated")),
            preliminary_risk_level=item.get("preliminary_risk_level", "info"),
            preliminary_risk_reasons_json=dumps_json(item.get("preliminary_risk_reasons")),
        )
        db.add(endpoint)
        endpoints.append(endpoint)

    levels = [item.get("preliminary_risk_level", "info") for item in parsed["endpoints"]]
    assessment.source_type = artifact_type
    assessment.source_filename = filename
    assessment.status = "completed"
    assessment.base_url = parsed.get("base_url")
    assessment.api_version = parsed.get("version")
    assessment.endpoint_count = len(endpoints)
    assessment.unauthenticated_endpoint_count = sum(1 for item in parsed["endpoints"] if not item.get("auth_required"))
    assessment.high_risk_endpoint_count = sum(1 for item in parsed["endpoints"] if item.get("preliminary_risk_level") == "high")
    assessment.risk_score = risk_score_for_levels(levels)
    assessment.error_message = None
    return artifact, endpoints


def import_definition(db: Session, assessment_id: int, artifact_type: str, filename: str, content: bytes) -> dict[str, Any]:
    assessment = get_assessment_or_404(db, assessment_id)
    assessment.status = "processing"
    assessment.error_message = None
    db.flush()
    try:
        parsed = parse_openapi(content, filename) if artifact_type == "openapi" else parse_postman(content, filename)
        artifact, endpoints = _replace_inventory(db, assessment, artifact_type, filename, parsed)
        _notify(
            db,
            f"{artifact_type.title()} import completed",
            f"Imported {len(endpoints)} API endpoints for '{assessment.name}'.",
            "success",
            assessment.id,
        )
        db.commit()
        db.refresh(assessment)
        db.refresh(artifact)
        return {
            "assessment": assessment,
            "artifact": _artifact_to_schema(artifact),
            "endpoints_discovered": len(endpoints),
            "unauthenticated_endpoints": assessment.unauthenticated_endpoint_count,
            "high_risk_endpoints": assessment.high_risk_endpoint_count,
        }
    except (OpenApiParseError, PostmanParseError, ValueError) as exc:
        assessment.status = "failed"
        assessment.error_message = str(exc)
        _notify(db, f"{artifact_type.title()} import failed", str(exc), "danger", assessment.id)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        assessment.status = "failed"
        assessment.error_message = "Import failed because the uploaded definition could not be processed safely."
        _notify(db, f"{artifact_type.title()} import failed", assessment.error_message, "danger", assessment.id)
        db.commit()
        raise HTTPException(status_code=500, detail=assessment.error_message) from exc


def list_endpoints(
    db: Session,
    assessment_id: int,
    method: str | None = None,
    auth: str | None = None,
    deprecated: bool | None = None,
    risk: str | None = None,
    tag: str | None = None,
    q: str | None = None,
    sort: str = "path",
) -> list[dict[str, Any]]:
    get_assessment_or_404(db, assessment_id)
    query = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.assessment_id == assessment_id)
    if method:
        query = query.filter(models.ApiEndpoint.method == method.upper())
    if auth == "authenticated":
        query = query.filter(models.ApiEndpoint.auth_required == True)
    elif auth == "unauthenticated":
        query = query.filter(models.ApiEndpoint.auth_required == False)
    if deprecated is not None:
        query = query.filter(models.ApiEndpoint.deprecated == deprecated)
    if risk:
        query = query.filter(models.ApiEndpoint.preliminary_risk_level == risk.lower())
    if tag:
        query = query.filter(models.ApiEndpoint.tags_json.ilike(f"%{tag}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.ApiEndpoint.path.ilike(like),
            models.ApiEndpoint.operation_id.ilike(like),
            models.ApiEndpoint.summary.ilike(like),
        ))
    sort_map = {
        "method": models.ApiEndpoint.method,
        "path": models.ApiEndpoint.path,
        "authentication": models.ApiEndpoint.auth_required.desc(),
        "risk": models.ApiEndpoint.preliminary_risk_level.desc(),
    }
    return [endpoint_to_schema(endpoint) for endpoint in query.order_by(sort_map.get(sort, models.ApiEndpoint.path)).all()]


def overview(db: Session) -> dict[str, Any]:
    owasp_indicators = db.query(models.ApiOwaspCoverage).filter(models.ApiOwaspCoverage.finding_count > 0).count()
    return {
        "total_assessments": db.query(models.ApiAssessment).count(),
        "endpoints_inventoried": db.query(func.coalesce(func.sum(models.ApiAssessment.endpoint_count), 0)).scalar() or 0,
        "unauthenticated_endpoints": db.query(func.coalesce(func.sum(models.ApiAssessment.unauthenticated_endpoint_count), 0)).scalar() or 0,
        "high_risk_endpoints": db.query(func.coalesce(func.sum(models.ApiAssessment.high_risk_endpoint_count), 0)).scalar() or 0,
        "api_findings": db.query(models.ApiFinding).count(),
        "high_risk_api_findings": db.query(models.ApiFinding).filter(models.ApiFinding.severity.in_(["high", "critical"])).count(),
        "owasp_categories_with_indicators": owasp_indicators,
        "recent_assessments": db.query(models.ApiAssessment).order_by(models.ApiAssessment.created_at.desc()).limit(5).all(),
    }


def summary(db: Session, assessment_id: int) -> dict[str, Any]:
    assessment = get_assessment_or_404(db, assessment_id)
    endpoints = db.query(models.ApiEndpoint).filter(models.ApiEndpoint.assessment_id == assessment_id).all()
    risk_distribution = {level: 0 for level in ["info", "low", "medium", "high"]}
    methods: dict[str, int] = {}
    tags: set[str] = set()
    for endpoint in endpoints:
        risk_distribution[endpoint.preliminary_risk_level] = risk_distribution.get(endpoint.preliminary_risk_level, 0) + 1
        methods[endpoint.method] = methods.get(endpoint.method, 0) + 1
        tags.update(loads_json(endpoint.tags_json, []))
    return {
        "assessment": assessment,
        "endpoint_count": len(endpoints),
        "unauthenticated_endpoint_count": assessment.unauthenticated_endpoint_count,
        "high_risk_endpoint_count": assessment.high_risk_endpoint_count,
        "risk_distribution": risk_distribution,
        "methods": methods,
        "tags": sorted(tags),
    }


def analyze_token(db: Session, payload: schemas.JwtAnalyzeRequest) -> dict[str, Any]:
    if payload.assessment_id is not None:
        get_assessment_or_404(db, payload.assessment_id)
    try:
        result = analyze_jwt(payload.token, payload.expected_issuer, payload.expected_audience)
    except JwtAnalyzeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    analysis = models.JwtAnalysis(
        assessment_id=payload.assessment_id,
        token_fingerprint=result["token_fingerprint"],
        header_json_redacted=json.dumps(result["header"], ensure_ascii=True, sort_keys=True),
        payload_json_redacted=json.dumps(result["payload"], ensure_ascii=True, sort_keys=True),
        algorithm=result["algorithm"],
        issuer=result["issuer"],
        audience_json=json.dumps(result["audience"], ensure_ascii=True),
        issued_at=result["issued_at"],
        expires_at=result["expires_at"],
        not_before=result["not_before"],
        expiration_status=result["expiration_status"],
        risk_score=result["risk_score"],
        findings_json=json.dumps(result["findings"], ensure_ascii=True, sort_keys=True),
    )
    db.add(analysis)
    db.flush()
    kind = "warning" if analysis.risk_score >= 4 else "info"
    _notify(db, "JWT analyzed", f"JWT fingerprint {analysis.token_fingerprint[:12]} analyzed. Raw token was not stored.", kind, payload.assessment_id)
    if analysis.risk_score >= 4:
        _notify(db, "JWT risk detected", f"JWT analysis found risk score {analysis.risk_score}/10.", "warning", payload.assessment_id)
    db.commit()
    db.refresh(analysis)
    return jwt_to_schema(analysis)


def get_jwt_analysis_or_404(db: Session, analysis_id: int) -> models.JwtAnalysis:
    analysis = db.query(models.JwtAnalysis).filter(models.JwtAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="JWT analysis not found.")
    return analysis


def list_jwt_analyses(db: Session, assessment_id: int | None = None) -> list[dict[str, Any]]:
    query = db.query(models.JwtAnalysis)
    if assessment_id is not None:
        query = query.filter(models.JwtAnalysis.assessment_id == assessment_id)
    return [jwt_to_schema(item) for item in query.order_by(models.JwtAnalysis.created_at.desc()).all()]


def delete_jwt_analysis(db: Session, analysis_id: int) -> None:
    analysis = get_jwt_analysis_or_404(db, analysis_id)
    db.delete(analysis)
    db.commit()


def _refresh_coverage(db: Session, assessment: models.ApiAssessment, findings: list[models.ApiFinding]) -> list[models.ApiOwaspCoverage]:
    db.query(models.ApiOwaspCoverage).filter(models.ApiOwaspCoverage.assessment_id == assessment.id).delete()
    rows: list[models.ApiOwaspCoverage] = []
    for item in build_coverage(assessment, findings):
        row = models.ApiOwaspCoverage(assessment_id=assessment.id, **item)
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def analyze_assessment(db: Session, assessment_id: int) -> dict[str, Any]:
    assessment = get_assessment_or_404(db, assessment_id)
    created, findings = upsert_findings(db, assessment)
    coverage = _refresh_coverage(db, assessment, findings)
    high_or_critical = sum(1 for finding in findings if finding.severity in {"high", "critical"})
    _notify(db, "API assessment analyzed", f"Generated {created} new API finding(s) for '{assessment.name}'.", "success", assessment.id)
    if high_or_critical:
        _notify(db, "High-risk API finding created", f"{high_or_critical} high or critical API finding(s) are present.", "warning", assessment.id)
    db.commit()
    return {
        "assessment_id": assessment.id,
        "findings_created": created,
        "findings_total": len(findings),
        "high_or_critical_findings": high_or_critical,
        "coverage_categories": len(coverage),
    }


def list_findings(db: Session, assessment_id: int, severity: str | None = None, source: str | None = None) -> list[models.ApiFinding]:
    get_assessment_or_404(db, assessment_id)
    query = db.query(models.ApiFinding).filter(models.ApiFinding.assessment_id == assessment_id)
    if severity:
        query = query.filter(models.ApiFinding.severity == severity)
    if source:
        query = query.filter(models.ApiFinding.source == source)
    return query.order_by(models.ApiFinding.created_at.desc()).all()


def get_finding_or_404(db: Session, finding_id: int) -> models.ApiFinding:
    finding = db.query(models.ApiFinding).filter(models.ApiFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="API finding not found.")
    return finding


def owasp_coverage(db: Session, assessment_id: int) -> list[dict[str, Any]]:
    assessment = get_assessment_or_404(db, assessment_id)
    rows = db.query(models.ApiOwaspCoverage).filter(models.ApiOwaspCoverage.assessment_id == assessment_id).order_by(models.ApiOwaspCoverage.category_id).all()
    if not rows:
        rows = _refresh_coverage(db, assessment, list(assessment.findings))
        db.commit()
    findings = list(assessment.findings)
    output = []
    for row in rows:
        related = [finding for finding in findings if finding.owasp_category and finding.owasp_category.startswith(row.category_id)]
        item = schemas.ApiOwaspCoverageRead.model_validate(row).model_dump()
        item["related_findings"] = related
        output.append(item)
    return output


def response_exposure(db: Session, assessment_id: int) -> list[dict[str, Any]]:
    return response_exposure_review(get_assessment_or_404(db, assessment_id))


def create_report(db: Session, assessment_id: int) -> models.ApiReport:
    assessment = get_assessment_or_404(db, assessment_id)
    if not assessment.findings:
        created, findings = upsert_findings(db, assessment)
        _refresh_coverage(db, assessment, findings)
    payload = build_report_payload(assessment)
    report = models.ApiReport(
        assessment_id=assessment.id,
        title=payload["title"],
        executive_summary=payload["executive_summary"],
        html_content=payload["html_content"],
        summary_json=json.dumps(payload["summary"], ensure_ascii=True, sort_keys=True),
    )
    db.add(report)
    db.flush()
    _notify(db, "API report generated", f"Generated API Security report for '{assessment.name}', including authorization and business-flow review sections.", "success", assessment.id)
    db.commit()
    db.refresh(report)
    return report


def list_reports(db: Session, assessment_id: int) -> list[models.ApiReport]:
    get_assessment_or_404(db, assessment_id)
    return db.query(models.ApiReport).filter(models.ApiReport.assessment_id == assessment_id).order_by(models.ApiReport.created_at.desc()).all()


def get_report_or_404(db: Session, report_id: int) -> models.ApiReport:
    report = db.query(models.ApiReport).filter(models.ApiReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="API report not found.")
    return report
