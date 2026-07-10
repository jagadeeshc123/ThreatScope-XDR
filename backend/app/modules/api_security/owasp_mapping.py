from app import models
from app.modules.api_security.rules_loader import owasp_categories


CONSERVATIVE_NOTE = "Manual validation required; imported metadata alone does not confirm this vulnerability."


def build_coverage(assessment: models.ApiAssessment, findings: list[models.ApiFinding]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    by_category: dict[str, list[models.ApiFinding]] = {}
    for finding in findings:
        if finding.owasp_category:
            by_category.setdefault(finding.owasp_category.split(" ")[0], []).append(finding)

    for category in owasp_categories():
        category_id = category["id"]
        related = by_category.get(category_id, [])
        if related:
            conservative_categories = {"API1:2023", "API3:2023", "API5:2023", "API6:2023", "API7:2023"}
            status = "partial" if category_id in conservative_categories else "covered"
            evidence = f"{len(related)} static finding indicator(s). {category['manual_validation_note']}"
        elif category_id == "API6:2023":
            status = "not_applicable"
            evidence = "Business-flow testing is out of scope for this phase."
        else:
            status = "not_observed"
            evidence = f"No static indicator observed. Manual validation note: {category['manual_validation_note']}"
        rows.append({
            "category_id": category_id,
            "category_title": category["title"],
            "status": status,
            "finding_count": len(related),
            "evidence_summary": evidence,
        })
    return rows
