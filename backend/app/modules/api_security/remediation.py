from app.modules.api_security.rules_loader import remediation_catalog


def remediation_for(kind: str) -> dict[str, str]:
    catalog = remediation_catalog()
    return catalog.get(kind, {
        "description": "A passive API security risk indicator was observed in imported metadata.",
        "impact": "The issue may increase API risk and should be reviewed by the owning team.",
        "remediation": "Update API documentation and implementation controls, then repeat passive analysis.",
    })

