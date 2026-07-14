from fastapi import Request


def required_permissions(request: Request) -> tuple[set[str], bool]:
    """Return (permissions, require_all). Empty permissions still requires authentication."""
    path = request.url.path
    method = request.method.upper()
    read = method in {"GET", "HEAD"}

    if path.startswith("/api/dashboard"):
        return {"dashboard:view"}, True
    if path.startswith("/api/search"):
        return {"search:use"}, True
    if path.startswith("/api/notifications"):
        return {"notifications:read"}, True
    if path.startswith("/api/profile"):
        return {"profile:manage"}, True
    if path.startswith("/api/settings"):
        return ({"system:manage"} if not read else {"profile:manage"}), True
    if path.startswith("/api/policies"):
        return ({"web:read"} if read else {"system:manage"}), True

    if path.startswith("/api/targets"):
        if method == "DELETE": return {"web:delete"}, True
        return ({"web:read"} if read else {"web:manage_targets"}), True
    if path.startswith("/api/scans"):
        if method == "DELETE": return {"web:delete"}, True
        return ({"web:read"} if read else {"web:run_scans"}), True
    if path.startswith("/api/reports"):
        if read: return {"web:read", "reports:read_all"}, False
        return {"web:generate_reports"}, True

    if path.startswith("/api/api-security"):
        if read: return {"api:read", "reports:read_all"} if "/reports" in path else {"api:read"}, False
        if method == "DELETE": return {"api:delete"}, True
        if "/reports" in path: return {"api:generate_reports"}, True
        if "/authorization" in path or "/identities" in path or "/roles" in path: return {"api:manage_authorization"}, True
        if "/business-flows" in path: return {"api:manage_business_flows"}, True
        if "/import" in path: return {"api:import"}, True
        if "/jwt" in path or "/analy" in path: return {"api:analyze"}, True
        return {"api:manage_assessments"}, True

    if path.startswith("/api/soc"):
        if read: return {"soc:read", "reports:read_all"} if "/reports" in path else {"soc:read"}, False
        if method == "DELETE": return {"soc:delete"}, True
        if "/reports" in path: return {"soc:generate_reports"}, True
        if "/imports" in path or "/sources" in path: return {"soc:import"}, True
        if "/simulator" in path: return {"soc:simulate"}, True
        if "/detections" in path: return {"soc:run_detection"}, True
        if "/alerts" in path: return {"soc:manage_alerts"}, True
        if "/rules" in path: return {"soc:manage_rules"}, True
        if "/blocklist" in path or "/watchlist" in path: return {"soc:manage_watchlist"}, True
        return {"soc:run_detection"}, True

    if path.startswith("/api/document-threats"):
        if read: return {"document:read", "reports:read_all"} if "/reports" in path else {"document:read"}, False
        if method == "DELETE": return {"document:delete"}, True
        if "/reports" in path: return {"document:generate_reports"}, True
        return {"document:analyze"}, True

    if path.startswith("/api/phishing-defense"):
        if read: return {"phishing:read", "reports:read_all"} if "/reports" in path else {"phishing:read"}, False
        if method == "DELETE" and "/watchlist" not in path: return {"phishing:delete"}, True
        if "/reports" in path: return {"phishing:generate_reports"}, True
        if "/watchlist" in path: return {"phishing:manage_watchlist"}, True
        if method == "PATCH": return {"phishing:manage_disposition"}, True
        return {"phishing:analyze"}, True

    if path.startswith("/api/correlation"):
        cases = "/cases" in path or "/case" in path or "/incident" in path
        if read:
            base = "cases:read" if cases else "correlation:read"
            return ({base, "reports:read_all"} if "/reports" in path else {base}), False
        if method == "DELETE": return {"cases:delete" if cases else "correlation:manage_matches"}, True
        if "/reports" in path: return {"cases:generate_reports"}, True
        if cases: return {"cases:create" if method == "POST" and path.rstrip("/").endswith("cases") else "cases:manage"}, True
        if "/synchron" in path: return {"correlation:synchronize"}, True
        if "/run" in path or "/matches" in path: return {"correlation:run"}, True
        return {"correlation:manage_matches"}, True

    if path.startswith("/api/governance"):
        if read: return {"governance:read", "reports:read_all"} if "/reports" in path else {"governance:read"}, False
        if "/reports" in path: return {"governance:generate_reports"}, True
        if "/synchron" in path: return {"governance:synchronize"}, True
        if "/mappings" in path: return {"governance:manage_mappings"}, True
        if "/treatments" in path: return {"governance:manage_treatments"}, True
        if "/exceptions" in path: return {"governance:manage_exceptions"}, True
        if "/evidence" in path: return {"governance:manage_evidence"}, True
        if "/reviews" in path: return {"governance:manage_reviews"}, True
        return {"governance:manage_risks"}, True
    return set(), True

