from typing import List, Dict

def check_security_headers(url: str, headers: Dict[str, str]) -> List[dict]:
    findings = []
    
    header_lower = {k.lower(): v for k, v in headers.items()}
    
    checks = [
        ("content-security-policy", "Missing Content-Security-Policy", "medium"),
        ("strict-transport-security", "Missing Strict-Transport-Security", "medium"),
        ("x-frame-options", "Missing X-Frame-Options", "low"),
        ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
        ("referrer-policy", "Missing Referrer-Policy", "low"),
        ("permissions-policy", "Missing Permissions-Policy", "info")
    ]
    
    for header, title, severity in checks:
        if header not in header_lower:
            findings.append({
                "title": title,
                "severity": severity,
                "category": "Security Headers",
                "affected_url": url,
                "description": f"The HTTP response does not include the {header} header.",
                "evidence": f"Headers received: {list(header_lower.keys())}"
            })
            
    return findings
