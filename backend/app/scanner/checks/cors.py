from typing import List, Dict

def check_cors(url: str, headers: Dict[str, str]) -> List[dict]:
    findings = []
    header_lower = {k.lower(): v for k, v in headers.items()}
    
    allow_origin = header_lower.get("access-control-allow-origin")
    allow_credentials = header_lower.get("access-control-allow-credentials")
    
    if allow_origin == "*":
        findings.append({
            "title": "Overly Permissive CORS (Access-Control-Allow-Origin: *)",
            "severity": "medium",
            "category": "CORS",
            "affected_url": url,
            "description": "The application allows cross-origin requests from any domain.",
            "evidence": "Access-Control-Allow-Origin: *"
        })
        
    if allow_origin and allow_origin != "*" and allow_credentials == "true":
        # Need to check if it reflects origin dynamically, but statically we can just flag it as info
        findings.append({
            "title": "CORS Allow Credentials Enabled",
            "severity": "info",
            "category": "CORS",
            "affected_url": url,
            "description": "The application allows credentials in cross-origin requests.",
            "evidence": f"Origin: {allow_origin}, Credentials: {allow_credentials}"
        })

    return findings
