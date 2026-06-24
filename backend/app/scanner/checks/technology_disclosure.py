from typing import List, Dict
from bs4 import BeautifulSoup

def check_technology_disclosure(url: str, headers: Dict[str, str], html_content: str) -> List[dict]:
    findings = []
    header_lower = {k.lower(): v for k, v in headers.items()}
    
    server = header_lower.get("server")
    if server:
        findings.append({
            "title": "Server Header Disclosure",
            "severity": "info",
            "category": "Technology Disclosure",
            "affected_url": url,
            "description": "The Server HTTP header is exposed, revealing technology stack details.",
            "evidence": f"Server: {server}"
        })
        
    x_powered_by = header_lower.get("x-powered-by")
    if x_powered_by:
        findings.append({
            "title": "X-Powered-By Header Disclosure",
            "severity": "low",
            "category": "Technology Disclosure",
            "affected_url": url,
            "description": "The X-Powered-By HTTP header is exposed, revealing framework details.",
            "evidence": f"X-Powered-By: {x_powered_by}"
        })
        
    # very basic HTML framework check
    if html_content:
        if "data-reactroot" in html_content or "id=\"__next\"" in html_content:
            findings.append({
                "title": "Frontend Framework Detected (React/Next.js)",
                "severity": "info",
                "category": "Technology Disclosure",
                "affected_url": url,
                "description": "Evidence of React or Next.js found in HTML markup.",
                "evidence": "HTML contains React-specific attributes or standard Next.js mount points."
            })
            
    return findings
