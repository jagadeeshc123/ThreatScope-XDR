from typing import List
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def check_forms_and_auth(url: str, html_content: str) -> List[dict]:
    findings = []
    if not html_content:
        return findings
        
    soup = BeautifulSoup(html_content, "html.parser")
    
    forms = soup.find_all("form")
    password_fields = soup.find_all("input", type="password")
    
    if password_fields:
        findings.append({
            "title": "Password Field Detected",
            "severity": "info",
            "category": "Authentication Surface",
            "affected_url": url,
            "description": "A password input field was detected on this page.",
            "evidence": f"Found {len(password_fields)} password input(s)."
        })
        
        parsed = urlparse(url)
        if parsed.scheme == "http":
            findings.append({
                "title": "Password Form over HTTP",
                "severity": "critical",
                "category": "Authentication Surface",
                "affected_url": url,
                "description": "A password input field is served over unencrypted HTTP.",
                "evidence": "Password field present on an HTTP URL."
            })
            
        for pf in password_fields:
            if pf.get("autocomplete") != "off" and not pf.get("autocomplete"):
                findings.append({
                    "title": "Missing Autocomplete Attribute on Password Field",
                    "severity": "low",
                    "category": "Authentication Surface",
                    "affected_url": url,
                    "description": "Password field does not explicitly disable autocomplete.",
                    "evidence": str(pf)[:100]
                })
                
    if forms:
        for form in forms:
            action = form.get("action", "")
            if "login" in action.lower() or "signin" in action.lower():
                findings.append({
                    "title": "Login Form Detected",
                    "severity": "info",
                    "category": "Authentication Surface",
                    "affected_url": url,
                    "description": "A login-like form was detected.",
                    "evidence": f"Form action: {action}"
                })
                
    return findings
