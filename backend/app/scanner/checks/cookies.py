from typing import List
import httpx

def check_cookies(url: str, cookies: httpx.Cookies, scheme: str) -> List[dict]:
    findings = []
    
    for name, value in cookies.items():
        # Ideally we'd need the cookie properties (Secure, HttpOnly, SameSite)
        # httpx doesn't expose these easily from the CookieJar for individual checks without looking at Set-Cookie headers.
        pass
        
    return findings

def check_set_cookie_headers(url: str, headers: list[tuple[str, str]], scheme: str) -> List[dict]:
    findings = []
    
    for name, value in headers:
        if name.lower() == "set-cookie":
            val_lower = value.lower()
            
            if "secure" not in val_lower:
                findings.append({
                    "title": "Missing Secure Flag on Cookie",
                    "severity": "low" if scheme == "https" else "medium",
                    "category": "Cookies",
                    "affected_url": url,
                    "description": "A cookie was set without the Secure flag.",
                    "evidence": f"Set-Cookie: {value}"
                })
                
            if "httponly" not in val_lower:
                findings.append({
                    "title": "Missing HttpOnly Flag on Cookie",
                    "severity": "low",
                    "category": "Cookies",
                    "affected_url": url,
                    "description": "A cookie was set without the HttpOnly flag.",
                    "evidence": f"Set-Cookie: {value}"
                })
                
            if "samesite" not in val_lower:
                findings.append({
                    "title": "Missing SameSite Attribute on Cookie",
                    "severity": "low",
                    "category": "Cookies",
                    "affected_url": url,
                    "description": "A cookie was set without the SameSite attribute.",
                    "evidence": f"Set-Cookie: {value}"
                })
                
    return findings
