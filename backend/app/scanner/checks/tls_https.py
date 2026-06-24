from urllib.parse import urlparse
from typing import List
from bs4 import BeautifulSoup

def check_https(url: str) -> List[dict]:
    findings = []
    parsed = urlparse(url)
    
    if parsed.scheme == "http":
        findings.append({
            "title": "Cleartext HTTP Usage",
            "severity": "high",
            "category": "HTTPS/TLS",
            "affected_url": url,
            "description": "The site is accessed over HTTP, which transmits data in cleartext.",
            "evidence": f"URL Scheme: {parsed.scheme}"
        })
        
    return findings

def check_mixed_content(url: str, html_content: str) -> List[dict]:
    findings = []
    parsed = urlparse(url)
    
    if parsed.scheme == "https":
        soup = BeautifulSoup(html_content, "html.parser")
        mixed_resources = []
        
        for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
            src = tag.get('src') or tag.get('href')
            if src and src.startswith("http://"):
                mixed_resources.append(src)
                
        if mixed_resources:
            findings.append({
                "title": "Mixed Content (HTTP resources on HTTPS page)",
                "severity": "medium",
                "category": "HTTPS/TLS",
                "affected_url": url,
                "description": "The HTTPS page loads resources over insecure HTTP.",
                "evidence": f"Resources: {mixed_resources[:3]}..."
            })
            
    return findings
