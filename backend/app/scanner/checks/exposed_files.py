import asyncio
from typing import List
from urllib.parse import urljoin
from app.scanner.http_client import SafeHTTPClient

SAFE_FILES_LIST = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/login",
    "/backup",
    "/config",
    "/.env"
]

async def check_exposed_files(base_url: str, http_client: SafeHTTPClient) -> List[dict]:
    findings = []
    
    for path in SAFE_FILES_LIST:
        target_url = urljoin(base_url, path)
        response, error = await http_client.head(target_url)
        
        if not error and response:
            if response.status_code == 200:
                severity = "low"
                if path in ["/.env", "/backup", "/config"]:
                    severity = "high"
                elif path in ["/admin", "/login"]:
                    severity = "info"
                    
                findings.append({
                    "title": f"Exposed File/Directory: {path}",
                    "severity": severity,
                    "category": "Exposed Files",
                    "affected_url": target_url,
                    "description": f"The file or directory {path} is publicly accessible.",
                    "evidence": f"Status: 200 OK, Content-Type: {response.headers.get('content-type', 'unknown')}"
                })
                
    return findings
