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
        
        if response and response.status_code in [405, 501]:
            response, error = await http_client.get(target_url)
            
        if not error and response:
            if response.status_code == 200:
                is_metadata = path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
                
                if is_metadata:
                    title = f"Public Metadata Exposed: {path}"
                    severity = "info"
                    desc = f"The standard metadata file {path} is publicly accessible."
                else:
                    title = f"Sensitive Public Path Exposure: {path}"
                    severity = "low"
                    desc = f"The file or directory {path} is publicly accessible."
                    if path in ["/.env", "/backup", "/config"]:
                        severity = "high"
                    elif path in ["/admin", "/login"]:
                        severity = "info"
                        
                findings.append({
                    "title": title,
                    "severity": severity,
                    "category": "Exposed Files",
                    "affected_url": target_url,
                    "description": desc,
                    "evidence": f"Status: 200 OK, Content-Type: {response.headers.get('content-type', 'unknown')} (Body omitted for safety)"
                })
                
    return findings
