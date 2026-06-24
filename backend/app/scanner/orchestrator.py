import asyncio
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app import models
from app.scanner.http_client import SafeHTTPClient
from app.scanner.crawler import Crawler
from app.scanner.checks import (
    security_headers, cookies, cors, tls_https, exposed_files,
    technology_disclosure, forms_auth_surface
)
from app.scanner.risk_scoring import calculate_risk_score
from app.scanner.remediation import get_remediation_for_finding

def utcnow():
    return datetime.now(timezone.utc)

async def async_run_scan(scan_id: int):
    db: Session = SessionLocal()
    try:
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            return
            
        scan.status = "running"
        db.commit()
        
        target = db.query(models.Target).filter(models.Target.id == scan.target_id).first()
        base_url = target.base_url

        notif_start = models.Notification(
            title="Scan Started",
            message=f"Scan #{scan.id} for {target.name} has started.",
            type="info",
            entity_type="scan",
            entity_id=scan.id
        )
        db.add(notif_start)
        db.commit()
        
        http_client = SafeHTTPClient()
        findings_data = []
        
        # 1. Base URL fetch
        response, error = await http_client.get(base_url)
        if error or not response:
            scan.status = "failed"
            scan.error_message = error or "No response from base URL"
            scan.completed_at = utcnow()
            db.commit()
            await http_client.close()
            return
            
        html_content = response.text
        headers = dict(response.headers)
        
        # Passive Checks
        findings_data.extend(security_headers.check_security_headers(base_url, headers))
        findings_data.extend(cookies.check_set_cookie_headers(base_url, list(response.headers.multi_items()), response.url.scheme))
        findings_data.extend(cors.check_cors(base_url, headers))
        findings_data.extend(tls_https.check_https(base_url))
        findings_data.extend(tls_https.check_mixed_content(base_url, html_content))
        findings_data.extend(technology_disclosure.check_technology_disclosure(base_url, headers, html_content))
        
        if scan.profile in ["Standard Safe Scan", "Full Safe Scan"]:
            # Fetch settings
            settings = db.query(models.AppSettings).first()
            max_pages = settings.max_pages_full if scan.profile == "Full Safe Scan" else settings.max_pages_standard
            max_depth = settings.max_depth_full if scan.profile == "Full Safe Scan" else settings.max_depth_standard
            
            # Exposed files check
            exp_findings = await exposed_files.check_exposed_files(base_url, http_client)
            findings_data.extend(exp_findings)
            
            # Crawl
            crawler = Crawler(base_url, max_pages=max_pages, max_depth=max_depth)
            pages_content = await crawler.crawl(http_client)
            
            # Form / Auth Check on all crawled pages
            for url, content in pages_content.items():
                findings_data.extend(forms_auth_surface.check_forms_and_auth(url, content))

        await http_client.close()

        # Save findings
        for f in findings_data:
            rem_info = get_remediation_for_finding(f["title"])
            finding = models.Finding(
                scan_id=scan.id,
                target_id=target.id,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                affected_url=f["affected_url"],
                description=f["description"],
                evidence=f["evidence"],
                impact=rem_info["impact"],
                remediation=rem_info["remediation"],
                confidence="high",
                risk_score=0.0 # calculate per finding if needed
            )
            db.add(finding)
            
        scan.total_findings = len(findings_data)
        scan.risk_score = calculate_risk_score(findings_data)
        scan.status = "completed"
        scan.completed_at = utcnow()
        
        notif_complete = models.Notification(
            title="Scan Completed",
            message=f"Scan #{scan.id} finished with {scan.total_findings} findings (Risk: {scan.risk_score}).",
            type="success",
            entity_type="scan",
            entity_id=scan.id
        )
        db.add(notif_complete)
        
        # Check for criticals
        criticals = [f for f in findings_data if f["severity"] == "critical"]
        if criticals:
            notif_crit = models.Notification(
                title="Critical Findings Detected",
                message=f"Found {len(criticals)} critical issues in scan #{scan.id}.",
                type="danger",
                entity_type="scan",
                entity_id=scan.id
            )
            db.add(notif_crit)
            
        db.commit()

    except Exception as e:
        db.rollback()
        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = utcnow()
            
            notif_fail = models.Notification(
                title="Scan Failed",
                message=f"Scan #{scan.id} failed to complete: {str(e)[:100]}",
                type="danger",
                entity_type="scan",
                entity_id=scan.id
            )
            db.add(notif_fail)
            db.commit()
    finally:
        db.close()

def run_scan(scan_id: int):
    asyncio.run(async_run_scan(scan_id))
