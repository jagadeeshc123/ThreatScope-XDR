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
from app.scanner.posture_scoring import calculate_posture_scores
from app.scanner.remediation import get_remediation_for_finding
from app.scanner.reports.report_generator import generate_report

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
        
        settings = db.query(models.AppSettings).first() or models.AppSettings()
        http_client = SafeHTTPClient(
            timeout=settings.request_timeout_seconds,
            rate_limit_delay=settings.rate_limit_delay_ms / 1000
        )
        findings_data = []
        
        # 1. Base URL fetch
        response, error = await http_client.get(base_url)
        if error or not response:
            scan.status = "failed"
            scan.error_message = error or "No response from base URL"
            scan.completed_at = utcnow()
            db.add(models.Notification(
                title="Scan Failed",
                message=f"Scan #{scan.id} could not reach {base_url}: {scan.error_message[:120]}",
                type="danger",
                entity_type="scan",
                entity_id=scan.id
            ))
            db.commit()
            await http_client.close()
            return
            
        html_content = response.text
        headers = dict(response.headers)
        
        # Capture header evidence
        header_evidence = models.EvidenceArtifact(
            scan_id=scan.id,
            target_id=target.id,
            artifact_type="header_snapshot",
            title="Base URL Response Headers",
            redacted_text=str(headers),
            related_url=base_url
        )
        db.add(header_evidence)
        db.commit()
        
        # Passive Checks
        findings_data.extend(security_headers.check_security_headers(base_url, headers))
        findings_data.extend(cookies.check_set_cookie_headers(base_url, list(response.headers.multi_items()), response.url.scheme))
        findings_data.extend(cors.check_cors(base_url, headers))
        findings_data.extend(tls_https.check_https(base_url))
        findings_data.extend(tls_https.check_mixed_content(base_url, html_content))
        findings_data.extend(technology_disclosure.check_technology_disclosure(base_url, headers, html_content))
        
        if scan.profile in ["Standard Safe Scan", "Full Safe Scan"]:
            max_pages = settings.max_pages_full if scan.profile == "Full Safe Scan" else settings.max_pages_standard
            max_depth = settings.max_depth_full if scan.profile == "Full Safe Scan" else settings.max_depth_standard
            
            # Exposed files check
            exp_findings = await exposed_files.check_exposed_files(base_url, http_client)
            findings_data.extend(exp_findings)
            
            # Crawl
            crawler = Crawler(base_url, max_pages=max_pages, max_depth=max_depth)
            pages_data = await crawler.crawl(http_client)
            
            # Form / Auth Check on all crawled pages
            for url, data in pages_data.items():
                html = data.get('html')
                if html:
                    findings_data.extend(forms_auth_surface.check_forms_and_auth(url, html))
                
                
                # Save crawl node
                node_info = data.get('node_info', {})
                crawl_node = models.CrawlNode(
                    scan_id=scan.id,
                    target_id=target.id,
                    url=node_info.get('url'),
                    path=node_info.get('path'),
                    status_code=node_info.get('status_code'),
                    content_type=node_info.get('content_type'),
                    page_title=node_info.get('page_title'),
                    depth=node_info.get('depth'),
                    parent_url=node_info.get('parent_url'),
                    has_forms=node_info.get('has_forms', False),
                    has_password_field=node_info.get('has_password_field', False),
                    finding_count=0 # updated below
                )
                db.add(crawl_node)
                
                # Capture HTML snippet evidence if it has a password field
                if crawl_node.has_password_field and html:
                    # Redact potentially sensitive content, keep a snippet
                    snippet = html[:2000] # just store the first 2KB as a snippet
                    html_evidence = models.EvidenceArtifact(
                        scan_id=scan.id,
                        target_id=target.id,
                        artifact_type="html_snippet",
                        title=f"Login Page Snippet ({crawl_node.path})",
                        redacted_text=snippet,
                        related_url=crawl_node.url
                    )
                    db.add(html_evidence)
            
            db.commit()

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
            
            # Update crawl node finding count
            if f.get("affected_url"):
                node = db.query(models.CrawlNode).filter(models.CrawlNode.scan_id == scan.id, models.CrawlNode.url == f["affected_url"]).first()
                if node:
                    node.finding_count += 1
            
        scan.total_findings = len(findings_data)
        scan.risk_score = calculate_risk_score(findings_data)
        
        posture_scores = calculate_posture_scores(findings_data)
        scan.overall_posture_score = posture_scores["overall_posture_score"]
        scan.posture_transport_security = posture_scores["transport_security"]
        scan.posture_browser_defense = posture_scores["browser_defense"]
        scan.posture_session_safety = posture_scores["session_safety"]
        scan.posture_exposure_hygiene = posture_scores["exposure_hygiene"]
        scan.posture_authentication_surface = posture_scores["authentication_surface"]

        scan.status = "completed"
        scan.completed_at = utcnow()
        db.commit()

        # Check for previous scan to generate PostureDiff
        previous_scan = db.query(models.Scan).filter(
            models.Scan.target_id == target.id,
            models.Scan.id < scan.id,
            models.Scan.status == "completed"
        ).order_by(models.Scan.id.desc()).first()

        if previous_scan:
            prev_findings = db.query(models.Finding).filter(models.Finding.scan_id == previous_scan.id).all()
            
            curr_keys = set(f"{f['title']}-{f.get('affected_url', '')}" for f in findings_data)
            prev_keys = set(f"{pf.title}-{pf.affected_url or ''}" for pf in prev_findings)
            
            new_count = len(curr_keys - prev_keys)
            resolved_count = len(prev_keys - curr_keys)
            unchanged_count = len(curr_keys & prev_keys)
            
            risk_delta = scan.risk_score - previous_scan.risk_score
            posture_delta = scan.overall_posture_score - previous_scan.overall_posture_score
            
            summary = "Posture worsened" if risk_delta > 0 else ("Posture improved" if risk_delta < 0 else "Posture stable")
            if new_count > 0:
                summary += f" ({new_count} new issues)"
                
            posture_diff = models.PostureDiff(
                current_scan_id=scan.id,
                previous_scan_id=previous_scan.id,
                target_id=target.id,
                new_findings_count=new_count,
                resolved_findings_count=resolved_count,
                unchanged_findings_count=unchanged_count,
                risk_score_delta=risk_delta,
                posture_score_delta=posture_delta,
                summary=summary
            )
            db.add(posture_diff)
            db.commit()
        
        notif_complete = models.Notification(
            title="Scan Completed",
            message=f"Scan #{scan.id} finished with {scan.total_findings} findings (Risk: {scan.risk_score}).",
            type="success",
            entity_type="scan",
            entity_id=scan.id
        )
        db.add(notif_complete)

        if settings.auto_generate_report and not db.query(models.Report).filter(models.Report.scan_id == scan.id).first():
            report = models.Report(
                scan_id=scan.id,
                target_id=scan.target_id,
                title=f"Security Assessment Report - {target.name}",
                executive_summary=f"Automated assessment resulted in {scan.total_findings} findings.",
                html_content=generate_report(db, scan)
            )
            db.add(report)
            db.flush()
            db.add(models.Notification(
                title="Report Generated",
                message=f"Report #{report.id} for scan #{scan.id} is ready.",
                type="success",
                entity_type="report",
                entity_id=report.id
            ))
        
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
