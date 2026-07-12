from jinja2 import Environment
from app import models

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ report_title }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            --primary: #2563eb;
            --text: #1e293b;
            --text-muted: #64748b;
            --bg: #ffffff;
            --border: #e2e8f0;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #94a3b8;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            color: var(--text);
            background-color: #f8fafc;
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }
        
        .report-container {
            max-width: 900px;
            margin: 40px auto;
            background: var(--bg);
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        @media print {
            body { background: white; margin: 0; }
            .report-container { margin: 0; box-shadow: none; max-width: 100%; border-radius: 0; }
            .page-break { page-break-before: always; }
        }
        
        .cover-page {
            text-align: center;
            padding: 100px 40px;
            border-bottom: 8px solid var(--primary);
            background-color: #0f172a;
            color: white;
        }
        
        .cover-page h1 { font-size: 36px; margin-bottom: 10px; font-weight: 700; }
        .cover-page p { font-size: 18px; color: #cbd5e1; }
        
        .section { padding: 40px; }
        .section-title {
            font-size: 24px;
            border-bottom: 2px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 20px;
            color: #0f172a;
            font-weight: 600;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            background: #f1f5f9;
            padding: 20px;
            border-radius: 6px;
            margin-bottom: 30px;
        }
        .metadata-item strong { display: block; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
        .metadata-item span { font-size: 16px; font-weight: 500; }
        
        .risk-score-container {
            text-align: center;
            padding: 30px;
            border: 1px solid var(--border);
            border-radius: 6px;
            margin-bottom: 30px;
            display: flex; 
            justify-content: space-around; 
            gap: 20px;
        }
        .risk-score { font-size: 48px; font-weight: 700; color: var(--primary); }
        
        table { width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background-color: #f8fafc; font-weight: 600; color: var(--text-muted); font-size: 14px; }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        .badge.critical { background-color: var(--critical); }
        .badge.high { background-color: var(--high); }
        .badge.medium { background-color: var(--medium); }
        .badge.low { background-color: var(--low); }
        .badge.info { background-color: var(--info); }
        
        .finding-card {
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            page-break-inside: avoid;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .finding-header h3 { margin: 0; font-size: 18px; color: #0f172a; }
        
        .finding-details h4 { margin: 20px 0 8px 0; color: #334155; font-size: 15px; font-weight: 600; }
        .finding-details p { margin: 0 0 10px 0; color: #475569; font-size: 14px; }
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 5px;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="cover-page">
            <h1>Web Application Exposure & Security Posture Report</h1>
            <p>Confidential Report for {{ target.name }}</p>
            <p>{{ report_company_name }}</p>
            <div style="margin-top: 40px; font-size: 14px; color: #94a3b8;">
                Generated on: {{ scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else 'N/A' }}
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">1. Executive Summary</h2>
            <p>This report details the findings from the automated Web Application Exposure and Security Posture assessment conducted against {{ target.name }}. The assessment focused on client-side security mechanisms, transport layer configuration, public exposure, and overall browser hygiene.</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">2. Assessment Scope</h2>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Target Name</strong>
                    <span>{{ target.name }}</span>
                </div>
                <div class="metadata-item">
                    <strong>Target URL</strong>
                    <span>{{ target.base_url }}</span>
                </div>
                <div class="metadata-item">
                    <strong>Scan Profile</strong>
                    <span>{{ scan.profile }}</span>
                </div>
                <div class="metadata-item">
                    <strong>Total Findings</strong>
                    <span>{{ findings|length }}</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">3. Web Exposure Overview</h2>
            <p>During the assessment, {{ scan.total_findings }} security issues were identified affecting the web application's exposure and client-side posture.</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">4. Security Posture Score</h2>
            <div class="risk-score-container">
                <div>
                    <div style="font-size: 14px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.05em;">Posture Score</div>
                    <div class="risk-score" style="color: var(--primary);">{{ scan.overall_posture_score }} / 100</div>
                    <p style="margin-top: 10px; color: var(--text-muted); font-size: 14px; max-width: 300px; margin-left: auto; margin-right: auto;">
                        Measures browser-facing web application exposure and hardening.
                    </p>
                </div>
                <div>
                    <div style="font-size: 14px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.05em;">Overall Risk Score</div>
                    <div class="risk-score">{{ scan.risk_score }} / 10</div>
                    <p style="margin-top: 10px; color: var(--text-muted); font-size: 14px; max-width: 300px; margin-left: auto; margin-right: auto;">
                        Based on severity weightings of identified vulnerabilities.
                    </p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">5. Crawl Map Summary</h2>
            <p>The scanner mapped the web application structure to identify accessible resources and exposed forms.</p>
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Forms</th>
                    </tr>
                </thead>
                <tbody>
                    {% for node in scan.crawl_nodes[:10] %}
                    <tr>
                        <td>{{ node.path }}</td>
                        <td>{{ node.status_code }}</td>
                        <td>{{ "Yes" if node.has_forms else "No" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if scan.crawl_nodes|length > 10 %}
            <p style="font-size: 12px; color: var(--text-muted);">Showing top 10 crawled pages.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2 class="section-title">6. Posture Drift Since Previous Scan</h2>
            <p>This section evaluates how the application's posture has changed compared to the previous baseline scan.</p>
            {% if drift %}
            <p><strong>Status:</strong> {{ drift.summary }}</p>
            <p><strong>New Findings:</strong> {{ drift.new_findings_count }}</p>
            <p><strong>Resolved Findings:</strong> {{ drift.resolved_findings_count }}</p>
            <p><strong>Risk Score Delta:</strong> {{ drift.risk_score_delta }}</p>
            <p><strong>Posture Score Delta:</strong> {{ drift.posture_score_delta }}</p>
            {% else %}
            <p>No previous baseline scan available for comparison.</p>
            {% endif %}
        </div>

        <div class="page-break"></div>
        
        <div class="section">
            <h2 class="section-title">7. Browser Security Controls</h2>
            <p>Score: {{ scan.posture_browser_defense }} / 100</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">8. Session & Cookie Safety</h2>
            <p>Score: {{ scan.posture_session_safety }} / 100</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">9. Public Exposure Findings</h2>
            <p>Score: {{ scan.posture_exposure_hygiene }} / 100</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">10. Authentication Surface Review</h2>
            <p>Score: {{ scan.posture_authentication_surface }} / 100</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">11. Policy Compliance Summary</h2>
            <p>The application was evaluated against the configured compliance packs. See the VulnScope dashboard for the complete pass/fail checks.</p>
        </div>
        
        <div class="page-break"></div>
        
        <div class="section">
            <h2 class="section-title">11. Detailed Findings</h2>
            {% for finding in findings %}
            <div class="finding-card">
                <div class="finding-header">
                    <h3>{{ finding.title }}</h3>
                    <span class="badge {{ finding.severity }}">{{ finding.severity }}</span>
                </div>
                <div class="finding-details">
                    <h4>Description</h4>
                    <p>{{ finding.description }}</p>
                    <h4>Affected URL</h4>
                    <div class="code-block">{{ finding.affected_url }}</div>
                    {% if finding.evidence %}
                    <h4>Technical Evidence</h4>
                    <div class="code-block">{{ finding.evidence }}</div>
                    {% endif %}
                    <h4>Impact</h4>
                    <p>{{ finding.impact }}</p>
                    <h4>Remediation</h4>
                    <p>{{ finding.remediation }}</p>
                </div>
            </div>
            {% endfor %}
            {% if not findings %}
            <p>No vulnerabilities were identified during this assessment.</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2 class="section-title">12. Remediation Roadmap</h2>
            <p>Focus on addressing Critical and High severity findings first, then proceed to harden browser defenses and session management controls as outlined in the findings.</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">13. Evidence Appendix</h2>
            <p>Refer to the VulnScope dashboard for raw HTTP and HTML evidence snapshots captured during this assessment.</p>
        </div>
        
        <div class="section">
            <h2 class="section-title">14. Authorized Testing Disclaimer</h2>
            <p style="font-size: 14px;">This automated assessment was generated by VulnScope. Validated for authorized testing only. The findings represented in this document are point-in-time observations and may not encompass all security risks.</p>
        </div>
        
        <div class="footer">
            {{ report_footer_text }} | {{ scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else '' }}
        </div>
    </div>
</body>
</html>
"""

def generate_report(db, scan: models.Scan) -> str:
    template = Environment(autoescape=True).from_string(REPORT_TEMPLATE)
    findings = scan.findings
    settings = db.query(models.AppSettings).first()
    
    # fetch drift
    drift = db.query(models.PostureDiff).filter(models.PostureDiff.current_scan_id == scan.id).first()
    
    html_content = template.render(
        report_title="Web Application Exposure & Security Posture Report",
        target=scan.target,
        scan=scan,
        findings=findings,
        drift=drift,
        report_company_name=settings.report_company_name if settings else "VulnScope",
        report_footer_text=settings.report_footer_text if settings else "Generated by VulnScope - Authorized Testing Only"
    )
    return html_content
