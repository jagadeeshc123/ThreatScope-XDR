from jinja2 import Template
from app import models

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {{ target.name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; line-height: 1.6; }
        h1, h2, h3 { color: #1a202c; }
        .header { border-bottom: 2px solid #2b6cb0; padding-bottom: 10px; margin-bottom: 20px; }
        .summary-box { background: #edf2f7; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f7fafc; }
        .severity-critical { color: #e53e3e; font-weight: bold; }
        .severity-high { color: #dd6b20; font-weight: bold; }
        .severity-medium { color: #d69e2e; font-weight: bold; }
        .severity-low { color: #3182ce; font-weight: bold; }
        .severity-info { color: #718096; font-weight: bold; }
        .finding { border: 1px solid #e2e8f0; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
        .finding h3 { margin-top: 0; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; text-transform: uppercase; }
        .bg-critical { background: #e53e3e; }
        .bg-high { background: #dd6b20; }
        .bg-medium { background: #d69e2e; }
        .bg-low { background: #3182ce; }
        .bg-info { background: #718096; }
    </style>
</head>
<body>
    <div class="header">
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>{{ report.title }}</title>
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
                max-w-width: 900px;
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
            }
            .risk-score { font-size: 48px; font-weight: 700; color: var(--primary); }
            
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
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
                <h1>Web Application Security Assessment</h1>
                <p>Confidential Report for {{ target.name }}</p>
                <div style="margin-top: 40px; font-size: 14px; color: #94a3b8;">
                    Generated on: {{ scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else 'N/A' }}
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">1. Executive Summary</h2>
                
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
                
                <div class="risk-score-container">
                    <div style="font-size: 14px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.05em;">Overall Risk Score</div>
                    <div class="risk-score">{{ scan.risk_score }} / 100</div>
                    <p style="margin-top: 10px; color: var(--text-muted); font-size: 14px; max-width: 600px; margin-left: auto; margin-right: auto;">
                        The risk score is calculated based on the CVSS-inspired severity weightings of all identified vulnerabilities. A higher score indicates a greater aggregate risk to the application.
                    </p>
                </div>
            </div>
            
            <div class="page-break"></div>
            
            <div class="section">
                <h2 class="section-title">2. Findings Summary</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulnerability Title</th>
                            <th>Category</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in findings %}
                        <tr>
                            <td><span class="badge {{ finding.severity }}">{{ finding.severity }}</span></td>
                            <td style="font-weight: 500; color: #0f172a;">{{ finding.title }}</td>
                            <td>{{ finding.category }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div class="page-break"></div>
            
            <div class="section">
                <h2 class="section-title">3. Detailed Technical Findings</h2>
                
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
            </div>
            
            <div class="footer">
                This automated assessment was generated by VulnScope. Validated for authorized testing only.<br>
                {{ scan.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.completed_at else '' }}
            </div>
        </div>
    </body>
    </html>
    """

def generate_report(db, scan: models.Scan) -> str:
    template = Template(REPORT_TEMPLATE)
    findings = scan.findings
    html_content = template.render(
        target=scan.target,
        scan=scan,
        findings=findings
    )
    return html_content
