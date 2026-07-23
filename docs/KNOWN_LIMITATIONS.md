# Known limitations

- Production supports one backend worker and a single-node SQLite database. Write concurrency is bounded; horizontal/shared-volume SQLite clusters and managed-database deployment are unsupported.
- The live database is not encrypted by the application. Deployment owners provide host/filesystem encryption, permissions, monitoring, capacity planning, and environment-specific CPU/memory/PID tuning.
- There is no guaranteed RPO/RTO, zero-downtime upgrade, automatic rollback, automatic cloud/orchestrator deployment, automatic certificate issuance/renewal, or automatic update.
- Backup/restore is local and operator-driven. Restore is staged, requires a stopped backend for final replacement, affects sessions, and may require downtime. Audit chaining is local tamper evidence, not external notarization.
- Findings are not proof of exploitation; risk/posture/confidence scores are deterministic decision aids, not certification, external reputation, or guaranteed detection. Governance records do not establish regulatory compliance.
- Document/phishing analysis is bounded static/offline analysis and is not a definitive malware/phishing verdict. Links and embedded code are not executed.
- SOC, threat intelligence, detection, and vulnerability workflows use imported, synthetic, or already stored data. There is no endpoint agent, live SIEM collection, public reputation/CVE/EPSS/package lookup, exploit execution, patch deployment, or malware deletion.
- SOAR-Lite never executes arbitrary commands or performs real external containment. It does not automatically isolate endpoints, disable accounts, block firewalls/DNS, delete email/malware, close cases, resolve vulnerabilities, punish users, deploy, or roll back production.
- Integration delivery is synchronous/bounded when explicitly invoked; no distributed worker/scheduler is installed. Configured or queued connectors are not proof of successful third-party delivery. Production egress is disabled by default, and external availability/credentials remain operator responsibilities.
- STIX/TAXII and Sigma support useful bounded subsets, not complete specification/backend compatibility. The bundled ATT&CK-style catalog is educational and not proof of coverage.
- Analytics uses deterministic local statistical logic, not external AI. It does not retrain automatically. An anomaly is a review signal, not proof of compromise; accuracy/recall/F1 are unavailable without defensible reviewed labels.
- Local accounts do not verify email ownership or send password-reset/verification mail. Recovery requires a local administrator. No external identity provider is included.
- Retention/process-due workflows require explicit invocation; there is no distributed scheduler. Native PDF generation, cloud backup, external telemetry, and managed monitoring are absent.
- Production visual/browser/assistive-technology QA may require manual execution when browser tooling is unavailable. Build/API/route/static review fallback does not prove pixel-perfect layout, formal WCAG conformance, or measured contrast ratios.
- Dependency inventory is manifest/environment based and is not a vulnerability, license, CycloneDX, or SPDX assessment. Vulnerability-scan results are not claimed unless a supported scanner actually runs.
