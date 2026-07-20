# Known limitations

# Advanced security analytics

- Analytics methods are deterministic statistical tools, not proof of compromise, malicious intent, future attacks, or guaranteed accuracy.
- Historical sufficiency, missingness, late data, seasonal coverage, reviewed labels, and third-party source quality constrain confidence and quality metrics.
- Recall, F1, and accuracy cannot be claimed without a defensible labeled population; operational coverage is not efficacy.
- SQLite is intended for local/small-scale use, and `process-due` is not a distributed production scheduler. Enterprise real-time streaming is outside Phase 18.
- No external AI service, automatic retraining, automatic containment, automatic case closure, or user punishment is provided.
- Browser automation may be unavailable in some verification environments; HTTP route refresh, production build, lint, API smoke, and documented manual checks are the fallback.

- Vulnerability management uses only stored ThreatScope data. It does not query NVD, CVE services, EPSS, exploit databases, package repositories, cloud CMDBs, or external ticketing systems.
- It does not scan beyond existing safe module workflows, exploit targets, deploy patches, execute commands, install endpoint agents, or change production systems.
- Source severity, optional manually supplied CVSS, internal priority, and accepted residual risk are distinct measures and are not interchangeable.
- Stored-data eligibility and deterministic scoring require analyst review; they are not external exploitability or remediation guarantees.
- Verification relies on later stored evidence, an existing safe scoped module check, or explicit manual confirmation. Inconclusive evidence cannot resolve a vulnerability.
- Risk-acceptance expiry is evaluated during module access and scoring in this local synchronous deployment; there is no unmanaged background scheduler.

- SQLite restore is deliberately staged; final replacement requires a stopped backend and local administrator script.
- Import is validation-only and never merges records into live modules.
- Retention has no automatic scheduler.
- Health does not contact external services; the local test target remains an explicitly authorized workflow.
- Software inventory is manifest-based and is not a vulnerability or license assessment.
- Release artifacts are unsigned release candidates and are not production-certified.
- Audit chaining provides local tamper evidence, not external notarization against a privileged full-database rewrite.
- Demo seeding currently provides a deterministic base scenario and does not auto-create demo users.
- Native PDF generation, cloud backup, external monitoring, telemetry, deployment, and automatic update are absent.
- Local email ownership is not verified and no verification or password-reset email is sent.
- Account recovery requires a local administrator using `scripts/manage_accounts.py`.
- Local authentication does not connect to Google, Gmail, or another external identity provider.
# Threat intelligence

- IOC intelligence is local and offline; there is no external reputation lookup, automatic feed/TAXII polling, DNS resolution, URL fetch, or commercial integration.
- STIX support is a bounded useful subset, not full STIX/TAXII compatibility.
- Correlation uses exact normalized values, URL host context, and explicit CIDR membership; it does not use fuzzy hash or IP matching.
- Scores are deterministic rules, not machine learning or an external reputation claim.
- Watchlists and cases are analyst workflow data only; ThreatScope XDR does not block traffic or create cases without explicit confirmation.

# Detection engineering

- Sigma compatibility is a bounded safe subset, not full Sigma specification or backend conversion support.
- The local ATT&CK-style catalog is an educational 27-technique subset and is not the complete current catalog or proof of organizational coverage.
- Evaluation currently maps stored ThreatScope fields and does not deploy agents, collect live telemetry, query cloud SIEMs, or download external rule feeds.
- Risk and quality scores are deterministic heuristics, not machine learning, threat reputation, or efficacy guarantees.
- There is no command execution, malware execution, active containment, process termination, firewall blocking, or automated alert/case creation.
- SOAR-Lite has no Phase 17 connectors, outbound webhooks, external ticket delivery, remote agent, real containment, automatic case closure, vulnerability resolution, risk acceptance, worker, or scheduler. External response actions are simulation-only. Revoked sessions and delivered notifications cannot be restored; rollback compensates only explicitly supported local state and may be partial.

# Integration Hub

- Connector delivery is synchronous when the bounded due-delivery endpoint is invoked; Phase 17 installs no worker or scheduler.
- OAuth authorization-code flows, arbitrary connector code, custom REST paths, redirects, automatic dead-letter replay, and automatic inbound promotion are intentionally unsupported.
- TAXII support is a bounded pull subset, STIX support is import-oriented, and ticket synchronization is explicit rather than silent bidirectional overwrite.
- Private destinations require exact Administrator approval and remain subject to address validation; this is not a general intranet proxy.
- Connector actions do not provide endpoint isolation, account disabling, firewall or DNS changes, email deletion, or any other real containment.

# Production deployment

- SQLite is limited to single-node, bounded-concurrency deployments and requires one backend worker; shared-volume horizontal scaling is unsupported.
- There is no distributed scheduler, orchestrator-specific deployment, managed-database deployment, zero-downtime multi-node workflow, or guaranteed RPO/RTO.
- Database encryption at rest is not included. Use host/filesystem encryption; backup encryption does not encrypt the live database.
- Certificate issuance/renewal, automatic cloud deployment, automatic rollback, and external deployment promotion are not integrated.
- There is no general SIEM log exporter beyond explicitly configured Phase 17 connectors, and connector egress is disabled by default.
- Production resource defaults require environment-specific capacity review and tuning.
- Visual browser QA remains manual when browser tooling is unavailable; fallback HTTP/build/API checks do not prove pixel-perfect layout.
