# Known limitations

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
