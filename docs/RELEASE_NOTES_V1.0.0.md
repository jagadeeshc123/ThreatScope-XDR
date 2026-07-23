# ThreatScope XDR 1.0.0 release notes

Status: final candidate; the `v1.0.0` Git tag and release publication are intentionally not created by Phase 20.

## Overview and capabilities

ThreatScope XDR is a self-hosted, offline-first platform for authorized security assessment, investigation, governance, and operational evidence. v1 consolidates Web Exposure, API Security/Authorization Review, SOC simulation, document/phishing static analysis, correlation/cases, governance, local authentication/MFA/RBAC, threat intelligence, detection engineering, vulnerability management, SOAR-Lite, controlled integrations, deterministic analytics, and production operations. See the [module matrix](MODULE_CAPABILITY_MATRIX.md).

The architecture is a React SPA, FastAPI/SQLAlchemy backend, single-node SQLite store, and optional Docker Compose profiles. Production uses a TLS-terminating Nginx edge, an internal-only one-worker backend, file-mounted secrets, strict preflight, secure cookies, redacted structured logging, rootless/read-only containers, bounded resources, readiness/build posture endpoints, and application-consistent backup/restore workflows.

## Security model and defaults

Server-owned RBAC, object checks, CSRF on authenticated mutations, opaque sessions, Argon2id, TOTP MFA, lockout/rate limiting, audit hash chaining, bounded validation, safe static reports, upload controls, SSRF destination policy, encrypted write-only connector credentials, and disabled-by-default production egress are implemented controls—not certification or proof that the software is vulnerability-free. Production also disables registration, API docs, debug/reload, and demo seeding by default. No default credential exists.

## Upgrade notes

Back up and verify the Phase 19 database, preserve encryption keys and configuration, build images with `THREATSCOPE_APP_VERSION=1.0.0` plus the full reviewed revision/timestamp, run preflight, start, verify readiness/authentication/module access/audit, and retain rollback criteria. Application 1.0.0 intentionally keeps `threatscope-schema-v19`; no persistent migration is introduced. Follow [Upgrade and Rollback](UPGRADE_AND_ROLLBACK.md).

## Important limitations

SQLite supports the documented single-node, one-worker topology and bounded write concurrency; there is no managed database, horizontal cluster, zero-downtime upgrade, automatic rollback, automatic certificate issuance, or guaranteed RPO/RTO. Host/filesystem encryption, backups, TLS trust, and tuning are operator responsibilities. Findings are not proof of exploitation; anomalies are not proof of compromise. SOAR performs simulations/bounded local workflows, not real containment, case closure, or user punishment. Connector configuration/queueing does not prove delivery. Analytics uses no external AI/model and cannot claim accuracy/recall/F1 without defensible labels. See [Known Limitations](KNOWN_LIMITATIONS.md).

## Browser QA and maintenance

The final audit records whether in-app browser verification or the approved build/API/route/static-accessibility fallback ran. Browser fallback is not visual browser testing. After v1.0.0, maintenance is limited to confirmed defects, security fixes, dependency/compatibility work, documentation corrections, and carefully reviewed operational improvements. No Phase 21 is planned.
