# ThreatScope XDR

ThreatScope XDR 1.0.0 is a self-hosted, offline-first security assessment and operations workspace. It combines authorized web/API assessment, SOC and document/phishing analysis, correlation and cases, governance, local identity, threat intelligence, detection engineering, vulnerability workflows, SOAR-Lite simulations, controlled connectors, analytics, and platform operations. It is not a hosted SaaS, compliance certification, penetration-test certification, or guarantee that findings were exploited.

Use the platform only with explicit authorization. Findings and anomalies are review signals. SOAR actions do not provide real external containment, connector configuration is not proof of delivery, and the local analytics layer makes no external AI/model call.

Release metadata: application `1.0.0`; database schema `threatscope-schema-v19`. Schema v19 remains unchanged because Phase 20 adds no persistent model.

## Major modules

- Web Exposure, API Security, and Authorization Review
- SOC Monitor, Document Threat Analysis, and Phishing Defense
- Unified Correlation, Cases, Governance, and Compliance
- Local accounts, MFA, sessions, RBAC, CSRF, and security audit
- Threat Intelligence, Detection Engineering, and Vulnerability Management
- SOAR-Lite, Integration Hub, and Advanced Security Analytics
- Platform Operations, backup/restore, diagnostics, release inventory, and production readiness

See the [module capability matrix](docs/MODULE_CAPABILITY_MATRIX.md) for exact boundaries.

## Development quick start

Prerequisites are Python 3.11+, Node 20+, and npm. No account or password is built in.

```text
cd backend
python -m pip install -r requirements.txt
python scripts/manage_accounts.py create-admin
uvicorn app.main:app --reload
```

In another terminal:

```text
cd frontend
npm ci
npm run dev
```

Docker development users can copy the documented non-secret settings from `.env.example` into an ignored `.env`, then run `docker compose up --build -d`. The local test target is the only preconfigured scan target; do not substitute an unauthorized public system.

## Production entry point

Production is a single-node, one-worker SQLite deployment behind an Nginx HTTPS edge. Start with [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md), [.env.production.example](.env.production.example), [Secrets Management](docs/SECRETS_MANAGEMENT.md), and [TLS Reverse Proxy](docs/TLS_REVERSE_PROXY.md). Operators supply unique file-mounted secrets, trusted TLS material, host/filesystem encryption, backups, and environment-specific resource limits. Production disables registration, API docs, debug/reload, demo seeding, and connector egress by default.

## Architecture and security principles

The React frontend calls a FastAPI/SQLAlchemy backend. Server-owned permissions are authoritative; hiding a link is never authorization. Authenticated mutations require a secure session, permission, CSRF token, and audit handling. Sessions are opaque and cookie-bound. Outbound-capable workflows use explicit action, scheme/host/address policy, redirect rejection, TLS verification, response limits, and timeouts. Reports are static escaped HTML without scripts or remote assets. Uploaded analysis inputs are bounded and are not directly served from a public static directory.

SQLite, filesystem artifacts, and configured connectors remain inside the deployment trust boundary. No external telemetry, hosted model, model download, automatic deployment, or automatic certificate issuance is included.

## Verification

```text
cd backend
python -m compileall app tests scripts
python -m unittest discover -s tests -v
python scripts/run_tests_network_disabled.py
python scripts/verify_vulnscope.py
python -m pip check

cd ../frontend
npm ci
npm run build
npm run lint
npm ls --depth=0

cd ..
docker compose config
```

Production builds intentionally omit source maps. The CI workflow is verification-only and has read-only repository permissions; it does not deploy or publish a release.

## Documentation index

- Setup and architecture: [Installation](docs/INSTALLATION.md), [Architecture](docs/ARCHITECTURE.md), [Project overview](PROJECT_OVERVIEW.md)
- Audience guides: [User Guide](docs/USER_GUIDE.md), [Administrator Guide](docs/ADMINISTRATOR_GUIDE.md), [Developer Guide](docs/DEVELOPER_GUIDE.md), [Demo Guide](docs/DEMO_GUIDE.md)
- Production: [Deployment](docs/PRODUCTION_DEPLOYMENT.md), [Configuration](docs/PRODUCTION_CONFIGURATION.md), [Secrets](docs/SECRETS_MANAGEMENT.md), [TLS](docs/TLS_REVERSE_PROXY.md), [Headers](docs/SECURITY_HEADERS.md), [Container hardening](docs/CONTAINER_HARDENING.md)
- Security: [Security Model](docs/SECURITY_MODEL.md), [Threat Model](docs/THREAT_MODEL.md), [Permissions Matrix](docs/PERMISSIONS_MATRIX.md), [CSRF Mutation Inventory](docs/CSRF_MUTATION_INVENTORY.md), [Data Handling](docs/DATA_HANDLING.md), [Security reporting](SECURITY.md)
- Operations: [Operations Guide](docs/OPERATIONS_GUIDE.md), [Backup and Restore](docs/BACKUP_AND_RESTORE.md), [Disaster Recovery](docs/DISASTER_RECOVERY.md), [Upgrade and Rollback](docs/UPGRADE_AND_ROLLBACK.md), [Troubleshooting](docs/TROUBLESHOOTING.md)
- Reference: [API Reference](docs/API_REFERENCE.md), [Module Capability Matrix](docs/MODULE_CAPABILITY_MATRIX.md), [Known Limitations](docs/KNOWN_LIMITATIONS.md), [Contributing](CONTRIBUTING.md)
- Release: [Release Notes](docs/RELEASE_NOTES_V1.0.0.md), [Changelog](docs/CHANGELOG.md), [Final Audit](docs/FINAL_AUDIT_REPORT.md), [v1 Release Checklist](docs/V1_RELEASE_CHECKLIST.md), [Release Process](docs/RELEASE_PROCESS.md)

## Support and maintenance

After v1.0.0 the planned feature roadmap is frozen. Maintenance is limited to confirmed defects, security fixes, dependency/compatibility maintenance, documentation corrections, and carefully reviewed operational improvements. Use the repository's private security-advisory mechanism for sensitive reports; do not include usable secrets or test systems you do not own or have permission to assess.
