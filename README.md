# ThreatScope XDR

Phase 15 adds unified offline-first asset inventory, vulnerability ingestion and prioritization, remediation plans/tasks, SLA governance, expiring risk acceptance, evidence-backed verification, regression reopening, safe static reports, dashboard/search integration, RBAC, audit, and operational backup/retention support. See [Vulnerability Management](docs/VULNERABILITY_MANAGEMENT.md).

ThreatScope XDR is a self-contained local security assessment, SOC simulation, incident-correlation, governance, and reporting platform. Release candidate `1.0.0-rc1` adds authenticated operational health, diagnostics, consistent SQLite backup, staged restore, safe export validation, retention preview/apply, synthetic demo management, local inventory, and bounded release packaging.

Start with [Installation](docs/INSTALLATION.md), then read the [Operations Guide](docs/OPERATIONS_GUIDE.md) and [Security Model](docs/SECURITY_MODEL.md). No cloud service, external telemetry, deployment, or automatic update is included.

Quick local verification:

```text
cd backend
python -m pip install -r requirements.txt
python scripts/create_admin.py
uvicorn app.main:app --reload
```

In another terminal run `cd frontend`, `npm ci`, and `npm run dev`. Docker users may configure `.env` from `.env.example` and run `docker compose up --build -d`.

This is a locally verified release candidate, not a production certification or compliance claim.

## Local accounts and owner setup

ThreatScope XDR supports local registration and sign-in with either a username or an email address. Gmail and non-Gmail addresses are ordinary identifiers; users create a separate ThreatScope password, and the platform does not connect to a mailbox or request email-account credentials.

Create an owner administrator even when test accounts already exist:

```powershell
cd backend
python scripts/manage_accounts.py create-admin
```

No account or password is built in. See `docs/LOCAL_ACCOUNT_SETUP.md` for registration modes, approval, and safe CLI commands.

## Authenticator-app MFA

TOTP enrollment uses the existing encrypted MFA store and standard six-digit, 30-second authenticator codes. Configure a private `THREATSCOPE_MFA_ENCRYPTION_KEY` as described in `.env.example` before enrollment. The frontend renders the backend-generated `otpauth` URI locally with the small `qrcode.react` dependency; setup material is never sent to an external QR service or persisted in browser storage.
# Phase 13: offline threat intelligence

ThreatScope XDR includes a permission-aware Threat Intelligence module for normalized IOC inventory, bounded CSV/JSON/STIX/text imports, protected watchlists, campaigns, analyst relationships, stored-data-only cross-module sightings, deterministic match risk, explicit incident-case escalation, and static HTML reports. It performs no external IOC lookup or automated blocking. See [docs/THREAT_INTELLIGENCE.md](docs/THREAT_INTELLIGENCE.md).

# Phase 14: offline detection engineering

Detection Engineering adds native and bounded Sigma-compatible rules, immutable versions, synthetic positive/negative tests, test-gated activation, protected demonstration packs, a local educational ATT&CK subset, deterministic historical evaluation, suppressions, explicit alert/case promotion, and static reports. It evaluates stored records only and never executes commands or downloads rules. See [docs/DETECTION_ENGINEERING.md](docs/DETECTION_ENGINEERING.md).
