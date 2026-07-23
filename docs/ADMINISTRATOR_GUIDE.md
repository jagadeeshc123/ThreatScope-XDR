# Administrator guide

## Secure initial setup

Install pinned dependencies, configure an ignored environment file, and create the first owner interactively with `backend/scripts/manage_accounts.py create-admin`. There are no default credentials. Use unique randomly generated session, MFA, connector, and backup-encryption keys; production reads them from protected files. Do not reuse examples. Configure exact hosts/origins/trusted proxies and deployment-owned TLS before starting production.

## Identity and access

Review the [permissions matrix](PERMISSIONS_MATRIX.md) before assigning Administrator, Security Analyst, Auditor, Executive Viewer, or Registered User. Keep least privilege and separation of duties for SOAR approvals and high-risk operations. Production registration is disabled by default; if approval mode is intentionally enabled, review each local account. Require MFA according to local policy, protect recovery material, review active sessions, revoke suspected sessions, and use the local account CLI for recovery. Email ownership is not verified.

## Production operations

Run production preflight before startup and after configuration changes. Keep API docs, debug/reload, demo mode, and connector egress disabled unless a reviewed requirement says otherwise. Inspect readiness, structured redacted logs, disk capacity, SQLite integrity/WAL behavior, container health, and resource use. The supported design is one backend worker and one SQLite node; do not place the database on an unsupported shared cluster filesystem.

## Backups, restore, retention, and audit

Schedule application-consistent backups outside the application, verify them, encrypt/copy them to an access-controlled failure domain, and test restore. The UI stages restore; final replacement is offline and revokes restored sessions according to policy. Confirm schema compatibility, encrypted connector fields, audit-chain integrity, and readiness afterward. Preview retention before apply; deletion ordering preserves referential integrity. Verify the local audit chain regularly, while recognizing that it is tamper evidence rather than external notarization.

## Connector and analytics governance

Keep connector egress disabled by default. Approve exact schemes, hosts, ports, and any private destination; test explicitly and review retries/dead letters without assuming delivery. Rotate credential keys using documented operational procedures. Review detector versions, baseline sufficiency, backtests, drift, suppressions, feedback, and quality claims. There is no external model or automatic retraining.

## Upgrade, rollback, and maintenance

Before upgrade: read release notes, validate configuration, identify application/schema versions, create and verify a backup, and record rollback criteria. Phase 20 keeps schema v19, so a Phase 19 database is compatible; do not regenerate encryption keys. Image rollback may be enough when schema/configuration remain compatible. Restore is required only when data/schema state requires it and causes downtime/session implications. Follow [Upgrade and Rollback](UPGRADE_AND_ROLLBACK.md) and enter maintenance mode after v1.0.0.
