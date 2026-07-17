# Operations guide

## Vulnerability-management operations

Run asset synchronization and finding ingestion from the Vulnerability Management overview. Both jobs process at most 5,000 stored records per request and record bounded run history. Repeated runs are safe and idempotent. Administrators may explicitly recalculate no more than 500 active SLA records per request; historical due dates otherwise remain fixed. Backup and restore sentinels include the Phase 15 inventory, vulnerability, occurrence, evidence, remediation, acceptance, and verification tables. Diagnostics list the module and safely count accessible tables. Retention policies may preview and remove old completed synchronization/ingestion runs only; active/resolved vulnerabilities and evidence are not retention targets.

Demo seeding creates one custom asset owned by the exact `platform_operations_demo` source namespace. Demo reset deletes only assets with that marker; synchronized or analyst-created assets and all vulnerability, occurrence, evidence, workflow, exception, verification, and report records are preserved.

`GET /api/health/live` is a minimal public liveness signal. `GET /api/health/ready` is a minimal public readiness signal and returns bounded `503` when a required check fails. Authenticated operators with `operations:diagnostics` can inspect detailed checks, aggregate diagnostics, and setting-name-only configuration validation under `/api/operations`.

Operational jobs are synchronous and bounded; their status, progress, safe summary, and error code are retained. JSON-compatible request logs include request ID, route, method, status, duration, and safe actor ID. Recursive redaction excludes bodies, passwords, cookies, authorization, CSRF, MFA, tokens, environment secrets, and sensitive paths. Security audit events remain the authoritative tamper-evident action record.

Runtime directories are configurable and generated beneath an allowlisted base. APIs store relative paths and downloads always pass through authorized backend routes. No scheduler, cloud storage, external telemetry, automatic restart, or update service is present.

## Local account operations

From `backend/`, use `python scripts/manage_accounts.py list`, `create-admin`, `reset-password --identifier user@example.com`, or `disable --identifier smoke.admin`. The list command shows only ID, username, masked email, status, roles, and demo status. It never displays passwords, hashes, sessions, MFA secrets, or recovery codes. Owner administrators may be added while smoke-test users exist; those records are tests, not default credentials. Registration approvals are managed under Administration / Registrations, and no email notification is sent.
# Threat-intelligence operations

Use `/api/threat-intel/correlation/run` only for bounded scans of existing database records. A failed run rolls back its new sightings/matches and records a failed run manifest; previous matches remain intact. Monitor Phase 13 table health in Operations diagnostics. Database backups include Phase 13 automatically. Retention policies for old IOC import manifests and completed/failed correlation-run manifests are dry-run-first; indicators are retained when they expire. No threat-intelligence operation requires outbound connectivity.

# Detection-engineering operations

Use `/api/detections/executions` for bounded synchronous scans of existing stored events. Requests are limited to 25 rules and 5,000 records, and fingerprinted matches prevent repeated duplicate creation. Diagnostics list the module and database table health; full SQLite backup/restore includes all detection tables. Dry-run-first retention covers completed executions and generated reports, while immutable rule versions and case-linked records are not automatically deleted. Demo reset removes only explicitly tagged analyst demo rules/executions and preserves protected system packs.
