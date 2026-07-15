# Operations guide

`GET /api/health/live` is a minimal public liveness signal. `GET /api/health/ready` is a minimal public readiness signal and returns bounded `503` when a required check fails. Authenticated operators with `operations:diagnostics` can inspect detailed checks, aggregate diagnostics, and setting-name-only configuration validation under `/api/operations`.

Operational jobs are synchronous and bounded; their status, progress, safe summary, and error code are retained. JSON-compatible request logs include request ID, route, method, status, duration, and safe actor ID. Recursive redaction excludes bodies, passwords, cookies, authorization, CSRF, MFA, tokens, environment secrets, and sensitive paths. Security audit events remain the authoritative tamper-evident action record.

Runtime directories are configurable and generated beneath an allowlisted base. APIs store relative paths and downloads always pass through authorized backend routes. No scheduler, cloud storage, external telemetry, automatic restart, or update service is present.

## Local account operations

From `backend/`, use `python scripts/manage_accounts.py list`, `create-admin`, `reset-password --identifier user@example.com`, or `disable --identifier smoke.admin`. The list command shows only ID, username, masked email, status, roles, and demo status. It never displays passwords, hashes, sessions, MFA secrets, or recovery codes. Owner administrators may be added while smoke-test users exist; those records are tests, not default credentials. Registration approvals are managed under Administration / Registrations, and no email notification is sent.
