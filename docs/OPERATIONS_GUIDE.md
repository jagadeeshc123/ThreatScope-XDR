# Operations guide

`GET /api/health/live` is a minimal public liveness signal. `GET /api/health/ready` is a minimal public readiness signal and returns bounded `503` when a required check fails. Authenticated operators with `operations:diagnostics` can inspect detailed checks, aggregate diagnostics, and setting-name-only configuration validation under `/api/operations`.

Operational jobs are synchronous and bounded; their status, progress, safe summary, and error code are retained. JSON-compatible request logs include request ID, route, method, status, duration, and safe actor ID. Recursive redaction excludes bodies, passwords, cookies, authorization, CSRF, MFA, tokens, environment secrets, and sensitive paths. Security audit events remain the authoritative tamper-evident action record.

Runtime directories are configurable and generated beneath an allowlisted base. APIs store relative paths and downloads always pass through authorized backend routes. No scheduler, cloud storage, external telemetry, automatic restart, or update service is present.
