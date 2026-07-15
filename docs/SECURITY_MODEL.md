# Security model

ThreatScope uses local Argon2id accounts, opaque hashed server-side sessions in HttpOnly cookies, per-session CSRF tokens, TOTP MFA with encrypted secrets, one-time hashed recovery codes, deterministic RBAC, and a hash-chained `SecurityAuditEvent` ledger. Operational permissions are separately assigned to administrator, analyst, and auditor roles; backend authorization remains authoritative.

Full database backups are restricted sensitive recovery artifacts. Safe export ZIPs instead include bounded redacted JSON summaries and never include authentication records, databases, environment values, original PDFs, emails, attachments, raw logs, or executable content. Validation never extracts untrusted archives or contacts external systems.

Operational logs and audit events have different purposes. Both exclude secrets; audit events record actor, outcome, request ID, and bounded metadata. The platform has no external telemetry, cloud upload, identity provider, email/SMS/Slack alerts, or automatic update path.

Public registration uses the same Argon2id, lockout, session, CSRF, MFA, RBAC, and audit controls. Email addresses, including Gmail addresses, are identifiers only; ThreatScope passwords are separate local secrets. Email ownership is not verified because outbound email is outside scope. No mailbox credentials, external identity tokens, or mail APIs are used.

The protected Registered User role contains only dashboard, own-profile, and notification permissions. Registration payloads forbid role, status, administrator, and MFA fields. Approval is explicit, and Administrator assignment requires additional confirmation.
