# Security model

## Phase 15 vulnerability-management boundary

Vulnerability management reads only local stored ThreatScope records. Asset synchronization never resolves DNS or probes a network. Ingestion eligibility prevents ordinary SOC events, IOC matches, and detection matches from automatically becoming vulnerabilities. Imported evidence is hostile: server responses truncate and redact it, reports escape and defang it, UI views render it as inert text, and report frames are sandboxed. Resolution is server-authoritative and requires passed verification evidence. All mutations are authenticated, CSRF protected, permission checked, bounded, and audit chained. No Phase 15 path invokes a shell, subprocess, remote command, external URL, patch mechanism, or ticketing service.

ThreatScope uses local Argon2id accounts, opaque hashed server-side sessions in HttpOnly cookies, per-session CSRF tokens, TOTP MFA with encrypted secrets, one-time hashed recovery codes, deterministic RBAC, and a hash-chained `SecurityAuditEvent` ledger. Operational permissions are separately assigned to administrator, analyst, and auditor roles; backend authorization remains authoritative.

Full database backups are restricted sensitive recovery artifacts. Safe export ZIPs instead include bounded redacted JSON summaries and never include authentication records, databases, environment values, original PDFs, emails, attachments, raw logs, or executable content. Validation never extracts untrusted archives or contacts external systems.

Operational logs and audit events have different purposes. Both exclude secrets; audit events record actor, outcome, request ID, and bounded metadata. The platform has no external telemetry, cloud upload, identity provider, email/SMS/Slack alerts, or automatic update path.

Public registration uses the same Argon2id, lockout, session, CSRF, MFA, RBAC, and audit controls. Email addresses, including Gmail addresses, are identifiers only; ThreatScope passwords are separate local secrets. Email ownership is not verified because outbound email is outside scope. No mailbox credentials, external identity tokens, or mail APIs are used.

The protected Registered User role contains only dashboard, own-profile, and notification permissions. Registration payloads forbid role, status, administrator, and MFA fields. Approval is explicit, and Administrator assignment requires additional confirmation.
# Threat-intelligence safety boundary

Threat-intelligence inputs remain inert text. The backend does not resolve, fetch, preview, enrich, execute, block, or otherwise interact with an indicator. Imports are bounded to 2 MiB and 5,000 records, parsed without archive extraction or subprocesses, and original bytes are discarded. The frontend defangs indicators and never generates automatic anchors. Mutations require CSRF and the relevant `threat_intel:*` permission; escalation additionally requires `cases:create` and explicit confirmation. See `THREAT_INTELLIGENCE.md` for scoring and lifecycle rules.

# Detection-engineering safety boundary

Rule content and event evidence are hostile inert data. YAML uses the safe loader after rejecting aliases, anchors, and custom tags. Conditions are parsed by a bounded allowlisted parser—not `eval`, `exec`, regex, templates, shells, PowerShell, subprocesses, or dynamic code generation. Historical evaluation is read-only, deterministic, synchronous, and bounded. URLs, command lines, paths, and evidence are escaped/redacted text. Alert and case promotion require explicit confirmation and additional permissions. See `DETECTION_ENGINEERING.md`.
