# Threat model

## Assets, actors, and trust boundaries

Assets include local credentials and MFA secrets, opaque sessions/CSRF tokens, permissions, assessment evidence, uploads during analysis, reports, connector credentials, encryption keys, the SQLite database, backups, audit chain, configuration, TLS material, and release images. Actors include anonymous visitors, registered users, analysts, auditors, executives, administrators, deployment operators, compromised accounts, malicious input authors, and external connector destinations.

Trust boundaries exist at the browser/HTTPS edge, edge/backend network, authenticated API, upload/parser boundary, SQLite/filesystem, file-mounted secrets, backup/restore staging, connector egress, inbound signed webhook, container runtime, and source/dependency/build pipeline.

## Entry points and threats

- Authentication: brute force, enumeration, weak/reused credentials, account-state bypass, MFA/recovery abuse, session theft/fixation, insecure cookies, and false expiry. Mitigations include Argon2id password handling, safe errors, lockout/rate limits, account-state checks, opaque rotated sessions, bounded idle/absolute lifetime, revocation/logout, TOTP/recovery controls, secure production cookies, and no default credentials. Residual risk includes endpoint compromise and administrator-led recovery.
- Authorization/IDOR: guessed identifiers, list/export leakage, hidden-link reliance, and credential disclosure. Server-owned route permissions, object lookups, recipient filters, 404/403 policy, protected downloads, and write-only connector secrets reduce risk. Administrators remain highly trusted.
- CSRF/XSS/report injection: authenticated mutations require token validation; React escapes text; static reports escape hostile input and omit scripts/remote assets; restrictive framing/CSP headers apply. A frontend or dependency defect remains residual risk.
- SSRF/connector abuse: allowed schemes/hosts/ports, DNS/address checks, redirect rejection, rebinding defense, TLS verification, response/time bounds, credential isolation, disabled-by-default production egress, and explicit actions constrain outbound paths. Approved private destinations deliberately expand trust.
- Malicious uploads: size/name/type/extension/signature/parser bounds, generated identities, no public serving, no execution/shell, safe deletion, and no raw-body logging constrain exposure. Parser/library defects and resource exhaustion remain residual risks.
- SQL/command/deserialization: ORM parameterization, allowlisted sort/filter fields, bounded pagination, declarative rules/mappings/playbooks, and no application-input shell/eval/exec paths reduce injection. Deployment scripts execute fixed operator-controlled commands.
- Secret/privacy leakage: file-mounted production secrets, encryption for MFA/connector/backup material, log/audit redaction, safe summaries, no external telemetry, ignored artifacts, image/candidate scans, and protected downloads reduce risk. Host administrators and unencrypted live database storage remain trusted/residual.
- Database/audit tampering: foreign keys, busy timeout, WAL in production, transactions, schema sentinel, integrity checks, canonical hash chaining, backup verification, and restore validation provide consistency and tamper evidence. A privileged actor able to rewrite the database and application can defeat local evidence; there is no external notarization.
- Supply chain/container: pinned locks/base tags, CI read-only permissions, build verification, non-root/read-only containers, dropped capabilities, limited networks/resources, no Docker socket, and image/history scans reduce exposure. Vulnerability-free or license-compliant status is not claimed without a successful supported scanner/review.
- Backup/restore/operations: encryption, manifests, validation, isolated drills, offline replacement, schema checks, session policy, and post-restore integrity/readiness checks reduce corruption and rollback risk. Operator mistakes, unavailable backups, downtime, and unknown RPO/RTO remain.

## Residual-risk ownership

Deployment owners provide host/filesystem encryption, trusted TLS, secret rotation, access-controlled backups, monitoring, capacity/resource tuning, authorized connector destinations, and manual browser/assistive-technology review. Analysts must interpret findings/anomalies cautiously. This model is engineering documentation, not a formal certification.
