# ThreatScope XDR v1.0 release checklist

Evidence is recorded in [Final Audit Report](FINAL_AUDIT_REPORT.md). Checked validation items passed on the current working tree; the final four release actions are intentionally reserved for the user/reviewer.

- [x] Required branch and baseline/tag verified before implementation
- [x] Application version is 1.0.0; schema remains threatscope-schema-v19
- [x] Full backend compile/tests/verifier/pip check
- [x] Network-disabled full regression
- [x] Frontend npm ci/build/lint/npm dependency validation
- [x] Development Compose config/start/health/authenticated representative flow
- [x] Isolated production Compose clean build/start/inspection
- [x] Trusted HTTPS, TLS versions/hostname, redirect, and security headers
- [x] Authenticated smoke and Administrator/Analyst/Auditor/Executive/Registered/anonymous RBAC
- [x] Authentication, MFA, session rotation/expiry/revocation/logout/default-credential checks
- [x] CSRF mutation inventory plus missing/invalid/valid token checks
- [x] IDOR/object/download/report checks
- [x] SSRF, connector destination policy, redirect/rebinding, and no uncontrolled network checks
- [x] Upload and report escaping/safety checks
- [x] Audit-chain tamper/backup/restore checks
- [x] Notification/search/dashboard and cross-module consistency checks
- [x] Exact frontend route refresh result recorded
- [x] Browser attempt and approved fallback plus static accessibility/responsive review
- [x] Before/after frontend performance measurements recorded
- [x] Backend performance/query-bound benchmark recorded
- [x] Backup verification and isolated restore drill
- [x] Phase 19-to-v1 schema-compatible upgrade smoke and rollback-document validation
- [x] Dependency inventory generated, validated, and removed
- [x] Release manifest generated, validated, and removed
- [x] SHA-256 workflow generated, validated, and removed
- [x] Release notes/changelog/README/guides/matrices/threat/data/API/security docs reviewed
- [x] Sensitive candidate/image/log scan
- [x] Strict protected-reference scan `(^|/)references(/|$)`
- [x] Source-control ignore/hygiene and `git diff --check`
- [x] Final branch/HEAD/status/diff/untracked inventory
- [ ] Commit created by the user/reviewer
- [ ] `v1.0.0` tag created by the user/reviewer
- [ ] Push performed by the user/reviewer
- [ ] GitHub release published by the user/reviewer
