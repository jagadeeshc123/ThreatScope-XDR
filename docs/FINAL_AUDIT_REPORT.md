# ThreatScope XDR v1.0.0 final audit report

Status: implementation and validation complete; ready for reviewer commit/tag/release actions. Application version is `1.0.0`; the persistent schema remains `threatscope-schema-v19`.

## Scope and methodology

The audit covered release metadata, 673 registered API routes, 355 mutation routes, 124 server-owned permissions and five default roles, authentication/session/MFA/CSRF controls, object authorization, outbound-network boundaries, uploads and reports, 228 declared frontend routes, accessibility, performance, deployment configuration, CI, backup/restore, upgrade compatibility, release generators, documentation, and repository hygiene. Evidence came from static code review, route introspection, focused regression tests, two full backend runs, a network-disabled run, production frontend builds, an authenticated development smoke, an isolated production HTTPS/restore drill, container/image inspection, bounded benchmarks, and source/artifact scans.

## Defect inventory

| ID | Severity | Module | Reproduction and actual behavior | Expected behavior | Security/user impact | Root cause | Remediation | Regression evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P20-001 | Medium | Release metadata | `VERSION`, backend fallback/build labels, frontend packages, and footer conflicted between `1.0.0-rc1`, `1.0.0-rc2`, and `0.0.0`. | One canonical `1.0.0`; schema independently remains v19. | Incorrect release identification. | Candidate values were not finalized together. | Normalized source, image, runtime, package, UI, Compose, and smoke metadata. | Focused test; built image labels and runtime report `1.0.0`, schema v19, reviewed 40-character revision. | Corrected |
| P20-002 | Medium | Notifications | Listing/unread/bulk-read materialized all visible rows; `limit` was unbounded. | SQL visibility filtering, bounded pagination, and set-based count/update. | Avoidable memory/latency growth and inconsistent input handling. | Filtering occurred after an unbounded query. | Added permission/recipient SQL predicates, deterministic ordering, bounded `skip`/`limit`, `count()`, and set-based update. | Focused recipient/privacy/pagination test; authenticated smoke and benchmark. | Corrected |
| P20-003 | Medium | Global search | Queries over 200 characters were accepted. | Excessive search input returns 422. | Avoidable wildcard work. | Unbounded query parameter. | Added FastAPI maximum length 200 while preserving the two-character minimum behavior. | Focused 200/201-character test. | Corrected |
| P20-004 | Medium | Frontend performance | Baseline main JS was 998,392 bytes (264.65 kB gzip) with a >500 kB warning. | Route-oriented splitting keeps optional modules out of the entry chunk. | Slow initial parsing/loading on constrained clients. | Core/access pages and the integration barrel were eager. | Lazy-loaded route pages/integration module behind the existing Suspense boundary. | Final entry JS 430,993 bytes (122.94 kB gzip), a 56.8% raw reduction; no >500 kB build warning. | Corrected |
| P20-005 | Low | Frontend routing | 227 paths existed without a wildcard route; unknown paths rendered no useful page. | Safe accessible not-found page. | Confusing blank outcome. | Missing fallback route. | Added public `*` route and not-found content. | Focused static test and production 228/228 direct route refreshes. | Corrected |
| P20-006 | Low | Notifications accessibility | Clickable `div` used partial emulated button semantics. | Native keyboard behavior and separately named actions. | Inconsistent keyboard operation. | Container emulated a button. | Split open, mark-read, and delete into native buttons; added labels and semantic time. | Focused semantic test, static accessibility scan, lint/build. | Corrected |
| P20-007 | Documentation-only | Release documentation | Required v1 guides, matrices, security/data/API/release documents, and index were absent or stale. | Documentation matches the release. | Operators/reviewers could not reproduce or interpret it reliably. | Phase documents had not been consolidated. | Added the required guides, matrices, inventories, threat/data/API/security/release documents, contribution policy, and README index. | Link/content regression test and final review. | Corrected |
| P20-008 | Low | CI/release smoke | Phase 19 project/material defaults and candidate labels remained active. | Isolated Phase 20/v1 naming, retaining compatibility only where needed. | Ambiguous evidence and possible older-project collision. | Prior hardening helpers were reused. | Changed runtime/project/default labels and CI invocation to Phase 20; legacy helper filenames remain compatibility entry points. | Clean production project build/drill/cleanup and source review. | Corrected |
| P20-009 | Medium | Notifications | `PATCH /api/notifications/mark-all-read` was shadowed by `/{notification_id}/read` and could return 422. | Literal bulk route is reachable and CSRF protected. | Users could not reliably clear unread notifications. | Static route registered after overlapping dynamic route. | Registered the literal route first. | Authenticated focused regression test. | Corrected |

No critical or high-severity defect was confirmed. All nine confirmed findings were corrected; no finding was invented to satisfy a count.

## Validation evidence

- Source-control gate: branch `feature/final-v1-release`; HEAD and baseline tag `production-deployment-hardening-v1` both `82c6e1928a4b66f8bb6313c5aec5a78547014c78`; ancestor checks passed; no commit, tag, push, merge, switch, rebase, stash, reset, clean, worktree, or submodule operation was performed.
- Backend: compile passed; full discovery passed 307 tests; the separate network-disabled discovery passed 307 tests in 147.013 seconds with one expected skip; six final-release focused tests passed; repository verifier passed; `pip check` reported no broken requirements.
- Frontend: `npm ci`, TypeScript/Vite production build, lint, and `npm ls --depth=0` passed; `npm audit` reported zero known vulnerabilities. Lint still reports 16 non-failing warnings (hook dependency guidance, one extra boolean cast, and fast-refresh export guidance); these are recorded, not represented as zero warnings.
- Route/security inventory: all 355 mutation routes are classified—300 central authenticated session/permission/CSRF/audit routes, 51 explicitly authenticated CSRF routes, four intentional no-session exceptions (login, registration, MFA login verification, and signed inbound webhook), zero unclassified. The generated permission matrix matches 124 permissions and five default roles.
- Development Compose: clean build/start and health checks passed; frontend, backend, and bundled safe target returned 200. A random ephemeral Administrator completed login/CSRF, safe scan (eight findings), sanitized local report generation, dashboard/notification/search reads, target deletion, logout, and account deletion.
- Production Compose: clean config/build/start passed for `threatscope/backend:1.0.0` and `threatscope/edge:1.0.0`; both images are non-root, carry version `1.0.0` and the reviewed revision; the edge image contains zero source maps.
- HTTPS acceptance: TLS 1.2 and TLS 1.3 succeeded; legacy TLS and invalid hostname failed; HTTP redirected to HTTPS; unknown hosts were rejected; production docs/config paths were blocked; session cookie and security/cache headers passed.
- Authorization and sessions: Administrator plus Security Analyst, Auditor, Executive Viewer, Registered User, and anonymous profiles were exercised. Missing/invalid/valid CSRF, disabled self-registration, protected health, login/logout, restart persistence, restore-time session revocation, and permission outcomes passed. The full suite covers MFA, lockout, expiry, rotation/revocation, object authorization, and default-credential behavior.
- Production UI fallback: automated direct refresh passed exactly 228/228 declared SPA routes. No browser is available. One in-app browser attempt was made; the approved automated route/authentication fallback and static accessibility/responsive review were used.
- Accessibility static review: zero clickable `div` controls, zero positive `tabIndex`, zero `dangerouslySetInnerHTML`, zero `<img>` elements lacking review, and no unsandboxed iframe. Native controls, 78 labels, 51 ARIA label references, 48 table headers, 37 focus-visible rules, and 174 responsive breakpoint declarations were reviewed. Three intentional autofocus uses are limited to login, MFA challenge, and TOTP enrollment.
- Security/data boundaries: full and network-disabled suites cover IDOR, SSRF/redirect/rebinding policy, connector egress controls, uploads, report escaping, audit-chain tamper detection, and cross-module consistency. Static scans found no uncontrolled outbound/telemetry/model client, unsafe rendered URL, remote report asset, or executable report content.
- Backup/restore/upgrade: verified encrypted backup, restore validation, offline restore, v19 schema continuity, target restoration, session invalidation, and post-restore audit-chain integrity passed. Because v1.0.0 intentionally retains schema v19, the application upgrade is an image replacement over a compatible Phase 19 database; restart persistence passed and the documented rollback path preserves keys/configuration and uses a verified pre-upgrade backup when data rollback is required.
- Container hardening: 14 checks per service (28 total) passed for non-root users, read-only roots, no privilege escalation, dropped capabilities, limits, restart/health/logging policy, Docker-socket isolation, direct-secret exclusion, network scope, and backend host-port isolation.
- Release artifacts: dependency inventory (57 Python and 225 npm entries), manifest (eight input artifacts and 69 documentation hashes), and ten-row SHA-256 file were generated, validated, and removed. Release candidate scan passed 48 candidates across six checks; strict protected-reference changes were zero; `git diff --check` passed.

## Performance evidence

| Measurement | Baseline | Final |
| --- | ---: | ---: |
| Main JavaScript | 998,392 B / 264.65 kB gzip | 430,993 B / 122.94 kB gzip |
| Main-chunk warning | Present (>500 kB) | Absent |
| Total emitted JavaScript | Not separately recorded | 1,524,955 B |
| CSS | Not separately recorded | 41,651 B |
| Largest lazy/vendor chunk | Included in entry | `CategoricalChart`, 310,715 B |
| Source maps | 0 | 0 |

The bounded in-process SQLite benchmark ran 15 successful HTTP 200 requests against each of 11 representative list/summary endpoints. Medians ranged from 10.358 to 64.464 ms, p95 from 12.422 to 74.043 ms, maximum latency was 78.787 ms, and maximum payload was 4,932 bytes. The 2,000 ms/2 MiB limits are regression tripwires, not production SLA claims.

## Accepted limitations

- Supported production topology is one backend worker with single-node SQLite; it is not horizontally scalable or zero-downtime.
- Database/host encryption, certificate issuance/renewal, backup scheduling, capacity planning, and resource tuning remain operator responsibilities.
- SOAR actions are simulations or tightly bounded local workflows; there is no automatic containment, case closure, user punishment, detector retraining, deployment, or rollback.
- Analytics is deterministic/local. An anomaly is a review signal, not proof of compromise; unlabeled data does not yield fabricated accuracy metrics.
- Connector configuration/queueing is not proof of delivery. Egress is disabled by default and requires explicit reviewed policy.
- The visual browser walkthrough could not run because the in-app browser was unavailable; exact route refresh, authenticated HTTP workflows, production smoke, and static UI review passed instead.
- The 16 non-failing frontend lint warnings should be reduced during maintenance, but no release-blocking lint/build error remains.

## Release recommendation

The working tree is ready for reviewer-controlled commit and release preparation. The user/reviewer must still review the diff, create the commit, create the `v1.0.0` tag, push, and publish any GitHub release; Codex intentionally performed none of those operations.
