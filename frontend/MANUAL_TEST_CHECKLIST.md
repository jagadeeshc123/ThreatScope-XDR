# VulnScope Frontend Manual Test Checklist

## Phase 15 - Vulnerability Management

Automation status on 2026-07-17: the in-app browser backend was unavailable after the prescribed connection check. Live Docker/API tests covered role authorization, synchronization, ingestion/deduplication, deterministic priority, lifecycle, plan/task completion, SLA, risk acceptance, verification/resolution, recurrence reopening, reports, source immutability, and direct HTTP 200 refreshes for all Phase 15 routes. The visual, browser-console, responsive-width, and keyboard-focus items below intentionally remain unchecked and must not be inferred from those executable checks.

- [ ] Administrator opens `/vulnerability-management`; local-data disclaimer and metrics or empty states render without console errors.
- [ ] Run asset synchronization twice; the second run creates no equivalent duplicate and source records remain unchanged.
- [ ] Search/filter assets, create a manual explicitly typed asset, and inspect identifiers, aliases, ownership, relationships, vulnerability count, priority, and overdue count.
- [ ] Run ingestion twice; eligible Web/API/Document/Phishing weaknesses aggregate occurrences and an ordinary SOC event is excluded.
- [ ] Inspect source severity, priority factors, optional CVSS distinction, affected assets, inert evidence, timeline, SLA, recurrence, plans, acceptance, and verification.
- [ ] Assign and triage through confirmed, in progress, and mitigated using keyboard controls.
- [ ] Create/approve a remediation plan, select local template guidance, create/assign/block/complete tasks, and confirm plan completion does not resolve the vulnerability.
- [ ] Request verification, pass with retained evidence, confirm resolution, ingest a newer matching occurrence, and confirm reopen.
- [ ] Request time-bounded risk acceptance; approve with a different authorized account, verify SLA pause, then revoke/expire and confirm reopened work.
- [ ] Mark a test record false positive only with note, evidence basis, and reviewer; confirm unchanged re-ingestion does not reactivate it.
- [ ] Verify SLA dashboard UTC label, warning/due/overdue/paused counts, distributions, upcoming deadlines, policies, and explicit recalculation permission.
- [ ] Generate a report; verify all 28 sections, sandboxed rendering, escaped hostile HTML, redacted secrets, defanged URLs, no active links, scripts, or remote assets.
- [ ] Global search returns assets, vulnerabilities, plans, tasks, policies, acceptances, verifications, templates, and reports.
- [ ] Dashboard shows active critical/high, overdue, due-soon, unassigned, resolution, and regression metrics when permitted.
- [ ] Auditor is read/export only; Executive Viewer gets aggregate overview only; Registered User and anonymous access are denied.
- [ ] Test loading, error, empty, responsive layouts and keyboard focus at 320 px, 768 px, and desktop widths.

Run the backend and frontend, then verify each workflow with browser developer tools open and no failed API requests.

- [ ] Refresh `/dashboard`, `/targets`, `/scans`, `/reports`, `/policies`, `/search`, `/profile`, `/settings`, and `/notifications` directly.
- [ ] Confirm the sidebar highlights Dashboard, Targets, Scans, Reports, Policies, and Settings on their routes.
- [ ] Add an authorized target, open its details, start a scan, and confirm the scan-start notification appears.
- [ ] Open the completed scan and verify Findings, Crawl Map, Posture Drift, Evidence, and Policy Results use backend records.
- [ ] In Crawl Map, verify parent-child edges, depth columns, state colors, node selection, zoom controls, and the records table on desktop and mobile widths.
- [ ] Open `/scans?highlight=<id>&tab=policies` and confirm the requested scan and policy tab open automatically.
- [ ] Generate a report from Scan Details; verify the report notification appears in the bell and Notifications page.
- [ ] Open a report by clicking its card, refresh its `?reportId=<id>` URL, open it in a new tab, and download its HTML.
- [ ] Search by target name, scan status, finding title/severity, URL, and report title; verify debounce and destination links.
- [ ] Clear the topbar search field while on `/search`; verify the old query and results are removed without adding a stale history entry.
- [ ] Update profile name and initials; verify the topbar avatar updates immediately and persists after refresh.
- [ ] Change every scanner default and report branding field, save, refresh, and confirm persistence.
- [ ] Reset settings only after accepting the confirmation and verify backend defaults return.
- [ ] Mark one notification read, mark all read, delete one after confirmation, and verify the unread badge updates.
- [ ] Verify loading, empty, and backend-error states by temporarily stopping the backend and revisiting each converted page.
# Secure access-control checks

- Open `/login` directly and confirm no example or default credentials are shown.
- Confirm failed login uses a generic message, successful login returns to the intended internal route, and duplicate submission is disabled.
- Confirm `/mfa-challenge`, `/change-password`, and `/forbidden` refresh directly without console errors.
- Verify the sidebar changes for Administrator, Security Analyst, Auditor, and Executive Viewer.
- Verify hidden mutation actions are also rejected with HTTP 403 when called directly.
- Enroll TOTP using only a local authenticator, acknowledge one-time recovery codes, and confirm a used code cannot be reused.
- Revoke an active session and confirm its next request returns HTTP 401 immediately.
- Change a role permission and confirm affected sessions are revoked.
- Inspect user, role, session, and security-audit tables at narrow and wide viewport sizes.
- Use keyboard Tab navigation on login, password, MFA, permission matrix, and audit filter controls; confirm visible focus.
- Confirm browser storage contains no session token and network mutation requests use the HttpOnly cookie plus `X-CSRF-Token`.
- Run audit integrity verification and confirm the limitations wording is visible.

# Phase 11 operations checks

- [ ] As Administrator, refresh every `/operations` route directly; confirm loading, empty, error, narrow-table, keyboard-focus, and responsive behavior.
- [ ] Confirm public liveness/readiness are minimal; detailed health, diagnostics, and configuration show no environment values, absolute paths, credentials, or traces.
- [ ] Create, verify, download, and delete a backup; confirm the sensitivity warning and authorized backend download.
- [ ] Validate a backup for restore, inspect warnings/counts, and verify the stage button requires password, MFA when enabled, and the exact phrase.
- [ ] Create and verify a multi-module export; confirm no authentication data or original PDF/email/log content exists.
- [ ] Preview retention, verify exact candidates, apply with confirmation, and confirm audit events and protected/current records remain.
- [ ] Enable demo mode, confirm both Demo Environment badges, seed twice, reset, and verify a separately created analyst record remains.
- [ ] Generate inventory and a marked local release candidate; inspect checksum, limitations, exclusions, and dirty-state warning.
- [ ] Confirm Analyst sees diagnostics/export/inventory only, Auditor sees health/diagnostics/inventory only, and Executive Viewer sees no Operations menu.
- [ ] Inspect browser console and network panel for route errors, external contacts, exposed paths/secrets, direct runtime links, or mutation requests without CSRF.

# Session-expiry regression checks

- [ ] Clear site cookies, open `/login`, and confirm no Session expired modal appears.
- [ ] Submit invalid credentials and confirm only the generic login error appears.
- [ ] Log in, revoke or expire the active session, then trigger a protected request; confirm one modal appears.
- [ ] Click Return to login and confirm the login form remains usable with no modal overlay.
- [ ] Log in again and confirm no stale modal returns; explicitly log out and confirm no expiry modal appears.
- [ ] Refresh `/`, `/mfa-challenge`, and `/forbidden` directly and confirm no expiry modal appears.
- [ ] Open `/change-password` anonymously and confirm it redirects to `/login` without an expiry modal.
- [ ] While authenticated on `/change-password`, revoke the session and trigger a protected request; confirm one modal appears and the password form is no longer usable.
- [ ] Check the console/network panel for repeated 401 requests or refresh loops.

# TOTP enrollment checks

- [ ] Configure a private `THREATSCOPE_MFA_ENCRYPTION_KEY`, start the app, sign in, and open Dashboard.
- [ ] Click Begin TOTP enrollment on Dashboard; confirm the shared Set up authenticator app dialog opens and the button cannot submit twice.
- [ ] Enter an incorrect current password; confirm only a bounded local error appears and no Session expired modal opens.
- [ ] Start setup; confirm a locally rendered QR code, manual setup key, Copy key action, issuer, account label, six-digit input, Verify and Enable MFA, and Cancel are visible.
- [ ] Confirm no QR request is made to an external host and neither the setup key nor `otpauth` URI is written to browser storage or the console.
- [ ] Close or cancel a pending setup; confirm Security shows Disabled. Start again, leave it pending, and confirm Dashboard and Security show Setup incomplete with Continue, Restart, and Cancel actions.
- [ ] Paste whitespace and non-digits into the verification input; confirm it safely normalizes to at most six digits.
- [ ] Submit an invalid six-digit code; confirm MFA remains disabled and only a bounded local error appears.
- [ ] Enter a valid current authenticator code; confirm recovery codes appear once with Copy all and an in-memory text download.
- [ ] Confirm Finish setup remains disabled until I have saved my recovery codes is checked.
- [ ] Finish setup; confirm Dashboard immediately shows MFA Enabled and Security immediately shows method, enrollment time, last-used state, and remaining recovery-code count without a page reload.
- [ ] Log out, sign in with username or email and password, and confirm the existing MFA challenge page appears before a protected session is established.
- [ ] Submit an invalid TOTP, then a valid current TOTP; confirm the former fails generically and the latter opens protected content with no token in browser storage.
- [ ] Sign in using one unused recovery code, then attempt the same code again and confirm replay is rejected.
- [ ] Regenerate recovery codes using current password and a current TOTP; acknowledge the one-time replacement list and confirm all previous codes fail.
- [ ] Disable MFA; confirm current password, current TOTP or unused recovery code, and the explicit destructive acknowledgement are all required.
- [ ] After disable, confirm recovery codes and pending login challenges are invalid, other active sessions are revoked, the current session remains usable, and both UI entry points show Disabled.
- [ ] Use keyboard-only navigation through both entry points, the setup dialog, recovery-code acknowledgement, regeneration, and disable confirmation; confirm visible focus at narrow and wide viewport sizes.
- [ ] Inspect the network, console, security audit, and activity views; confirm no password, TOTP secret, `otpauth` URI, verification code, recovery code/hash, session token, CSRF token, or encryption key is exposed.

# Phase 12 local-account checks

- [ ] Clear site cookies and open `/`; confirm Sign In and Create Account are visible and no protected metrics or sidebar appears.
- [ ] Refresh `/`, `/login`, `/signup`, `/account-pending`, `/account-rejected`, and `/known-limitations` directly.
- [ ] Register once with a Gmail address and once with a non-Gmail address, always using a new separate ThreatScope password.
- [ ] Confirm registration never asks for an email-account password, mailbox access, a role, status, administrator access, or MFA state.
- [ ] In `auto_activate_limited` mode, confirm the activated result appears and the account receives only Registered User access.
- [ ] In `approval_required` mode, confirm the pending result appears and protected routes remain inaccessible.
- [ ] Sign in to the same account by normalized email and by username; confirm both restore the intended protected route.
- [ ] Submit invalid email/password and username/password combinations; confirm only the generic login error appears and no expiry modal opens.
- [ ] Confirm pending and rejected status pages reveal account details only after correct password authentication.
- [ ] Confirm disabled and locked accounts cannot access protected routes and a locked account follows the existing temporary lockout policy.
- [ ] Run `python scripts/manage_accounts.py create-admin` from `backend/` while another non-administrator account exists.
- [ ] Sign in as the new owner and open Administration / Registrations; check loading, empty, error, keyboard-focus, narrow, and wide layouts.
- [ ] Approve one registration with Registered User and another with an operational role; explicitly confirm any Administrator assignment.
- [ ] Reject a pending registration with a bounded reason, verify rejected login status, then reopen it and confirm it returns to pending.
- [ ] Confirm Security Analyst and Registered User accounts receive HTTP 403 for registration-management routes and see no administration navigation.
- [ ] Confirm Registered User sees only the safe welcome dashboard, profile, notifications, and account status with no fake module zeroes.
- [ ] Log out explicitly and confirm no expiry modal; then invalidate a real authenticated session and confirm exactly one expiry modal.
- [ ] Inspect cookies, browser storage, and requests: session cookie is HttpOnly, no browser token exists, and authenticated mutations use CSRF.
- [ ] Check the console and network panel for route errors, external identity calls, Google scripts, mailbox calls, repeated requests, or exposed secrets.
- [ ] Check responsive layout and visible keyboard focus for landing, login, signup, status, registration list, and approval/rejection dialogs.
# Phase 13 threat-intelligence checks

- [ ] Sign in as Administrator and refresh all `/threat-intelligence` routes directly without a console error.
- [ ] Create domain, URL, email, IP, CIDR, and hash indicators; verify server normalization and safe defanged display.
- [ ] Confirm Copy is explicit and malicious URLs/domains/emails/IPs are text, not anchors, previews, favicons, or open-in-browser controls.
- [ ] Re-enter the same normalized IOC; verify the bounded duplicate response, stable identity, merged tags, and no revoked reactivation.
- [ ] Import a CSV with valid, duplicate, and invalid rows; verify accepted/duplicate/rejected counts and that only a manifest remains.
- [ ] Import equivalent JSON and the documented STIX subset; verify unsupported objects become bounded warnings.
- [ ] Create a watchlist, add/remove indicators, and confirm indicator records remain. Confirm protected watchlist identity cannot be changed.
- [ ] Create a campaign with indicators and inspect the data-only graph/causality disclaimer.
- [ ] Add and remove an analyst relationship; confirm self/duplicate relationships fail safely.
- [ ] Seed stored observations in existing modules, run correlation twice, and confirm sightings/matches do not duplicate.
- [ ] Inspect exact URL, URL-host, email, hash, IP, and CIDR membership matches and their risk-factor explanations.
- [ ] Review a match as false positive and confirm status/counts update. Review another as confirmed.
- [ ] Try escalation without confirmation, then explicitly confirm and verify the new/linked incident case and audit event.
- [ ] Generate the default report; verify all 20 sections, defanged values, no active links, no remote assets/scripts, and refresh-safe details.
- [ ] Search for an indicator, source, watchlist, campaign, match, and report; follow each internal result.
- [ ] Verify the four Threat Intelligence dashboard metrics and responsive card layout.
- [ ] Sign in as Security Analyst, Auditor, Executive Viewer, Registered User, and anonymously; verify sidebar/actions/API access follow the documented matrix.
- [ ] Remove the CSRF header from a mutation and confirm HTTP 403. Confirm anonymous is 401 and Registered User is 403.
- [ ] Inspect browser Network while creating/importing/correlating/reporting; confirm no request targets an external host.
- [ ] Verify keyboard focus, narrow/mobile tables/forms, loading, empty, error, and long-value wrapping states.

## Detection Engineering

- [ ] Sign in as Administrator; refresh every `/detections` route and check loading, empty, error, keyboard-focus, responsive-table, and console states.
- [ ] Create a native rule with one positive and one negative synthetic test; run tests and verify activation is blocked until both pass.
- [ ] Edit the rule, inspect immutable version hashes, compare versions, and confirm rollback creates another version without deleting history.
- [ ] Preview/import safe Sigma YAML and JSON; inspect unsupported-field and unknown ATT&CK-tag warnings.
- [ ] Confirm YAML anchors/aliases, custom tags, malformed conditions, excessive depth, wildcards, fields, rules, and file sizes fail safely.
- [ ] Inspect all four protected demonstration packs and confirm non-administrators clone rather than modify system content.
- [ ] Open ATT&CK Coverage and verify covered/uncovered local techniques, local-subset disclaimer, accessible labels, and technique filters.
- [ ] Run a bounded historical execution twice and confirm deterministic ordering, match fingerprints, no endless duplicates, and unchanged source events.
- [ ] Mark one match false positive and confirm the disposition persists. Create an expiring suppression and confirm rerun produces a countable suppressed match.
- [ ] Confirm alert promotion and case escalation both require explicit confirmation and their additional permissions.
- [ ] Generate a report and verify all 24 sections, redaction/escaping, defanged URL text, sandboxed preview, and absence of remote assets/scripts.
- [ ] Search rules, packs, techniques, matches, executions, suppressions, and reports; verify internal navigation and dashboard detection metrics.
- [ ] Sign in as Analyst, Auditor, Executive Viewer, Registered User, and anonymously; verify the documented sidebar, route, API, and mutation matrix.
- [ ] Remove CSRF from a mutation and verify 403. Inspect Network and confirm no external request, rule download, URL fetch, command, or process execution occurs.
