# VulnScope Frontend Manual Test Checklist

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
