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
