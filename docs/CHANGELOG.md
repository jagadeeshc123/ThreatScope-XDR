# Changelog

## 1.0.0-rc1 — Phase 11

- Added minimal public liveness/readiness and permission-protected health and diagnostics.
- Added redacted structured request logging and setting-name-only configuration validation.
- Added consistent optional-encrypted SQLite backup, integrity manifests, verification, inventory, and previewed retention.
- Added non-mutating restore and import validation plus controlled staged restore and offline replacement script.
- Added permission-filtered safe exports, retention, synthetic demo management, software inventory, and bounded local release candidates.
- Added operations UI, role-aware navigation, notifications/activity/audit integration, Docker persistence/health, verification-only CI, and operating documentation.

## Phase 12 - Local registration and onboarding

- Added a public landing page, local sign-up, and username-or-email sign-in.
- Added approval-required and limited auto-activation modes plus the protected Registered User role.
- Added registration administration, safe owner CLI, lifecycle audit events, and internal notifications.
- Preserved Argon2id, opaque sessions, CSRF, MFA, lockout, RBAC, and session-expiry behavior.
# Phase 13 — Threat Intelligence, IOC Watchlists, Sightings, and Correlation

- Added offline IOC sources, normalized indicators, imports, protected watchlists, campaigns, relationships, sightings, matches, correlation runs, and HTML reports.
- Added deterministic duplicate/lifecycle handling and explainable 0–100 match-risk scoring.
- Added stored-data correlation for SOC, phishing, documents, Web Exposure, API Security, unified correlation, and incident-case evidence.
- Added `threat_intel:view`, `threat_intel:import`, `threat_intel:manage`, `threat_intel:correlate`, and `threat_intel:export` with role seeding, CSRF, audit-chain, activity, and notification integration.
- Added permission-aware frontend routes, dashboard/search integration, defanged non-clickable indicator display, and static offline reports.
- Updated diagnostics, retention, backup/restore schema validation, documentation, and regression coverage.
