# Changelog

## 1.0.0 — Final candidate (unreleased)

- Finalized one canonical application version while retaining the independent `threatscope-schema-v19` database sentinel; no persistent schema change is introduced.
- Corrected permission-aware notification query bounds and bulk-read routing, bounded global search input, added a safe frontend not-found route, and restored native keyboard semantics for notification navigation.
- Reduced the measured production main JavaScript chunk through route-level lazy loading without changing authorization or data behavior; source maps remain disabled.
- Added consolidated user/administrator/developer guides, capability/permission matrices, threat model, data handling, API index, security/contribution policies, release notes/checklist, deterministic checksum workflow, and final audit evidence.
- Updated isolated production smoke naming and CI inputs for the v1 candidate. No commit, tag, push, deployment, publication, external telemetry/model, containment, automatic case closure, or user punishment is performed.

## Phase 19 - Production Deployment and Hardening

- Added development/test/production runtime profiles, strict production validation, file-mounted secrets, startup preflight, and schema sentinel `threatscope-schema-v19`.
- Added rootless read-only backend and static-edge images, segmented production Compose networks, persistent volumes, runtime limits, OCI metadata, TLS 1.2/1.3 Nginx termination, redirect, headers, cache policy, and safe access logging.
- Added protected production readiness/build/security APIs and responsive operations UI, structured redaction/request IDs, SQLite WAL/foreign-key/busy-timeout/integrity safeguards, release/inventory tooling, CI gates, smoke helpers, and production runbooks.
- Production defaults disable registration, docs, debug/reload, demo seeding, and connector egress. No cloud deployment, real credential, certificate, key, containment, tag, or v1.0 release is included.

## Phase 18 - Advanced Security Analytics

- Added 64 immutable detector templates, 42 server-owned feature definitions, ten deterministic scoring methods, bounded baseline construction, backtesting, confidence/severity separation, and explainable anomaly materialization.
- Added immutable versions, validation/quality gates, explicit lifecycle and rollback, analyst feedback revisions, declarative suppressions, drift with no automatic retraining, case/SOAR/outbox integration, and 40-section static reports.
- Added schema v18, RBAC/CSRF/audit/activity/notifications, search/dashboard, backup/retention/diagnostics/demo-reset, 25 frontend routes, documentation, and focused security/regression coverage.

## Phase 17 - Security Integrations and Connectors

- Added a server-owned connector catalog, encrypted write-only credentials, explicit network policies, SSRF/DNS-rebinding defenses, signed inbound quarantine, and bounded declarative mappings.
- Added transactional outbox delivery, retries, circuit breakers, dead letters, manual replay, connector health, external references, STIX import, TAXII pull, and safe static integration reports.
- Added Integration Hub APIs and UI, SOAR queued connector-delivery actions, RBAC, dashboard/search, backup/retention/diagnostics/demo-reset integration, documentation, and focused security tests.

## Phase 15 - Unified Vulnerability Management

- Added explicit unified asset inventory and bounded stored-data synchronization.
- Added eligible finding ingestion, deterministic deduplication, occurrences, scoring, triage, merge/split, and recurrence reopening.
- Added remediation plans/tasks/library, deterministic SLA, expiring risk acceptance, false-positive evidence, and verification-required resolution.
- Added 28-section safe static reports, dashboard/search/notification/activity integration, RBAC/audit controls, operations integration, frontend routes, and regression coverage.

## Phase 14 - Detection Engineering

- Added native and bounded Sigma YAML/JSON rules, static validation, immutable versioning, rollback-as-new-version, and test-gated activation.
- Added deterministic stored-event normalization/evaluation, historical execution, idempotent matches, suppressions, risk and quality scoring, and explicit alert/case promotion.
- Added four protected rule packs, a 27-technique local educational ATT&CK-style subset, coverage UI, reports, dashboard/search integration, RBAC, audit/activity/notifications, retention, backup, and diagnostics integration.
- Added all Detection Engineering frontend routes/components and focused offline-safety regression coverage.

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
- Added Phase 16 offline SOAR-Lite with a server-owned action catalog, five safety classifications, policy governance, declarative validated playbooks, immutable versions, trigger proposals, dry-run/simulation/live-local execution, multi-person approvals, analyst input, persistent delays, retries, idempotency, case automation, protected sensitive actions, evidence, compensation/rollback records, reports, RBAC, audit, operations, dashboard, search, and full safety boundaries.
