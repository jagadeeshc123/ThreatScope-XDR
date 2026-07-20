# Architecture

## Phase 18 analytics plane

`app.modules.analytics` is a cohesive derivation layer over existing SQLAlchemy source modules. Immutable catalogs feed bounded extraction; versioned configurations reference aggregate baselines; deterministic scoring may materialize deduplicated explainable anomalies; review, suppressions, drift, reports, and jobs remain transactional. The layer has no network or command-execution capability and never owns or mutates source evidence. It reuses central RBAC, CSRF, audit chaining, activity, notifications, cases, SOAR safe actions, connector outbox, search, dashboard, backup/restore, retention, diagnostics, and demo reset.

Phase 17 adds server-owned connectors, encrypted credentials, network policies, canonical events/outbox, subscriptions/mappings, bounded deliveries/attempts/dead letters, inbound quarantine/nonces, health, cursors, external references, STIX runs, and reports. External work occurs only through process-due after commit.

The React/TypeScript frontend uses a typed Axios client, cookie credentials, CSRF interception, lazy routes, and permission-aware navigation. FastAPI provides public minimal health and authenticated module routers. SQLAlchemy uses SQLite and the established `create_all` model-registration pattern.

`app/modules/platform_operations` owns operational models and services for health, diagnostics, configuration, logging, backup, staged restore, export validation, retention, demo data, inventory, and release packaging. Generated files are constrained to configured runtime directories; database rows retain only generated relative paths. `OperationalJob` tracks bounded work while `SecurityAuditEvent`, notifications, and SOC activity integrate successful outcomes.

No background worker, migration framework, cache, queue, cloud service, monitoring server, reverse proxy, deployment automation, or live selective import is part of this release candidate.
`app/modules/soar` owns Phase 16 catalog definitions, SQLAlchemy records, strict schemas, safe condition and validation engines, deterministic synchronous/resumable execution, approval/input/trigger/compensation services, routes, and static report generation. It reuses central database sessions, authentication, CSRF, permissions, hash-chained audit, notifications, SOC activity, case/vulnerability/user/session models, operations, and the shared frontend client/guards. It contains no connector or executable plug-in mechanism.

## Phase 19 deployment plane

`app.modules.production` is the single production policy layer for profiles, configuration, file secrets, preflight, headers, redacted logging, schema metadata, health, and operations endpoints. It extends the existing access-control and platform-operations modules rather than duplicating them. Production Compose builds a static frontend into a rootless Nginx edge and a separate rootless FastAPI backend. Only the edge joins the public network; both share an internal application network, and the backend owns explicit persistent data/backup/upload/report/runtime volumes. SQLite enables WAL, foreign keys, a five-second busy timeout, quick-check readiness, and exactly one worker.
