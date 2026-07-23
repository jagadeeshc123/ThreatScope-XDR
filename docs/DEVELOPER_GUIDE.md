# Developer guide

## Architecture and repository layout

`backend/app` contains FastAPI routers, SQLAlchemy models, schemas, central access control, scanners, module services, and production controls. `frontend/src` contains the React router, permission guards, API clients, reusable UI, and route pages. `deploy` contains Nginx and deterministic local release/smoke helpers. `docs` is operator/user guidance. Generated runtime, inventory, manifest, checksum, database, upload, report, secret, TLS, build, and dependency directories are ignored.

## Local setup and tests

Use Python 3.11+ and Node 20+. Install `backend/requirements.txt` and use `npm ci`. Before review run compileall, full unittest discovery, the network-disabled harness, `verify_vulnscope.py`, `pip check`, frontend build/lint/dependency validation, and both Compose configurations. Do not contact a real third party from a test.

## Backend conventions

Register module routers in `app.main`. Authenticated modules use `authorize_platform_request`, whose server-owned path/method mapping enforces permissions, CSRF on POST/PUT/PATCH/DELETE, and mutation audit events. Object queries must apply ownership/scope before serialization and use 404 where existence should not be disclosed. Validate external text/URLs/enums/numbers/page sizes with schemas/Query bounds; use ORM parameterization and allowlisted sort/filter fields. Bound list, export, search, report, retention, and process-due work. Commit domain records before post-commit notification/audit helpers when required.

Schema changes are additive only. Do not bump `threatscope-schema-v19` for application branding. If an unavoidable persistent fix advances the schema, preserve data and add startup-upgrade, backup/restore, readiness, and rollback tests.

## Frontend conventions

Declare routes in `App.tsx`, lazy-load route pages, and update `auth/permissions.ts` plus permission-aware navigation when needed. Backend authorization is still mandatory. Use the shared API client so CSRF and 401/session-expiry behavior remain consistent; a 403 must not trigger expiry. Provide loading, empty, recoverable error, and bounded table states. Prefer native buttons/links, visible labels, landmarks/headings, focus styles, dialog semantics, table headers, textual chart summaries, and non-color status text.

## Security and release rules

Escape static report data, use safe download names/headers, never place uploaded files under the public frontend, and never add shell/eval/deserialization paths for application input. Preserve SSRF destination checks, redirect rejection, TLS verification, timeouts, response bounds, and explicit connector action. Do not add external telemetry, AI/model services, autonomous containment, automatic deployment, or unreviewed dependencies.

`VERSION` is the canonical application version; schema and build-provided Git revision are separate. Generate permission docs, dependency inventory, release manifest, and checksums with repository scripts; remove ignored generated outputs after verification. The CI workflow is verification-only. After v1.0.0, changes must fit maintenance mode: confirmed defect, security, compatibility/dependency, documentation, or carefully reviewed operational improvement.
