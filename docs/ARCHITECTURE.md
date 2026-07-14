# Architecture

The React/TypeScript frontend uses a typed Axios client, cookie credentials, CSRF interception, lazy routes, and permission-aware navigation. FastAPI provides public minimal health and authenticated module routers. SQLAlchemy uses SQLite and the established `create_all` model-registration pattern.

`app/modules/platform_operations` owns operational models and services for health, diagnostics, configuration, logging, backup, staged restore, export validation, retention, demo data, inventory, and release packaging. Generated files are constrained to configured runtime directories; database rows retain only generated relative paths. `OperationalJob` tracks bounded work while `SecurityAuditEvent`, notifications, and SOC activity integrate successful outcomes.

No background worker, migration framework, cache, queue, cloud service, monitoring server, reverse proxy, deployment automation, or live selective import is part of this release candidate.
