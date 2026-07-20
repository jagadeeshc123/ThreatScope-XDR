# Production configuration

`THREATSCOPE_PROFILE=production` activates strict validation. Unknown profiles, unsafe booleans or limits, wildcard hosts/origins, HTTP origins, insecure cookies, debug/reload/docs, relative SQLite paths, multiple SQLite workers, demo seeding, unacknowledged public registration, missing revision/version, direct secrets, or invalid encryption keys fail closed.

The deployment owner must set exact hosts and HTTPS origins, trusted proxy CIDRs, persistent runtime/data/upload/report/backup paths, request/upload sizes, timeouts, free-space floor, build metadata, TLS paths, and `_FILE` secret references. Production registration and connector egress default to disabled. API documentation defaults to disabled.

`DATABASE_URL` must use an absolute persistent SQLite path and `THREATSCOPE_WORKERS` must remain `1`. Limits are rejected when outside server-owned safety ranges; dangerous values are never silently clamped. Development retains HTTP, Vite, docs, and the safe test target. Test mode is intended for temporary deterministic storage and synthetic credentials only.
