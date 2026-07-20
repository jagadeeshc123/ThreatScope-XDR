# Production checklist

- [ ] Exact production profile, hosts, HTTPS origins, proxy networks, paths, limits, and build metadata reviewed.
- [ ] File-mounted secrets are separate, restrictive, backed up, and absent from Git/images/environment/logs.
- [ ] Trusted TLS certificate/key supplied; hostname verification, TLS 1.2/1.3, redirect, HSTS, CSP, and headers tested.
- [ ] Backend has no host port; containers are rootless, read-only, unprivileged, capability-free, limited, segmented, and socket-free.
- [ ] Registration, docs, demo seeding, debug/reload, and connector egress are disabled.
- [ ] Schema v19, SQLite WAL/foreign keys/busy timeout/quick-check, one worker, persistence restart, disk floor, and audit integrity pass.
- [ ] Backup validates and isolated restore drill succeeds; recovery artifacts and owner-defined RPO/RTO are reviewed.
- [ ] Authenticated HTTPS smoke, role matrix, CSRF/IDOR, complete route refresh, frontend build/lint, and backend regression pass.
- [ ] Inventory/manifest generated locally and checked; no source maps, sensitive artifact, automatic containment, or external telemetry exists.
