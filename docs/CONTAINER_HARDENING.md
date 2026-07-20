# Container hardening

Production backend and edge images use pinned version tags, explicit OCI metadata, non-root UIDs, read-only root filesystems, `no-new-privileges`, all-capability drops, PID/CPU/memory limits, tmpfs scratch space, bounded shutdown, health checks, restart policies, and Docker log rotation.

The Docker socket, host root, development database, tests, `.git`, `.env`, source maps, build caches, and credentials are absent. Only explicit application volumes are writable. The edge and application networks are separate; only Nginx joins both and only Nginx publishes ports. The application network is internal by default.

Digest pinning remains a deployment-owner responsibility because this repository does not invent unverifiable digests. Inspect every built image and container before release using the Phase 19 inspection tests.
