# Production deployment

Phase 19 provides a production-oriented, single-node Docker Compose deployment. It does not deploy automatically to any host and it is not a zero-downtime, multi-node architecture.

1. Review [PRODUCTION_CONFIGURATION.md](PRODUCTION_CONFIGURATION.md), copy `.env.production.example` to the ignored `.env.production`, and replace every placeholder.
2. Store session, MFA, connector, and backup keys outside the repository as restrictive regular files. Supply a deployment-owner-managed TLS certificate and key whose SAN covers the public hostname.
3. Create encrypted offline backups of any existing database and persistent uploads/reports.
4. Run `docker compose --env-file .env.production -f docker-compose.production.yml config` and the production preflight before promotion.
5. Build reviewed images with explicit version, full revision, and UTC build timestamp metadata.
6. Start with `docker compose --env-file .env.production -f docker-compose.production.yml up --build -d` and verify HTTPS, readiness, build identity, authentication, audit integrity, and backup status.

Only the edge service publishes ports. HTTP redirects to HTTPS; the backend is reachable only on the internal application network. The local Phase 19 smoke material is ephemeral and never suitable for production.

SQLite requires one backend worker and suits only bounded, single-node workloads. Use host/filesystem encryption because database encryption at rest is not provided by default.
