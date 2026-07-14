# Release guide

`VERSION` is the deterministic product version source. Generate the local software inventory through Operations or `inventory_service`; it reads only pinned Python requirements, npm manifests, Docker base declarations, and registered modules. It performs no vulnerability lookup and makes no security or license-compliance claim.

Enter `backend` and run `python scripts/build_release.py`. A dirty worktree is refused unless `--allow-dirty` is explicit; such output is visibly marked dirty. The deterministic ZIP contains approved source, Docker configuration, manifests, documentation, `.env.example`, inventory, release manifest, and checksums. It excludes Git metadata, references, `.env`, databases, runtime artifacts, uploads, reports, `node_modules`, built frontend output, virtual environments, caches, IDE settings, keys, logs, and coverage.

The GitHub workflow compiles and tests backend, builds and lints frontend, checks dependencies and hygiene, and validates Compose. It does not deploy, publish, tag, upload backups, or create a GitHub release. “Release candidate” and “locally verified” do not mean certified, compliant, externally audited, production-approved, or vulnerability-free.
