# Release process

Phase 19 release engineering is local and operator-controlled. Verify a clean intended diff, exact baseline, full tests, network-disabled tests, frontend build/lint/dependencies, development Compose, production Compose/TLS/authentication/persistence/restore smoke, container inspection, image-content scan, log redaction, and sensitive-artifact scan.

Generate the ignored dependency inventory and release manifest only after tests. Confirm version, schema, full Git revision, build IDs, manifest hashes, Dockerfile/Compose/Nginx hashes, and test-summary reference. OCI labels receive non-secret version/revision/timestamp build arguments.

The workflow creates no tag, publication, deployment, or v1.0 release automatically. Vulnerability-scan results must not be claimed unless an identified scanner was actually run and its output reviewed.
