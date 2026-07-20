# Supply-chain security

Python requirements are exact-pinned under the repository convention; npm installs from `package-lock.json` via `npm ci`. Production base images use explicit version tags rather than `latest`. No application runtime downloads packages or models, and no curl-pipe-shell installer is used.

The local dependency inventory records installed Python/npm names and versions, configured base images, application/schema/revision, and manifest hashes. It is not claimed to be SPDX or CycloneDX. Generated inventories and manifests are ignored.

CI uses official read-only actions, bounded job timeouts, concurrency cancellation, no `pull_request_target`, no deployment, and no long-lived release credential. Deployment owners should pin reviewed image digests and perform independent vulnerability and provenance review.
