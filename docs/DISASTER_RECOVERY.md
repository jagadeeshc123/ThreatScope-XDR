# Disaster recovery

ThreatScope Phase 19 supports a bounded single-node recovery plan. Preserve the reviewed image/revision, production Compose file and environment policy, database backup and manifest, uploads, required report artifacts, secret files, and deployment-owner TLS material.

Recover the host and encrypted filesystem, restore restrictive ownership, validate configuration/preflight, start no public traffic, restore and validate data, confirm schema v19 and encryption-key consistency, verify audit integrity, start the edge, run authenticated smoke, and then reopen traffic.

RPO and RTO are operator-defined; Phase 19 guarantees neither. Escalate on hash/schema mismatch, missing keys, corruption, audit failure, or uncertain provenance. Do not bypass validation to accelerate recovery.
