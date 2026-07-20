# Backup and restore runbook

Create a backup through the authenticated operations workflow. SQLite's backup API produces a consistent snapshot, bounded name, record counts, schema/application/revision metadata, SHA-256 integrity data, and a manifest. Production requires a file-mounted backup Fernet key; this is application-level backup encryption, not full database encryption at rest.

Validate the backup and copy the backup, manifest, uploads, persistent reports, configuration, keys, and TLS material to separately protected storage. Test restores regularly in an isolated environment.

Restore is an authorized maintenance operation: stop writes, validate checksum/schema/space/integrity, create a protected pre-restore backup, stage to temporary storage, perform a controlled offline replacement, verify SQLite and audit integrity, restart, verify readiness and authenticated smoke, and revoke sessions where required. Restore may require downtime. Never restore from a URL or an arbitrary API-provided filesystem path.
