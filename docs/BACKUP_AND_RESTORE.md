# Backup and restore

Database backups use SQLite's backup API, never a blind live-file copy. Each generated snapshot is opened read-only, integrity checked, checked for required tables, hashed with SHA-256, and paired with a hashed manifest. Full database snapshots are sensitive because recovery requires protected authentication tables. Store them with restrictive host permissions.

Configure `THREATSCOPE_BACKUP_ENCRYPTION_KEY` with a Fernet key. Production must also enable `THREATSCOPE_REQUIRE_BACKUP_ENCRYPTION`. Keys are never written to backup metadata or logs. Retention always requires a preview and explicit phrase, preserves protected snapshots, the newest valid snapshot, and the configured minimum.

Restore validation verifies managed path, size, extension, checksums, manifest, encryption, schema, SQLite integrity, and required tables without touching the live database. UI execution confirms password, MFA when enabled, and `RESTORE THREATSCOPE DATA`; it creates a protected pre-restore backup and stages replacement. Stop the backend, then run `python scripts/restore_backup.py BACKUP_ID --validate-only` followed by the confirmed command without `--validate-only`. The script preserves the old database, rolls it back on failure, revokes all sessions after success, and requires a restart and new login. It never restarts the service itself.
