# Production troubleshooting

If preflight fails, use the remediation code and correct the named setting or storage condition; never weaken the validation. Common causes are a direct/conflicting secret, invalid Fernet key, wildcard/insecure origin, unavailable TLS file, relative SQLite path, wrong ownership, multiple workers, missing revision, or insufficient disk.

For edge failure, inspect bounded container logs for template, certificate permission/SAN, hostname, upstream health, or port conflicts. For readiness failure, verify schema metadata, SQLite quick-check, data-volume ownership, audit integrity, and secrets without printing values.

For restore failure, keep the current database unchanged, retain the safety backup, validate hashes/schema/space offline, and escalate. Do not use `verify=False` as evidence of valid production TLS, expose the backend temporarily, enable docs/debug, reset data, regenerate encryption keys, or substitute the smoke certificate.
