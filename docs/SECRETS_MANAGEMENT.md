# Secrets management

Production consumes secrets from files mounted at runtime. `_FILE` references are absolute, bounded regular files; symlinks, empty/oversized files, and detectable world-writable files are rejected. Supplying both a direct value and `_FILE`, or a direct production value alone, fails startup.

Never commit `.env.production`, secret files, passwords, Fernet keys, connector tokens, TLS keys, or certificates. Do not put them in Compose environment values, build arguments, commands, labels, image layers, logs, API responses, frontend bundles, inventories, or release manifests.

Use separate values for session signing, MFA encryption, connector credential encryption, and backup encryption. Back up keys through an independently protected operator process. Rotation must account for existing sessions and encrypted records; loss of a key can make protected data unrecoverable. Production has no reusable default credential or environment-password bootstrap.
