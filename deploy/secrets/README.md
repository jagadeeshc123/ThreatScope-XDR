# Production secret mounts

This directory contains documentation only. Never place live secrets in the repository. Create secret files outside the source checkout, grant read access only to the deployment operator and the intended container runtime, and reference their absolute paths from the ignored `.env.production` file.

Required files contain a strong session signing secret and separate valid Fernet keys for MFA, connector credentials, and backup encryption. Each file contains only its value with an optional trailing newline. Direct secret environment variables are rejected in production, symlinks are rejected, files are size-bounded, and world-writable files are rejected where the operating system exposes reliable mode bits.

Rotate keys only through a reviewed workflow that accounts for existing sessions, encrypted MFA devices, connector credentials, and backups. Losing an encryption key can make the corresponding encrypted records unrecoverable.
