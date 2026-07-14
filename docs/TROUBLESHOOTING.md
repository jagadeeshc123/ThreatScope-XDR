# Troubleshooting

If liveness fails, check that the backend process is running. If readiness returns `503`, authenticate and inspect Operations → Health and Configuration. Common causes are inaccessible runtime directories, an empty role catalog, or invalid production security settings. Responses deliberately omit raw paths and exceptions; correlate the returned `X-Request-ID` with local structured logs.

If a backup fails, verify SQLite access, free space, directory permissions, maximum size, and Fernet key format. Incomplete files are removed. If verification fails, do not restore or delete the newest valid backup. If restore staging is pending, stop the service and follow `BACKUP_AND_RESTORE.md`; never copy over a running SQLite database.

If the UI returns 401, sign in again. A 403 indicates missing permission or CSRF failure. Direct route refresh should return the SPA shell through Vite. Docker diagnostics use `docker compose ps` and the public health endpoints; operational files are not served by the frontend.
