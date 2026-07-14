# Data retention

Retention applies only to configured non-critical history: successful operational jobs, deleted artifact metadata, expired login attempts, revoked expired sessions, used MFA challenges, old read notifications, and operational activity. Active identities, permissions, sessions, findings, alerts, cases, governance records, evidence, source assessments, newest valid backups, protected backups, and every security audit event are excluded.

Administrators configure bounded days and minimum keep counts, run a preview, inspect exact candidate IDs, and type `APPLY RETENTION PREVIEW`. A preview expires after 15 minutes. Apply revalidates every candidate and deletes only the exact preview set in a transaction. There is no automatic scheduler.
