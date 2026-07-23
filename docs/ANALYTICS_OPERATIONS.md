# Analytics operations

Database schema v19 includes the analytics tables introduced in schema 18: detectors, versions, baselines, jobs, backtests, evaluations, anomalies, contributions, feedback, suppressions, drift, and reports. Startup creates missing tables through the existing additive metadata flow. Backup inventory, staged restore validation, retention preview/apply, diagnostics, activity, notifications, audit, demo reset, dashboard, and search include analytics records.

Jobs move through queued, running, succeeded, failed, or cancelled states. `POST /api/analytics/process-due` handles at most 100 queued records, rechecks permission, updates heartbeats, and recovers stale running jobs as failed without an automatic retry. Repeated idempotency keys return the existing job.

For local operation, run the normal backend and frontend verification commands. Monitor failed/stale jobs, insufficient baselines, degraded detectors, drift warnings, review backlog, retention previews, and backup manifests. SQLite and the synchronous dispatcher are not distributed production infrastructure.
