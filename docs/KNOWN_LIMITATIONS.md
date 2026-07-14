# Known limitations

- SQLite restore is deliberately staged; final replacement requires a stopped backend and local administrator script.
- Import is validation-only and never merges records into live modules.
- Retention has no automatic scheduler.
- Health does not contact external services; the local test target remains an explicitly authorized workflow.
- Software inventory is manifest-based and is not a vulnerability or license assessment.
- Release artifacts are unsigned release candidates and are not production-certified.
- Audit chaining provides local tamper evidence, not external notarization against a privileged full-database rewrite.
- Demo seeding currently provides a deterministic base scenario and does not auto-create demo users.
- Native PDF generation, cloud backup, external monitoring, telemetry, deployment, and automatic update are absent.
