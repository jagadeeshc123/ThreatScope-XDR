# Upgrade and rollback

Before upgrade, record current version/revision/schema, create and validate an offline backup, preserve configuration and keys, run strict preflight, build reviewed images, and validate release metadata. Start the upgrade in a maintenance window, allow additive schema initialization, then verify readiness, audit integrity, authentication, routes, reports, and backups.

Rollback criteria include startup failure, schema failure, authentication/security regression, failed smoke, or data-integrity failure. Application-only rollback uses the previous reviewed image when schema-compatible. Configuration rollback restores the reviewed prior configuration without replacing secrets. Database rollback uses the validated pre-upgrade backup through the offline restore workflow.

Not every schema change is automatically reversible. Rollback may invalidate sessions and must preserve encryption keys, connector policy, and audit evidence. No automatic rollback or zero-downtime claim is made.
