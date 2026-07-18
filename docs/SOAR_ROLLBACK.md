# SOAR-Lite compensation and rollback

Rollback never rewinds the database or deletes execution history. A request creates a record per completed action with redacted before state, intended compensation, requester, reason, and either approval-required or explicit `not_supported` status. Approved execution reloads current state and applies only the fixed compensating action. A newer analyst change produces a conflict instead of an overwrite. Every completed, failed, partial, cancelled, conflicted, and unsupported result remains in history.

Supported compensation includes restoring a previous case owner, severity, or valid status; removing an execution-added tag; cancelling an execution-created case/remediation task; restoring a vulnerability owner; restoring playbook enabled state; and approval-gated re-enable of a temporarily disabled ThreatScope user.

Rollback is explicitly unsupported for external simulations, delivered notifications, audit history, consumed approvals, irreversibly revoked sessions, and any external firewall/DNS/WAF/proxy/EDR/mailbox/endpoint/identity-provider simulation. A simulation is never described as externally reversed. Partial rollback is accurate: supported records may complete while unsupported or failed records remain visible.
