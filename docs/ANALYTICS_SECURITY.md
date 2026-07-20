# Analytics security

All analytics APIs inherit authenticated platform authorization and CSRF protection. Eight exact permissions separate viewing, aggregate access, management, execution, review, suppression, export, and administration. Backend checks remain authoritative even when the UI hides an action; executives receive aggregate-only access.

Requests use strict bounded schemas. IDs are resolved through protected routes, mutations are audited, optimistic locks prevent lost updates, idempotency keys prevent duplicate work, and rate limits bound expensive job submission. Safe output removes secret-like keys and does not expose raw source payloads or peer membership.

The analytics package does not perform networking, execute commands, dynamically import code, evaluate expressions, deserialize pickle/joblib models, or accept arbitrary SQL. SOAR integration is proposal/simulation/local-evidence only and performs no external containment. Connector integration writes approved redacted events to the transactional outbox after source commit.
