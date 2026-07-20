# Analytics suppressions

Suppressions are bounded declarative scopes using allowlisted fields. They require an owner, reason, start, expiry, status, and optimistic lock. Broad scope is administrator-only; emergency use remains explicit and audited. Wildcards, protected identity attributes, excessive duration, and unbounded values are rejected.

A suppression prevents matching analytics output from creating another active review item during its period. It does not delete the anomaly, source facts, occurrences, feedback, audit events, or reports. Hit counts and last review remain visible.

Expiry is evaluated locally when analytics work runs. Phase 18 installs no unmanaged scheduler; operators may invoke the existing bounded maintenance workflow.
