# Outbound Deliveries

Canonical v1 events store safe identity/time/source/severity/title/summary/tags/actor metadata, redacted payload, hash, and idempotency key. Minimal egress is default. Standard and Administrator-configured extended profiles remain allowlisted and always exclude credentials, sessions, MFA data, raw files, hostile content, environment data, and unbounded evidence.

Outbox content is append-only and committed before delivery. Attempts omit headers and bodies. Retryable failures use bounded exponential delays; seven attempts is the hard maximum. Five consecutive retryable failures open a 15-minute circuit. Dead letters never replay automatically; manual replay revalidates and creates a new delivery. Successful history is immutable.
