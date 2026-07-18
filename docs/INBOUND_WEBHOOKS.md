# Signed Inbound Webhooks

Endpoint UUIDs identify routes but are not credentials. JSON requests send X-ThreatScope-Event-ID, X-ThreatScope-Timestamp, X-ThreatScope-Schema-Version, and X-ThreatScope-Signature. The signature is sha256=HMAC-SHA256(secret, timestamp + dot + raw_body) and comparison is constant-time.

ThreatScope bounds the body before parsing, validates timestamp/schema/signature, hashes replay identity, and stores an expiring nonce. Valid content is redacted, mapped, and quarantined by default. Promotion requires permission, confirmation, attribution, duplicate checks, and a bounded target proposal. Authentication failures are generic.

Signing-secret rotation supports only the immediately previous secret and only for a fixed five-minute encrypted overlap. After expiry (or another rotation), the older signature is rejected with the same generic authentication response.

## Persistent abuse controls

Every inbound attempt consumes persistent SQLite fixed-window counters before signature verification or JSON domain processing. Counters are isolated per endpoint and privacy-hashed source summary, with a global window. Invalid signatures, replay attempts, and other invalid requests consume dedicated threshold counters. Defaults are 60 endpoint requests/minute, 30 source requests/minute, 300 global requests/minute, 10 signature failures/5 minutes, and 5 replay attempts/5 minutes. Server hard caps bound every limit and window. Exceeding a counter returns generic HTTP 429 with `Retry-After` capped at 300 seconds. Counter keys contain hashes only, expire automatically, and are cleaned by process-due and retention.
