# Logging and monitoring

Production backend logs are JSON and include UTC timestamp, severity, service/event, request ID, safe route, method, status, duration, actor identifier when allowed, and revision. Nginx access logs include timestamp, generated request ID, method, normalized path without query string, status, bytes, duration, and client address.

Central redaction covers nested authorization, cookie, password, secret, token, API key, signature, credential, private-key, CSRF, session, recovery-code, and TOTP fields. Bodies, credential-bearing URLs, environment dumps, database URLs, document/email/STIX payloads, and response bodies are not logged.

Container logs rotate at 10 MiB with five files. Operators should monitor readiness degradation, audit integrity, disk capacity, backup freshness/failure, restore failure, schema mismatch, and explicit registration or connector-egress enablement through approved local monitoring/connector workflows. No external telemetry is contacted automatically.
