# ThreatScope Security Integration Hub

Phase 17 adds a server-owned connector catalog, disabled connector instances, declarative subscriptions/mappings, canonical events, transactional outbox, bounded deliveries, attempts, retries, circuits, dead letters, signed inbound quarantine, STIX preview/promotion, and TAXII pull.

Built-ins: Local Test Sink, generic outbound/inbound HMAC webhooks, Slack, Teams, SMTP, Jira, ServiceNow, Splunk HEC, STIX 2.1, and TAXII 2.1. Arbitrary code, REST paths, SQL, scripts, shell, external deletion, and containment are unsupported. Connectors move draft to testing to active only after validation, credentials where needed, and a successful test. Process-due performs bounded work; Phase 19 may add managed scheduling. SOAR actions queue deliveries and all containment actions remain simulations.

Connector lifecycle, security thresholds, credential rotation, circuit transitions, dead letters, TAXII failures, ticket creation, and SOAR delivery requests use the existing recipient-specific notification table. Events are emitted only after the source mutation commits, deduplicated by event/entity/recipient, permission filtered, internally routed, bounded, and redacted. Successful integration mutations use explicit operation names in the existing hash-chained security audit log.
