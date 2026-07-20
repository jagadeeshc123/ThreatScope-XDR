# Detector catalog

The detector catalog in `backend/app/modules/analytics/catalog.py` is server-owned and immutable at runtime. It declares 64 use cases across authentication, SOC, API, documents, phishing, correlation, governance, threat intelligence, detections, vulnerabilities, SOAR, integrations, operations, and platform posture.

Each entry states its source domain, feature, approved method, default window, minimum samples, and availability. A listed but unavailable detector includes a precise reason; the API never silently pretends unsupported telemetry exists. User-provided Python, SQL, expressions, imports, serialized models, shell commands, URLs, and arbitrary REST definitions are not accepted.

Configuration creates immutable detector versions. Validation and backtesting precede explicit activation. Disablement and retirement preserve history. Rollback selects a prior reviewed version through an audited lifecycle action rather than mutating an active version.
