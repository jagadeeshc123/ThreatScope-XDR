# Advanced security analytics

Phase 18 adds deterministic, offline-first statistical analytics over data already stored by ThreatScope XDR. It provides 64 immutable detector templates (unavailable templates are explicitly identified), 42 server-owned feature definitions, versioned detectors, baseline construction, backtests, anomalies, analyst feedback, suppressions, drift review, reports, and operational integration.

An anomaly is a statistical deviation and is not proof of compromise, malicious intent, or a confirmed attack. Sparse history, missing data, late arrival, seasonality mismatch, and third-party data quality lower confidence. No external AI or model service is used, and the module never performs automatic containment, case closure, user punishment, or automatic retraining.

The local API is under `/api/analytics`; the UI starts at `/analytics`. Source facts remain owned by their original modules. Analytics stores derived aggregates, immutable configuration versions, explanations, and workflow records without rewriting source evidence.

SQLite is suitable for local and small-scale use. `process-due` is a bounded operator-invoked dispatcher, not a production distributed scheduler, and enterprise real-time streaming is outside Phase 18.
