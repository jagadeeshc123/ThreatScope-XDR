# Analytics reporting

Analytics reports are static self-contained HTML with exactly 40 sections covering scope, methods, detector health, anomalies, confidence, review, drift, suppressions, jobs, governance, privacy, limitations, and integrity metadata. Dynamic content is escaped; there are no scripts, forms, active links, remote assets, external fonts, or live queries.

Detailed reports require view/export permissions. Executive summaries are aggregate-only and omit entity, anomaly, detector-detail, feedback, and raw operational records. Export is audited and carries a SHA-256 content hash.

The frontend displays HTML only in an empty-sandbox iframe and downloads it as a separate artifact. Reports state that anomalies are not proof of compromise, metrics depend on reviewed labels, no external AI is used, and no automatic containment occurred.
