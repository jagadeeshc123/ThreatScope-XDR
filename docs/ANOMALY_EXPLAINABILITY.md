# Anomaly explainability

Every materialized anomaly carries a bounded explanation: expected range, observed value, score, confidence, severity, baseline and detector version, top contributions, reason codes, sample sufficiency, drift state, limitations, and observation window.

Safe wording describes anomalous behavior, statistical deviation, and potential operational or security concern. It does not claim that AI confirmed an attack, identify a user as malicious, guarantee accuracy, predict attacks, or promise zero false positives.

Explanation serialization recursively redacts secret-like keys and truncates oversized values. It contains aggregates only—no credentials, tokens, raw email or document content, full connector payloads, or individual peer membership.
