# Analytics model governance

Although the module uses statistical detectors rather than opaque learned models, it applies model-governance controls: immutable catalogs, versioned configurations, hashes, validation, leakage-resistant backtests, quality gates, explicit activation, degradation on drift, audited rollback, and retention.

Quality claims distinguish operational coverage from reviewed-label evidence. Precision and false-positive estimates are reported only when sufficient reviewed labels exist. Recall, F1, accuracy, or efficacy are not claimed without a defensible labeled population.

Drift never starts automatic retraining. An administrator or analyst reviews the aggregate evidence, builds a new baseline or version explicitly, validates it, and performs an audited lifecycle action. No external model registry, download, unsafe pickle/joblib artifact, or AI service is used.
