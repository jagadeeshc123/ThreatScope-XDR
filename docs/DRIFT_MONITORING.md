# Drift monitoring

Server-owned drift signals cover mean, median, variance, MAD, percentile, missingness, cardinality, anomaly volume, score and confidence distributions, false-positive estimates, freshness, and schema-version change. Distribution comparison uses bounded aggregate data and deterministic thresholds.

Sparse samples produce `insufficient_data`. Detected drift records the prior and current aggregate distributions, score, threshold, confidence, affected volume, recommendation, and hash. Significant drift can degrade a detector and notify authorized reviewers.

There is no automatic retraining or activation. Acknowledgment requires a reason and preserves the record; remediation is an explicit new baseline/version, validation, backtest, and lifecycle decision.
