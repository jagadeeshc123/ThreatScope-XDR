# Baseline methods

Baselines contain bounded aggregate statistics: observation and missing counts, mean, median, standard deviation, MAD, IQR, percentiles, optional winsorization summary, seasonal buckets, cutoff, scope, and deterministic hash. They never expose individual source rows.

Insufficient history produces an explicit `insufficient_data` state and reason rather than a score. Zero-spread baselines use documented deterministic fallbacks. Approved seasonality is limited to none, hour of day, day of week, and hour of week; missing seasonal buckets fall back to the global baseline and lower confidence.

Baseline builds are idempotent for a version, feature, scope, and cutoff. Data later than the cutoff is excluded, preventing future leakage during backtests.
