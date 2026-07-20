# Anomaly scoring

Phase 18 implements static thresholds, z-score, robust z-score, IQR distance, percentile bands, EWMA deviation, rate-of-change, consecutive-failure thresholds, seasonal baselines, and weighted ensembles in pure Python. Inputs and outputs are bounded and deterministic.

Anomaly score, confidence, and severity are separate. Score measures deviation; confidence reflects sample sufficiency, missingness, peer support, seasonality, and drift; severity maps reviewed score bands and business context. A high score with low confidence remains low confidence.

Cooldown and deterministic fingerprints deduplicate materialized anomalies while preserving occurrence count and history. Suppressed matches are countable but do not delete evidence. Scoring never changes source records or performs a response action.
