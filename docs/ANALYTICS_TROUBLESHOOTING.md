# Analytics troubleshooting

`insufficient_data` means the approved minimum sample, peer size, seasonal bucket, or freshness requirement was not met. Add legitimate historical telemetry or choose a supported wider lookback; do not fabricate samples. Low confidence commonly indicates sparse/missing/late data or drift.

Validation failures identify unknown catalog keys, incompatible windows/methods, unsafe scope, invalid thresholds, missing backtests, or quality gates without evidence. Active configurations are immutable, so create a new version rather than editing them.

Failed jobs retain a safe bounded error summary. Stale running jobs are failed on the next process-due call and are not retried automatically. Check `/operations/diagnostics`, database writeability, schema sentinel 18, permissions, CSRF, and source-module data. Browser verification may be unavailable in headless environments; use build, route-refresh HTTP checks, API smoke tests, screenshots when available, and document the limitation.
