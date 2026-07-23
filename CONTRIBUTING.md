# Contributing

ThreatScope XDR is in a v1 product freeze. Contributions must address a confirmed defect, security issue, dependency/compatibility maintenance, documentation correction, or carefully reviewed operational improvement. Do not begin a new roadmap phase or add speculative modules, providers, telemetry, autonomous response, deployment targets, databases, identity providers, agents, or extensions.

Create a focused branch from the reviewed baseline, preserve unrelated user changes, and never commit secrets, databases, TLS material, runtime artifacts, generated reports/manifests/inventories/checksums, source maps, or unauthorized test data. Security-sensitive changes must preserve server authorization, CSRF, session/audit behavior, SSRF/connector boundaries, report/upload safety, and cautious product language.

Run backend compile/full tests/network-disabled harness/verifier/pip check, frontend npm ci/build/lint/dependency validation, Compose config, and relevant production smoke. Add meaningful regression coverage for a confirmed behavior; do not delete or weaken prior tests. Update user/operator/developer documentation and schema/backup/rollback guidance when applicable.

Pull requests should state the defect and reproduction, impact, root cause, remediation, tests, schema decision, security/operational effects, dependencies, documentation, and remaining limitations. Commits should be reviewable and must not fabricate release evidence. Use only authorized local/synthetic targets in development and tests.
