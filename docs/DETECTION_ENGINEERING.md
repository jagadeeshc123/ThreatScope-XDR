# Detection Engineering

ThreatScope XDR Detection Engineering is an offline-first rule-authoring, validation, testing, and stored-event evaluation module. It does not deploy endpoint agents, collect live telemetry, execute commands, fetch rule feeds, or perform active response.

## Rule formats and safe Sigma subset

The module accepts native ThreatScope JSON, bounded Sigma YAML, bounded Sigma JSON, and rules created with the guided UI. Sigma metadata supports title, ID, status, description, references, author, dates, tags, logsource, detection selections, condition, false positives, and level. Conditions support named selections, `and`, `or`, `not`, parentheses, `1 of selection*`, and `all of selection*` with bounded depth.

Field matching supports case-insensitive equality, contains, starts-with, ends-with, bounded wildcards, list membership, numeric comparisons, existence, and CIDR membership. Fields outside the local allowlist are warnings and evaluate as missing.

YAML is parsed with `yaml.safe_load_all` after rejecting aliases, anchors, and custom tags. Imports are limited to 1 MiB and 50 rules. The service does not support arbitrary Python, regular expressions, Jinja, shell substitutions, external includes, executable modifiers, recursive expressions, or repository downloads. Original upload bytes are not stored; safe previews and SHA-256 content identities are calculated in memory.

## Normalized stored-event model

Evaluation uses a read-only canonical dictionary containing the supported `event.*`, `source.*`, `destination.*`, `user.*`, `host.*`, `process.*`, `file.*`, `url.*`, `http.*`, `network.*`, `threat.*`, `case.id`, and `tags` fields. Only fields already present in stored ThreatScope records are mapped. Strings are bounded, timestamps normalized, missing fields represented safely, and command lines, URLs, file paths, and messages treated as hostile text. No DNS, enrichment, URL retrieval, file opening, or command execution occurs.

## Lifecycle, versioning, and tests

Rules move through draft, testing, active, disabled, and archived states. Every meaningful edit creates a sequential immutable version with actor, timestamp, change summary, normalized condition, and SHA-256 content hash. Rollback copies a historical version into a new version; history is never overwritten.

Activation requires static validation, at least one enabled synthetic test, and all enabled positive and negative tests to pass. Test dictionaries are bounded to 64 KiB and 64 canonical fields. They never open arbitrary paths, fetch URLs, or execute values.

## Historical execution, matches, and suppressions

Historical execution is bounded to 25 rules and 5,000 stored records, ordered deterministically, and processed synchronously within the existing request architecture. A fingerprint of rule, version, module, entity type, and entity ID prevents endless duplicate matches. Source records are never modified.

Suppressions are explicit analyst-authored field conditions with required reasons and optional validity windows. Suppressed matches remain stored and countable but do not create normal high-risk notifications. Expired or disabled suppressions do not apply. False-positive review dispositions persist across reruns.

Detection risk is a deterministic 0–100 heuristic using rule severity, confidence, quality, source-event severity, and lifecycle. Rule quality is a deterministic 0–100 heuristic using validation, documentation, positive and negative test coverage, and local ATT&CK mapping. Neither score is machine learning or an external reputation claim.

## ATT&CK-style educational coverage

ThreatScope seeds 27 commonly used Enterprise technique identifiers and names plus four protected demonstration rule packs. This bounded local catalog exists for educational coverage mapping only; it is not the complete current MITRE ATT&CK catalog and does not prove complete organizational coverage. Known `attack.tNNNN` Sigma tags map locally. Unknown tags remain warnings and are never invented as techniques.

## Review, alerts, cases, and reports

Analysts explicitly review matches. Alert promotion requires confirmation and SOC alert permission. Case escalation requires confirmation and `cases:create`. No evaluation creates alerts, cases, containment, firewall rules, or process actions automatically.

Static detection reports contain 24 sections, escape and redact hostile values, defang displayed URLs, contain no remote assets or scripts, and render in a sandboxed frame. Reports explain methodology, risk and quality scoring, local ATT&CK limitations, and offline evaluation.

## RBAC

- Administrator: all detection permissions.
- Security Analyst: view, manage, import, execute, review, and export.
- Auditor: view and export only.
- Executive Viewer: aggregate dashboard outcomes only.
- Registered User: no Detection Engineering access.

Backend authorization and CSRF enforcement are authoritative. Existing custom roles remain unchanged.
