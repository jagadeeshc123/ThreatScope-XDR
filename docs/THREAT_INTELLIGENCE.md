# Threat Intelligence and IOC Correlation

ThreatScope XDR Phase 13 is an offline-first threat-intelligence workspace. It manages local indicators and correlates them only with records already stored by ThreatScope XDR. It never resolves DNS, fetches a URL, downloads a feed, queries an external reputation service, executes malware, or blocks traffic.

## Supported indicators and normalization

Supported types are `ipv4`, `ipv6`, `cidr`, `domain`, `hostname`, `url`, `email`, `sha256`, `sha1`, `md5`, `file_name`, `user_agent`, `vulnerability_id`, and `custom`.

- IP addresses and CIDRs use Python's standard `ipaddress` canonical form. CIDR host bits are cleared.
- Domains and hostnames are IDNA-normalized, lowercased, length-bounded, and never resolved.
- Email local parts are retained; email domains are normalized like domains.
- HTTP(S) URLs have a lowercased scheme and canonical host, default ports removed, fragments removed, and paths safely quoted. Userinfo and non-HTTP(S) schemes are rejected.
- Hashes must be hexadecimal and exactly match the selected algorithm length.
- File names reject paths and are case-folded. User agents are whitespace-normalized and case-folded.
- Vulnerability IDs support canonical CVE identifiers. Custom values are whitespace-normalized and case-folded.

The original submitted text is retained as inert, bounded data. The uniqueness identity is `(indicator_type, normalized_value)` and its SHA-256 identity hash is indexed. Different types never merge. Duplicate ingestion merges tags without repetition, keeps the earliest `first_seen`, keeps the latest `last_seen`, and sets confidence to the maximum submitted confidence. This is deterministic and repeated identical imports do not increase confidence further. Source identity is not overwritten and revoked indicators are never reactivated by an import.

## Sources and imports

Sources record provenance, type, reliability, default confidence, TLP handling, enabled state, and last import time. Imports accept up to 2 MiB and 5,000 records. Uploaded bytes are parsed in memory, hashed with SHA-256, and discarded after the request. Only the safe base filename, counts, digest, status, and bounded errors remain.

CSV and JSON support `type`, `value`, `title`, `description`, `severity`, `confidence`, `tlp`, `tags`, `first_seen`, `last_seen`, and `valid_until`. JSON can be an array or an object with an `indicators` array. Plain text uses one `type value` pair per line.

The bounded STIX 2 JSON subset accepts bundles containing simple indicator equality patterns for IPv4, IPv6, domain, URL, and email SCO values, plus explicit MD5/SHA-1/SHA-256 file-hash patterns; relationships between indicators; and malware, threat-actor, or campaign objects as contextual campaign records. Unsupported objects/patterns produce warnings. This is not complete STIX or TAXII compatibility.

## Watchlists, campaigns, and relationships

The idempotent protected watchlists are High-Risk Indicators, Confirmed Malicious, and Under Investigation. Analysts can create additional enabled/disabled watchlists, add indicators once, and remove an entry without deleting the indicator.

Campaigns are analyst-defined collections. Relationships support `related_to`, `resolves_to`, `redirects_to`, `communicates_with`, `downloads`, `drops`, `impersonates`, `associated_with`, `duplicate_of`, and `custom`. Self-relationships and duplicates are rejected. Graphs are data-only and do not assert causality.

## Stored-data correlation

Correlation inspects normalized values already stored in SOC events/alerts, phishing indicators and sender/reply-to fields, document indicators/hashes/embedded artifacts, Web Exposure targets, API assessment hosts, unified entities, and case evidence linked to unified entities. Source records are never modified or re-executed.

Matching is exact by default. URL exact matches and URL-host-only matches remain distinct. Email and hash comparisons are exact. IP comparisons are exact or explicit CIDR membership. Hashes and IPs never use fuzzy matching. Reruns reuse sightings and matches instead of creating duplicates.

## Deterministic match risk

The score is bounded to 0–100. It adds indicator severity × 0.35, indicator confidence × 0.25, source reliability × 0.10, up to 10 points for occurrences, up to 10 for affected modules, 2–8 for recency, 8 for watchlist membership, 5 for Confirmed Malicious membership, and 2–5 for match strength. Expired indicators receive a 0.6 multiplier. Inactive, revoked, or false-positive indicators score zero and do not produce normal active matches.

Classifications are 0–19 informational, 20–39 low, 40–59 medium, 60–79 high, and 80–100 critical. This is deterministic rules-based scoring, not machine learning or external reputation.

## Review, escalation, display, and reports

Match dispositions are reviewing, confirmed, false positive, accepted risk, and escalated. The reviewer, time, bounded note, and optional case link are retained. Creating or linking an incident case requires an explicit confirmation and `cases:create`; correlation never creates cases automatically.

The UI renders URLs, domains, IPs, and emails as text. It provides Copy and an explicit raw/defanged toggle, never a dangerous anchor or preview. Defanging changes `http` to `hxxp` and `.` to `[.]`; email display also changes `@` to `[@]`.

HTML reports contain all 20 prescribed sections, escape data, have no remote assets or scripts, and default to defanged values. Raw generation requires `threat_intel:export` and an explicit UI warning. Report generation performs no lookup.

## RBAC, audit, operations, and limitations

- Administrator: all threat-intelligence permissions.
- Security Analyst: view, import, manage, correlate, and export.
- Auditor: view and export only.
- Executive Viewer: aggregate dashboard values under existing dashboard conventions; no direct module access.
- Registered User: no threat-intelligence access.

Mutations use authenticated cookie sessions, CSRF, bounded inputs, and centralized authorization. Explicit source, indicator lifecycle, import, watchlist, campaign, relationship, correlation, review, escalation, and report events join the hash-chained audit log after the primary transaction commits. Notifications are deduplicated and created only after successful correlation/import/escalation transactions.

Full database backup includes all Phase 13 tables; restore validation requires the Phase 13 schema identifier. Retention can remove old import manifests and completed/failed correlation-run manifests, but never deletes an indicator merely because it expired. Case-linked records and audit history remain preserved.

Limitations: there is no feed polling, TAXII client, external reputation enrichment, automated blocking, endpoint agent, packet capture, malware execution, sandbox, active exploitation, or complete STIX ecosystem support.
