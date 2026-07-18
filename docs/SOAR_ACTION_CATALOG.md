# SOAR-Lite action catalog

The immutable action catalog lives in backend source. Each definition includes its key, name, category, description, exact safety classification, allowed modes, required permission, approval and separation rules, bounded input/output schemas, timeout/retry limits, retryable error codes, idempotency and compensation support, simulation flag, automatic-local eligibility, evidence support, audit event, and warning. Clients can read the catalog; no API can add an action or alter implementation, safety class, callable, module, database operation, URL, command, or simulation boundary.

Classifications are:

- `read_only`: permission-filtered, redacted, bounded reads with no mutation.
- `harmless_local`: internal notes, evidence, links, notifications, or analyst tasks; automatic only when policy explicitly allows it.
- `controlled_local`: ordinary ThreatScope workflow changes with action-specific permission and policy approval.
- `sensitive_local`: ThreatScope user/session security changes; always explicit Administrator approval with requester/approver separation where another eligible Administrator exists.
- `simulation_only`: records intended external containment without network, operating-system, identity-provider, firewall, DNS, WAF, proxy, EDR, mailbox, endpoint, or cloud mutation.

Read actions cover SOC alerts, cases, detections, IOC matches, vulnerabilities, phishing, documents, users, sessions, assets, workflow risk, links, tasks, notifications, and ownership. Local actions cover case creation/reuse/assignment/severity/comment/evidence/tag/source links/tasks/transitions; SOC review; detection proposals; watchlists; vulnerability assignment/comments/plans/tasks/verification/risk proposals; notifications/review tasks/evidence; and sensitive session revocation or temporary user disable/re-enable.

Simulation-only actions cover IP/domain/URL block, endpoint quarantine, host isolation, external account/token changes, malicious-email removal, firewall/WAF/DNS/proxy/EDR updates, process termination, and malicious-file quarantine. Every result is `simulated`, records intended target, reason and assumptions, states that no external infrastructure was modified, and displays `SIMULATION ONLY — NO EXTERNAL ACTION IS PERFORMED`. No simulated action supports `live_local`.

Administrators may disable catalog actions, allow eligible harmless automatic-local work, require stricter approval, lower retries, or add notes. They cannot weaken sensitive approval/separation, enable sensitive/simulation automatic-local behavior, change a classification, make simulation real, or exceed the server retry maximum. Policies seed idempotently and existing changes survive restart.
