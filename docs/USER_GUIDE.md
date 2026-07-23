# User guide

## Sign in and account security

Open `/login` and use the local username or email identifier plus the separate ThreatScope password. No mailbox or external identity provider is contacted. Complete a required password change before other workflows. MFA enrollment under Profile Security displays a locally rendered TOTP QR code; save recovery codes in a protected location. Logout revokes the current session. Idle/absolute expiry or administrator revocation requires sign-in again; a permission denial is shown as forbidden, not as session expiry.

## Navigation and dashboard

The sidebar shows only modules allowed by effective permissions. Direct routes are guarded as a convenience, but the backend remains authoritative. Dashboard cards summarize stored data that the current role may see. A zero after loading is a count, not proof of safety. Use global search for bounded permission-filtered summaries and Notifications for recipient/permission-filtered workflow messages.

## Authorized assessments

Register a Web Exposure target only after confirming authorization. Choose a safe scan profile and review scope before starting. API Security imports bounded OpenAPI/Postman definitions and reviews endpoints, JWT structure, authorization matrices, and business flows without exploiting a service. Document and phishing workflows perform bounded static/offline analysis; suspicious indicators are not definitive malware or phishing verdicts.

## Investigations and governance

SOC Monitor works on imported or synthetic local events. Correlation joins normalized stored observations and lets authorized analysts explicitly create/manage cases. Governance organizes risk, mappings, treatments, exceptions, evidence, reviews, and reports; it does not certify compliance. Threat Intelligence uses local indicators/watchlists and stored-data correlation. Detection Engineering validates a bounded rule subset and evaluates stored records. Vulnerability Management prioritizes eligible stored findings and tracks remediation evidence.

## Simulations, integrations, and analytics

SOAR-Lite playbooks are declarative and server-owned actions remain dry-run, simulation, or tightly bounded local state changes. They do not isolate endpoints, block firewalls, delete malware, close cases automatically, or punish users. Integration Hub credentials are write-only after save. Test/delivery requires explicit policy and action; queued/configured does not mean delivered. Analytics uses deterministic local features and scoring. An anomaly indicates deviation requiring review, not compromise; missing reviewed labels do not produce accuracy/recall/F1 claims.

## Reports and safe interpretation

Reports are static escaped HTML downloads. Verify scope, timestamp, limitations, evidence, and role authorization before sharing. A finding is not proof of exploitation, confidence is not severity, and a posture score is not a certification. Follow the module's remediation guidance and record analyst decisions rather than treating automated output as a verdict.

## Common states

Loading text means the route or API request is active. Empty states mean no visible records match; they are not errors. Recoverable errors provide a retry where safe. A 403 means the session is valid but lacks permission. A 404 may intentionally avoid revealing whether an inaccessible object exists. A 409 indicates a state/version conflict; refresh before retrying. A 422 indicates invalid input and a 429 indicates a rate limit.
