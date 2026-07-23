# Permissions matrix

Generated from the server-owned `permissions.json` and `default_roles.json` definitions. Administrator has the server-owned `*` wildcard; the other columns show explicit defaults. Frontend visibility is convenience only; the backend is authoritative.

| Permission | Description | Category | Administrator | Security Analyst | Auditor | Executive Viewer | Registered User | High-risk mutation/export |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dashboard:view` | View dashboards | General | Yes | Yes | Yes | Yes | Yes | — |
| `search:use` | Use global search | General | Yes | Yes | Yes | Yes | — | — |
| `notifications:read` | Read notifications | General | Yes | Yes | Yes | Yes | Yes | — |
| `activity:read` | Read activity | General | Yes | Yes | Yes | Yes | — | — |
| `profile:manage` | Manage own profile | General | Yes | Yes | Yes | Yes | Yes | Yes |
| `web:read` | Read web exposure data | Web Exposure | Yes | Yes | Yes | — | — | — |
| `web:manage_targets` | Manage web targets | Web Exposure | Yes | Yes | — | — | — | Yes |
| `web:run_scans` | Run web scans | Web Exposure | Yes | Yes | — | — | — | Yes |
| `web:delete` | Delete web exposure records | Web Exposure | Yes | Yes | — | — | — | Yes |
| `web:generate_reports` | Generate web reports | Web Exposure | Yes | Yes | — | — | — | Yes |
| `api:read` | Read API security data | API Security | Yes | Yes | Yes | — | — | — |
| `api:manage_assessments` | Manage API assessments | API Security | Yes | Yes | — | — | — | Yes |
| `api:import` | Import API definitions | API Security | Yes | Yes | — | — | — | Yes |
| `api:analyze` | Run API analyses | API Security | Yes | Yes | — | — | — | — |
| `api:manage_authorization` | Manage API authorization reviews | API Security | Yes | Yes | — | — | — | Yes |
| `api:manage_business_flows` | Manage API business flows | API Security | Yes | Yes | — | — | — | Yes |
| `api:delete` | Delete API security records | API Security | Yes | Yes | — | — | — | Yes |
| `api:generate_reports` | Generate API reports | API Security | Yes | Yes | — | — | — | Yes |
| `soc:read` | Read SOC data | SOC | Yes | Yes | Yes | — | — | — |
| `soc:import` | Import SOC events | SOC | Yes | Yes | — | — | — | Yes |
| `soc:simulate` | Run local SOC simulations | SOC | Yes | Yes | — | — | — | — |
| `soc:run_detection` | Run SOC detections | SOC | Yes | Yes | — | — | — | Yes |
| `soc:manage_alerts` | Manage SOC alerts | SOC | Yes | Yes | — | — | — | Yes |
| `soc:manage_rules` | Manage SOC rules | SOC | Yes | Yes | — | — | — | Yes |
| `soc:manage_watchlist` | Manage SOC watchlist | SOC | Yes | Yes | — | — | — | Yes |
| `soc:delete` | Delete SOC records | SOC | Yes | Yes | — | — | — | Yes |
| `soc:generate_reports` | Generate SOC reports | SOC | Yes | Yes | — | — | — | Yes |
| `document:read` | Read document analyses | Document Threat | Yes | Yes | Yes | — | — | — |
| `document:analyze` | Analyze documents | Document Threat | Yes | Yes | — | — | — | — |
| `document:delete` | Delete document analyses | Document Threat | Yes | Yes | — | — | — | Yes |
| `document:generate_reports` | Generate document reports | Document Threat | Yes | Yes | — | — | — | Yes |
| `phishing:read` | Read phishing analyses | Phishing Defense | Yes | Yes | Yes | — | — | — |
| `phishing:analyze` | Analyze phishing inputs | Phishing Defense | Yes | Yes | — | — | — | — |
| `phishing:manage_disposition` | Manage phishing disposition | Phishing Defense | Yes | Yes | — | — | — | Yes |
| `phishing:manage_watchlist` | Manage phishing watchlist | Phishing Defense | Yes | Yes | — | — | — | Yes |
| `phishing:delete` | Delete phishing analyses | Phishing Defense | Yes | Yes | — | — | — | Yes |
| `phishing:generate_reports` | Generate phishing reports | Phishing Defense | Yes | Yes | — | — | — | Yes |
| `correlation:read` | Read correlation data | Correlation and Cases | Yes | Yes | Yes | Yes | — | — |
| `correlation:synchronize` | Synchronize correlation records | Correlation and Cases | Yes | Yes | — | — | — | — |
| `correlation:run` | Run correlation | Correlation and Cases | Yes | Yes | — | — | — | Yes |
| `correlation:manage_matches` | Manage correlation matches | Correlation and Cases | Yes | Yes | — | — | — | Yes |
| `cases:read` | Read incident cases | Correlation and Cases | Yes | Yes | Yes | Yes | — | — |
| `cases:create` | Create incident cases | Correlation and Cases | Yes | Yes | — | — | — | — |
| `cases:manage` | Manage incident cases | Correlation and Cases | Yes | Yes | — | — | — | Yes |
| `cases:delete` | Delete incident cases | Correlation and Cases | Yes | Yes | — | — | — | Yes |
| `cases:generate_reports` | Generate incident reports | Correlation and Cases | Yes | Yes | — | Yes | — | Yes |
| `governance:read` | Read governance records | Governance | Yes | Yes | Yes | Yes | — | — |
| `governance:synchronize` | Synchronize governance risks | Governance | Yes | Yes | — | — | — | — |
| `governance:manage_risks` | Manage governance risks | Governance | Yes | Yes | — | — | — | Yes |
| `governance:manage_mappings` | Manage control mappings | Governance | Yes | Yes | — | — | — | Yes |
| `governance:manage_treatments` | Manage treatments | Governance | Yes | Yes | — | — | — | Yes |
| `governance:manage_exceptions` | Manage exceptions | Governance | Yes | Yes | — | — | — | Yes |
| `governance:manage_evidence` | Manage evidence | Governance | Yes | Yes | — | — | — | Yes |
| `governance:manage_reviews` | Manage governance reviews | Governance | Yes | Yes | — | — | — | Yes |
| `governance:generate_reports` | Generate governance reports | Governance | Yes | Yes | Yes | Yes | — | Yes |
| `users:read` | Read user accounts | Administration | Yes | — | — | — | — | — |
| `users:manage` | Manage user accounts | Administration | Yes | — | — | — | — | Yes |
| `roles:read` | Read access roles | Administration | Yes | — | — | — | — | — |
| `roles:manage` | Manage access roles | Administration | Yes | — | — | — | — | Yes |
| `sessions:manage_all` | Manage all user sessions | Administration | Yes | — | — | — | — | Yes |
| `audit:read` | Read security audit events | Administration | Yes | — | Yes | — | — | — |
| `audit:verify` | Verify audit integrity | Administration | Yes | — | Yes | — | — | — |
| `system:manage` | Manage system security settings | Administration | Yes | — | — | — | — | Yes |
| `reports:read_all` | Read reports across modules | Reports | Yes | — | Yes | — | — | — |
| `operations:view` | View platform operations | Operations | Yes | Yes | Yes | — | — | — |
| `operations:diagnostics` | View safe operational diagnostics | Operations | Yes | Yes | Yes | — | — | — |
| `operations:backup` | Manage local database backups | Operations | Yes | — | — | — | — | Yes |
| `operations:restore` | Validate and stage database restores | Operations | Yes | — | — | — | — | Yes |
| `operations:export` | Create safe local exports | Operations | Yes | Yes | — | — | — | Yes |
| `operations:import` | Validate local import packages | Operations | Yes | — | — | — | — | Yes |
| `operations:retention` | Manage retention previews and apply | Operations | Yes | — | — | — | — | — |
| `operations:maintenance` | Manage operational jobs | Operations | Yes | — | — | — | — | — |
| `operations:demo_manage` | Manage the synthetic demo environment | Operations | Yes | — | — | — | — | Yes |
| `operations:release` | Build local release candidates | Operations | Yes | — | — | — | — | — |
| `operations:inventory` | View and generate software inventory | Operations | Yes | Yes | Yes | — | — | — |
| `threat_intel:view` | View threat-intelligence data | Threat Intelligence | Yes | Yes | Yes | — | — | — |
| `threat_intel:import` | Import bounded IOC data | Threat Intelligence | Yes | Yes | — | — | — | Yes |
| `threat_intel:manage` | Manage indicators, sources, watchlists, and campaigns | Threat Intelligence | Yes | Yes | — | — | — | Yes |
| `threat_intel:correlate` | Run stored-data IOC correlation and review matches | Threat Intelligence | Yes | Yes | — | — | — | — |
| `threat_intel:export` | Generate and export threat-intelligence reports | Threat Intelligence | Yes | Yes | Yes | — | — | Yes |
| `detections:view` | View detection engineering data | Detection Engineering | Yes | Yes | Yes | — | — | — |
| `detections:manage` | Create and manage detection rules, packs, tests, and suppressions | Detection Engineering | Yes | Yes | — | — | — | Yes |
| `detections:import` | Validate and import bounded Sigma rules | Detection Engineering | Yes | Yes | — | — | — | Yes |
| `detections:execute` | Run bounded detection tests and historical executions | Detection Engineering | Yes | Yes | — | — | — | Yes |
| `detections:review` | Review detection matches and explicitly promote outcomes | Detection Engineering | Yes | Yes | — | — | — | — |
| `detections:export` | Generate and export detection engineering reports | Detection Engineering | Yes | Yes | Yes | — | — | Yes |
| `assets:view` | View unified asset inventory | Vulnerability Management | Yes | Yes | Yes | — | — | — |
| `assets:manage` | Manage unified asset inventory | Vulnerability Management | Yes | Yes | — | — | — | Yes |
| `vulnerabilities:view` | View vulnerability and remediation records | Vulnerability Management | Yes | Yes | Yes | — | — | — |
| `vulnerabilities:aggregate` | View aggregate vulnerability and SLA metrics | Vulnerability Management | Yes | — | — | Yes | — | — |
| `vulnerabilities:triage` | Triage and assign vulnerabilities | Vulnerability Management | Yes | Yes | — | — | — | — |
| `vulnerabilities:remediate` | Manage remediation plans and tasks | Vulnerability Management | Yes | Yes | — | — | — | — |
| `vulnerabilities:verify` | Perform bounded vulnerability verification | Vulnerability Management | Yes | Yes | — | — | — | — |
| `vulnerabilities:accept_risk` | Request vulnerability risk acceptance | Vulnerability Management | Yes | Yes | — | — | — | — |
| `vulnerabilities:approve_risk` | Approve vulnerability risk acceptance | Vulnerability Management | Yes | — | — | — | — | — |
| `vulnerabilities:export` | Generate vulnerability-management reports | Vulnerability Management | Yes | Yes | Yes | — | — | Yes |
| `sla:manage` | Manage vulnerability SLA policies | Vulnerability Management | Yes | — | — | — | — | Yes |
| `soar:view` | View SOAR playbooks and execution history | SOAR-Lite | Yes | Yes | Yes | — | — | — |
| `soar:manage` | Manage SOAR playbooks and trigger rules | SOAR-Lite | Yes | Yes | — | — | — | Yes |
| `soar:execute` | Execute allowlisted SOAR workflows | SOAR-Lite | Yes | Yes | — | — | — | Yes |
| `soar:approve` | Decide SOAR approvals | SOAR-Lite | Yes | — | — | — | — | — |
| `soar:review` | Submit SOAR analyst input | SOAR-Lite | Yes | Yes | — | — | — | — |
| `soar:rollback` | Approve and execute SOAR compensation | SOAR-Lite | Yes | — | — | — | — | — |
| `soar:export` | Generate and export SOAR reports | SOAR-Lite | Yes | Yes | Yes | — | — | Yes |
| `soar:sensitive_actions` | Approve sensitive local user and session actions | SOAR-Lite | Yes | — | — | — | — | — |
| `soar:action_policy_manage` | Manage server-owned SOAR action policies | SOAR-Lite | Yes | — | — | — | — | Yes |
| `integrations:view` | View connector inventory and delivery history | Security Integrations | Yes | Yes | Yes | — | — | — |
| `integrations:aggregate` | View aggregate connector health and delivery metrics | Security Integrations | Yes | — | — | Yes | — | — |
| `integrations:manage` | Manage connector configuration, mappings, and subscriptions | Security Integrations | Yes | — | — | — | — | Yes |
| `integrations:test` | Run bounded connector validation and tests | Security Integrations | Yes | Yes | — | — | — | — |
| `integrations:execute` | Queue and process bounded connector deliveries | Security Integrations | Yes | Yes | — | — | — | Yes |
| `integrations:replay` | Manually replay dead-letter deliveries | Security Integrations | Yes | — | — | — | — | — |
| `integrations:export` | Generate and export integration reports | Security Integrations | Yes | Yes | Yes | — | — | Yes |
| `integrations:credentials_manage` | Manage write-only connector credentials | Security Integrations | Yes | — | — | — | — | Yes |
| `integrations:network_policy_manage` | Manage connector egress network policies | Security Integrations | Yes | — | — | — | — | Yes |
| `integrations:inbound_promote` | Promote quarantined inbound integration events | Security Integrations | Yes | Yes | — | — | — | — |
| `analytics:view` | View entity-level analytics and explanations | Security Analytics | Yes | Yes | Yes | — | — | — |
| `analytics:aggregate` | View aggregate analytics dashboards and reports | Security Analytics | Yes | Yes | Yes | Yes | — | — |
| `analytics:manage` | Create detectors and immutable detector versions | Security Analytics | Yes | — | — | — | — | Yes |
| `analytics:train` | Build baselines, validate detectors, backtest, and evaluate drift | Security Analytics | Yes | — | — | — | — | — |
| `analytics:execute` | Execute approved analytics jobs and active detectors | Security Analytics | Yes | Yes | — | — | — | Yes |
| `analytics:review` | Review anomalies, record feedback, and link cases | Security Analytics | Yes | Yes | — | — | — | — |
| `analytics:export` | Generate and export safe analytics reports | Security Analytics | Yes | Yes | Yes | — | — | Yes |
| `analytics:policy_manage` | Manage detector activation, rollback, and suppression policy | Security Analytics | Yes | — | — | — | — | Yes |

## Review rules

Role changes require `roles:manage`; account changes require `users:manage`; production operations, connector credentials/network policy, restore, SOAR execution, analytics policy, and exports require their specific server-owned permission. Mutating authenticated requests additionally require a valid CSRF token. Default mappings are seed defaults, not a substitute for reviewing effective permissions in a deployed database.

Permission count: 124. Default role count: 5.
