# OWASP API Migration Plan

## Current OWASP architecture

The OWASP reference is an API security lab, not a drop-in ThreatScope module.
The active backend is a Node.js/Express API in `app.js`, `server.js`, and
`routes/`, with Helmet, rate limiting, Supabase authentication middleware, and a
separate `worker.js` passive-scan worker. The frontend is a Next.js 16
application in `frontend/` using React 19, TypeScript, Tailwind CSS, and
Supabase client helpers. The authoritative database model is Supabase/PostgreSQL
under `supabase/migrations/`, with row-level security, organizations, projects,
assets, assessments, findings, API specs, API endpoints, authorization tests,
business-flow reviews, reports, scan jobs, audit events, and evidence tables.

The repository also contains legacy Mongoose models and some older routes. The
project's own overview says these are migration source material and should not
be treated as active product APIs.

Important backend routes and libraries:

- `routes/assets.js`, `routes/assessments.js`, `routes/analyze.js`: active
  Express API boundary around asset registration, assessment scheduling, and
  analysis.
- `routes/inventory.js`: Supabase-backed endpoint inventory gap analysis.
- `routes/authz.js`: guided authorization matrix records.
- `routes/businessFlows.js`: guided business-flow review records.
- `routes/evidence.js`, `routes/reports.js`, `lib/evidence.js`,
  `lib/reportQuality.js`: evidence and reporting concepts.
- `routes/openapi.js`: legacy Mongoose OpenAPI JSON import route; useful as a
  concept only.
- `frontend/src/lib/tooling.ts`: client-side OpenAPI JSON parsing, local `$ref`
  handling, endpoint extraction, and review-candidate detection.
- `frontend/src/lib/postman.ts`: passive Postman collection review logic.
- `lib/scanner/analyzers/jwtAnalyzer.js`, `endpointRiskClassifier.js`,
  `openApiSecurityLinter.js`, `postmanCollectionAnalyzer.js`: analyzers with
  useful rule ideas, but several belong to later phases.

Implemented frontend pages include workspace/project pages, OpenAPI import,
inventory gap analysis, authorization matrix, business flows, token analyzer,
reports, evidence builder, integrations, retest, third-party risk, methodology,
templates, and demo walkthroughs. Some are connected to Supabase and Express;
some are guided/manual workflows; some are demo or migration-era surfaces.

## Feature classification

| OWASP feature | Classification | Notes |
| --- | --- | --- |
| Assessment record concept | migrate conceptually | Recreated as `ApiAssessment` in FastAPI/SQLAlchemy. |
| API spec and endpoint inventory tables | redesign for FastAPI | Recreated as local SQLite-backed SQLAlchemy models. |
| OpenAPI endpoint extraction | migrate conceptually | Implemented server-side, OpenAPI 3.x JSON/YAML, no remote `$ref`. |
| Postman collection parsing | migrate conceptually | Implemented server-side, recursive v2.1 parsing, redaction. |
| Inventory gap page | redesign for FastAPI | Implemented as endpoint inventory with filters/sorting. |
| Supabase auth/RLS/org/project model | postpone to later phase | ThreatScope currently uses local single-workspace SQLite. |
| Notifications | replace with existing ThreatScope shared component | Uses existing `Notification` model and UI updates. |
| Global search | replace with existing ThreatScope shared component | API assessments and endpoints are added to current search. |
| Reports/evidence styling | replace with existing ThreatScope conventions | No new API reports in this phase. |
| OpenAPI linter findings and OWASP mapping | postpone to later phase | Phase 2 only classifies preliminary metadata risk. |
| JWT token analyzer | postpone to later phase | Explicitly excluded from this phase. |
| Authorization matrix / BOLA / BFLA | postpone to later phase | No active or guided authorization validation added. |
| Business-flow review | postpone to later phase | No API6 workflow added. |
| Passive scanner worker and HTTP checks | exclude because it duplicates Web Exposure | ThreatScope already has safe web exposure scanning. |
| Active request execution and SSRF protection | exclude because unsafe or unnecessary | This phase does not contact imported URLs. |
| Legacy Mongoose models/routes | exclude because migration-only | Reference project marks them non-authoritative. |
| Demo walkthrough/templates/methodology pages | exclude because unnecessary | Not needed for the ThreatScope foundation module. |

## Migration mapping

ThreatScope uses React + Vite + TypeScript, FastAPI, SQLAlchemy, and SQLite
locally. The migration maps OWASP ideas into this stack instead of merging
OWASP code.

- OWASP `assessments` becomes `ApiAssessment`.
- OWASP `api_specs` becomes `ApiImportArtifact`, storing only redacted uploaded
  content plus parsed summaries.
- OWASP `api_endpoints` becomes `ApiEndpoint`, with normalized metadata,
  authentication declaration, tags, content types, parameters, folder path,
  deprecation state, and preliminary passive risk.
- OWASP OpenAPI import concepts become `parsers/openapi_parser.py`.
- OWASP Postman concepts become `parsers/postman_parser.py`.
- OWASP review candidates become passive `preliminary_risk_level` and
  `preliminary_risk_reasons`, not confirmed findings.
- OWASP dashboard/search/report/evidence UI concepts are integrated through
  existing ThreatScope dashboard, search, notification, and layout systems.

This phase intentionally stops after local import, redaction, endpoint
inventory, and passive metadata classification. JWT analysis, active API
scanning, authorization testing, BOLA/BFLA validation, fuzzing, business-flow
testing, and full OWASP API Top 10 coverage remain future work.
