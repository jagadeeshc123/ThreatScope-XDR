# API reference

Development can expose FastAPI OpenAPI at `/docs`, `/redoc`, and `/openapi.json`. Production disables those routes by default, so this file is the maintainable route-group index rather than a hand-copied schema.

| Prefix | Capability |
| --- | --- |
| `/api/auth`, `/api/admin`, `/api/security-audit` | Login/registration policy, MFA, sessions, users/roles, audit integrity |
| `/api/dashboard`, `/api/search`, `/api/notifications`, `/api/profile`, `/api/settings` | Shared user services |
| `/api/targets`, `/api/scans`, `/api/reports`, `/api/policies` | Web Exposure |
| `/api/api-security` | API inventory, assessment, authorization/business-flow review, reports |
| `/api/soc`, `/api/document-threats`, `/api/phishing-defense` | SOC and static content analysis |
| `/api/correlation`, `/api/governance` | Correlation/cases and governance |
| `/api/threat-intel`, `/api/detections`, `/api/vulnerability-management` | Intelligence, detection, vulnerability workflows |
| `/api/soar`, `/api/integrations`, `/api/analytics` | SOAR-Lite, connectors, analytics |
| `/api/health`, `/api/operations`, `/api/operations/production` | Public minimal health plus protected operations/readiness |

Authentication uses an HttpOnly session cookie. Retrieve the current CSRF token from `/api/auth/csrf` after authentication and send it in `X-CSRF-Token` for authenticated POST/PUT/PATCH/DELETE requests. Pre-authentication login/registration/MFA challenge and the signed inbound integration endpoint follow their dedicated anti-abuse/signature controls. Production cookies are Secure and SameSite according to validated runtime policy.

List endpoints use endpoint-specific `page`/`page_size`, `skip`/`limit`, time windows, or fixed server limits. Excessive values return 422 rather than loading an unbounded data set. Common responses are 401 unauthenticated, 403 permission/CSRF denial, 404 absent or intentionally undisclosed object, 409 lifecycle/optimistic-lock conflict, 413 upload too large, 422 invalid input, 429 rate limited, and safe 500 responses. JSON errors include a bounded request ID where available; stack traces are not returned in production.

The server-owned permission map is authoritative. Rate limits are applied to security-sensitive endpoints such as login according to configuration. Request IDs may be supplied in `X-Request-ID` only within the accepted format and are returned for correlation. Consult generated OpenAPI in an authorized development environment for exact schemas; do not expose production internals merely to publish documentation.
