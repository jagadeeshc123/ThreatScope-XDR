# Demo guide

Use only the development profile, synthetic local data, and the bundled local test target. Never scan a public or third-party system without explicit authorization.

1. Install backend/frontend dependencies and start the development stack or run `docker compose up --build -d` with an ignored development `.env`.
2. Create a local administrator interactively. No demo user or password is built in. Sign in and optionally enroll MFA.
3. Set `THREATSCOPE_DEMO_MODE=true` only in development, restart, then open Operations → Demo Environment. Seed is explicit/idempotent; reset/reseed requires confirmation and selects only deterministic synthetic-demo records.
4. Review Dashboard, register/use the bundled authorized local target, run a safe scan, inspect findings, and generate a static report.
5. Walk through API inventory/authorization review, synthetic SOC events, inert document/phishing fixtures, correlation/case creation, governance evidence, local IOC/detection/vulnerability records, and notifications/search.
6. In SOAR-Lite use dry-run or simulation and say “simulated action,” never “contained.” In Integration Hub use disabled/test fixtures; configured/queued is not delivered. In Analytics explain that deviations are deterministic review signals, not compromise or external AI.
7. Export/share only synthetic reports. Stop the stack and use the explicit demo reset to remove tagged demo rows. Remove generated runtime artifacts with the documented cleanup; do not delete normal user data or volumes.

The demo does not weaken authentication, CSRF, MFA, RBAC, SSRF, connector policy, or production defaults. Production disables demo seeding by default.
