# Demo guide

Set `THREATSCOPE_DEMO_MODE=true`, restart, authenticate as an administrator, and open Operations → Demo Environment. Seed is explicit and idempotent; reset and reseed require confirmation. The scenario uses RFC documentation addressing, `example.test` naming, inert summaries, and synthetic identities. It does not contact public targets or weaken authentication, CSRF, MFA, or RBAC.

Reset selects only records bearing the deterministic demo name and `synthetic-demo` environment, so analyst-created data remains. No users are created automatically and no password is hardcoded. If future demo users are explicitly requested, their passwords must be entered or generated once and shown only once.
