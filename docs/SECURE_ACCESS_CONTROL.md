# ThreatScope XDR local access control

ThreatScope XDR has no default account or default password. Permissions and the four protected system-role definitions are seeded automatically, but a human account is never created during ordinary startup.

## First administrator

From the repository root, install backend dependencies and run the local interactive bootstrap:

```powershell
cd backend
python -m pip install -r requirements.txt
python scripts/create_admin.py
```

The script uses hidden password entry, enforces the local password policy, refuses to run after any user exists, and never prints the password.

For an explicitly requested one-time Docker bootstrap, supply all three `THREATSCOPE_BOOTSTRAP_ADMIN_*` variables only in your uncommitted local environment. Bootstrap runs only when the user table is empty. Remove the variables immediately afterward. Partial bootstrap configuration fails without printing supplied values.

## Local environment

Copy `.env.example` to `.env`, generate private values locally, and keep `.env` untracked. A session-secret value of at least 32 characters is mandatory in production mode. MFA enrollment is unavailable until `THREATSCOPE_MFA_ENCRYPTION_KEY` contains a valid Fernet key. Production additionally requires explicit CORS origins and secure cookies.

Browser authentication uses an opaque random cookie called `threatscope_session`. Only its SHA-256 digest (optionally peppered by the session secret) is stored. The browser cookie is HttpOnly, SameSite=Lax, path-scoped to `/`, and Secure in production. Mutation requests also require the session's in-memory CSRF token in `X-CSRF-Token`.

## Roles and accountability

Administrator, Security Analyst, Auditor, and Executive Viewer are deterministic protected roles. Custom-role permission changes and user-role assignments revoke affected sessions so stale permissions cannot survive. The last active system administrator cannot be disabled or demoted.

Security audit hash chaining provides local tamper evidence. It does not provide external notarization or prevent a privileged database administrator from rewriting the complete chain.

## Recovery boundaries

There is no email/SMS password reset and no external identity provider. An authorized local administrator may issue a temporary password that is returned once and forces a change at next login. TOTP recovery codes are returned once, stored only as hashes, and become unusable after one successful use.
