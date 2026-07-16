# Installation

Prerequisites are Git, Python 3.11, Node 20, and optionally Docker Compose. Clone the repository, copy `.env.example` to an untracked `.env`, and generate the session and Fernet keys locally using the commands documented in that example. Never commit `.env`.

For the backend, create a virtual environment, install `backend/requirements.txt`, enter `backend`, and run `python scripts/create_admin.py` with explicit administrator inputs or the documented one-time environment bootstrap. Start with `uvicorn app.main:app --reload`. Authentication, CSRF, RBAC, and secure cookies remain enabled.

For the frontend, run `npm ci` and `npm run dev` in `frontend`. For Docker, supply secrets externally and run `docker compose up --build -d`; persistent operational artifacts live under the host `runtime` mount. Production mode requires a strong session secret, explicit origins, secure cookies, a valid MFA key when MFA is used, and encrypted backups.

The preferred owner command is `python scripts/manage_accounts.py create-admin`; it can add an owner when other local or smoke-test accounts exist. Recommended development configuration enables local login and registration with `THREATSCOPE_REGISTRATION_MODE=auto_activate_limited`. Production should use `approval_required`. Compose contains empty registration substitutions and no credentials.
# Threat-intelligence schema

Phase 13 uses the existing database and requires no feed key, external service, Redis, worker, or new package. On startup, SQLAlchemy creates the threat-intelligence tables and role seeding adds the Phase 13 permissions. Existing SQLite installations should be backed up before first Phase 13 startup. Phase 13 introduced backup/restore schema identifier `threatscope-schema-v13`; Phase 14 advances it as described below.

# Detection-engineering schema

Phase 14 uses the existing SQLite database and already-pinned PyYAML dependency. Startup idempotently creates detection tables, seeds six `detections:*` permissions, 27 local educational ATT&CK-style techniques, and four protected demonstration packs. Back up existing installations before first startup. The backup/restore schema identifier is `threatscope-schema-v14`; no Redis, worker, external rule repository, or feed credential is required.
