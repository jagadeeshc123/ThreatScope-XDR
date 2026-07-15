# Local account setup

ThreatScope XDR uses local accounts only. An email address, including a Gmail address, is an identifier. Users create a separate ThreatScope password. ThreatScope does not access Gmail, request Gmail credentials, send mail, or use an external identity provider.

## Owner administrator

From `backend/`, run:

```powershell
python scripts/manage_accounts.py create-admin
```

The command prompts locally for email, username, display name, password, and confirmation using hidden password input. It works when other accounts already exist and assigns the protected Administrator role. There are no fixed credentials or automatic administrator accounts.

Safe commands include `list`, `reset-password --identifier user@example.com`, `unlock --identifier user@example.com`, `approve --identifier user@example.com`, and `revoke-sessions --identifier user@example.com`.

## Registration configuration

- `THREATSCOPE_LOCAL_LOGIN_ENABLED` enables local identifier/password login.
- `THREATSCOPE_SELF_REGISTRATION_ENABLED` controls public registration.
- `THREATSCOPE_REGISTRATION_MODE` is `disabled`, `approval_required`, or `auto_activate_limited`.
- `THREATSCOPE_PRIVACY_NOTICE_VERSION` identifies the locally accepted notice.

Development should enable local login and registration with `auto_activate_limited`. Production should use `approval_required`. Registration never accepts a role, status, administrator flag, or MFA state.

Approval-mode accounts remain pending until reviewed under Administration / Registrations. Rejected accounts may be reopened. Auto-activated accounts receive only Registered User access to the welcome dashboard, own profile, and notifications. Local email ownership remains unverified because outbound email is not implemented.
