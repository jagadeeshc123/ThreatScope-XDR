"""Local-only account lifecycle administration without fixed credentials."""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import models  # noqa: E402,F401
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.modules.access_control.account_service import mask_email  # noqa: E402
from app.modules.access_control.audit_service import append_event  # noqa: E402
from app.modules.access_control.migration import ensure_local_account_schema  # noqa: E402
from app.modules.access_control.models import AccessRole, UserAccount  # noqa: E402
from app.modules.access_control.password_service import PasswordPolicyError  # noqa: E402
from app.modules.access_control.role_service import assign_roles, role_keys, seed_roles_and_permissions  # noqa: E402
from app.modules.access_control.session_service import revoke_user_sessions, utcnow  # noqa: E402
from app.modules.access_control.user_service import create_user, ensure_not_last_admin, normalize_email, normalize_username, set_password  # noqa: E402


def _user(db, identifier: str) -> UserAccount:
    value = identifier.strip()
    normalized = normalize_email(value) if "@" in value else normalize_username(value)
    item = db.query(UserAccount).filter_by(**({"email_normalized": normalized} if "@" in value else {"username_normalized": normalized})).first()
    if not item:
        raise ValueError("Account was not found")
    return item


def _password(username: str) -> str:
    first = getpass.getpass("ThreatScope password: ")
    second = getpass.getpass("Confirm ThreatScope password: ")
    if first != second:
        raise ValueError("Password confirmation does not match")
    return first


def _audit(db, event_type: str, action: str, user: UserAccount, metadata=None) -> None:
    append_event(db, event_type=event_type, action=action, request_id=f"local-cli-{action}"[:64], outcome="success", actor=user, resource_type="user", resource_id=user.id, route_template="scripts/manage_accounts.py", request_method="CLI", metadata=metadata or {})


def create_account(db, *, administrator: bool) -> UserAccount:
    email = input("Email: ").strip()
    username = input("Username: ").strip()
    display_name = input("Display name: ").strip()
    password = _password(username)
    role = "administrator" if administrator else "registered_user"
    user = create_user(db, username=username, email=email, display_name=display_name, password=password, role_keys=[role], must_change_password=False, is_system_admin=administrator, registration_source="administrator")
    user.approved_at = utcnow()
    db.add(models.SocActivity(action="owner_administrator_created" if administrator else "account_created", message=f"Local CLI created account {user.username}.", entity_type="account_registration", entity_id=user.id))
    db.commit()
    _audit(db, "owner_administrator_created" if administrator else "user_created", "create_admin" if administrator else "create_user", user)
    return user


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage local ThreatScope accounts safely.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    sub.add_parser("create-admin")
    sub.add_parser("create-user")
    for name in ("reset-password", "unlock", "enable", "disable", "approve", "reject", "reopen", "assign-role", "revoke-sessions"):
        item = sub.add_parser(name)
        item.add_argument("--identifier", required=True)
        if name == "reset-password": item.add_argument("--no-force-change", action="store_true")
        if name == "assign-role": item.add_argument("--role", required=True)
        if name == "reject": item.add_argument("--reason")
    return parser


def run(args) -> None:
    Base.metadata.create_all(bind=engine)
    ensure_local_account_schema(engine)
    with SessionLocal() as db:
        seed_roles_and_permissions(db)
        if args.command == "list":
            print("ID\tUSERNAME\tSAFE EMAIL\tSTATUS\tROLES\tDEMO")
            for user in db.query(UserAccount).order_by(UserAccount.id):
                print(f"{user.id}\t{user.username}\t{mask_email(user.email) if user.email else '-'}\t{user.status}\t{','.join(role_keys(db, user.id)) or '-'}\t{'yes' if user.is_demo_account else 'no'}")
            return
        if args.command in {"create-admin", "create-user"}:
            user = create_account(db, administrator=args.command == "create-admin")
            print(f"Account created safely: ID {user.id}, username {user.username}.")
            return
        user = _user(db, args.identifier)
        if args.command == "reset-password":
            password = _password(user.username)
            set_password(db, user, password, not args.no_force_change, "local_cli_password_reset")
            user.failed_login_count = 0; user.locked_until = None; db.commit(); _audit(db, "password_reset", "reset_password", user)
        elif args.command == "unlock":
            if user.status != "locked": raise ValueError("Only a locked account can be unlocked")
            user.failed_login_count = 0; user.locked_until = None; user.status = "active"; db.commit(); _audit(db, "account_unlocked", "unlock", user)
        elif args.command == "enable":
            if user.status != "disabled": raise ValueError("Only a disabled account can be enabled")
            user.status = "pending_password_change" if user.must_change_password else "active"; user.disabled_at = None; db.commit(); _audit(db, "user_enabled", "enable", user)
        elif args.command == "disable":
            ensure_not_last_admin(db, user); user.status = "disabled"; user.disabled_at = utcnow(); db.commit(); revoke_user_sessions(db, user.id, "local_cli_disabled"); _audit(db, "user_disabled", "disable", user)
        elif args.command == "approve":
            if user.status not in {"pending_approval", "rejected"}: raise ValueError("Only a pending or rejected account can be approved")
            assign_roles(db, user, ["registered_user"]); user.status = "active"; user.approved_at = utcnow(); db.commit(); _audit(db, "account_approved", "approve", user)
        elif args.command == "reject":
            reason = (args.reason or input("Rejection reason: ")).strip()
            if not 3 <= len(reason) <= 500: raise ValueError("A bounded rejection reason is required")
            if user.status not in {"pending_approval", "active"}: raise ValueError("Account cannot be rejected from its current status")
            ensure_not_last_admin(db, user)
            user.status = "rejected"; user.rejection_reason = reason; user.rejected_at = utcnow(); db.commit(); revoke_user_sessions(db, user.id, "local_cli_rejected"); _audit(db, "account_rejected", "reject", user)
        elif args.command == "reopen":
            if user.status != "rejected": raise ValueError("Only a rejected account can be reopened")
            user.status = "pending_approval"; db.commit(); _audit(db, "account_reopened", "reopen", user)
        elif args.command == "assign-role":
            role = db.query(AccessRole).filter_by(role_key=args.role, enabled=True).first()
            if not role: raise ValueError("Role is invalid or disabled")
            keys = sorted(set(role_keys(db, user.id) + [role.role_key])); assign_roles(db, user, keys); user.is_system_admin = "administrator" in keys; db.commit(); revoke_user_sessions(db, user.id, "local_cli_role_assignment"); _audit(db, "role_assigned", "assign_role", user, {"role_key": role.role_key})
        elif args.command == "revoke-sessions":
            count = revoke_user_sessions(db, user.id, "local_cli_revoked"); _audit(db, "session_revocation", "revoke_sessions", user, {"sessions_revoked": count})
        print(f"Account command completed safely for {user.username}.")


def main(argv=None) -> int:
    try:
        run(build_parser().parse_args(argv))
        return 0
    except (ValueError, PasswordPolicyError) as exc:
        print(f"Account command failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("Account command failed safely. Review local configuration and database access.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
