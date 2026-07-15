import re
import secrets
from datetime import datetime

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app import models

from .config import get_config
from .models import AccessRole, UserAccount
from .password_service import PasswordPolicyError, hash_password
from .rate_limit_service import clear_user_login_attempts, is_registration_rate_limited, record_registration_attempt
from .role_service import assign_roles, role_keys
from .session_service import client_ip_hash, revoke_user_sessions, utcnow
from .user_service import ensure_not_last_admin, normalize_email, normalize_username, user_dict, validate_display_name


REGISTRATION_STATUSES = {"pending_approval", "active", "rejected", "disabled", "locked", "pending_password_change"}
REGISTRATION_SOURCES = {"local", "administrator", "bootstrap", "demo"}


def mask_email(email: str) -> str:
    local, domain = email.split("@", 1)
    visible = local[:1]
    return f"{visible}{'*' * min(max(len(local) - 1, 2), 8)}@{domain}"


def generated_username(db: Session, email_normalized: str) -> str:
    local = email_normalized.split("@", 1)[0]
    base = re.sub(r"[^a-z0-9._-]+", ".", local.casefold()).strip("._-")[:44]
    if len(base) < 3:
        base = "user"
    for _ in range(20):
        candidate = f"{base}.{secrets.token_hex(4)}"[:64]
        if not db.query(UserAccount).filter_by(username_normalized=candidate).first():
            return candidate
    raise ValueError("A safe username could not be generated")


def _activity(db: Session, action: str, message: str, user_id: int) -> None:
    db.add(models.SocActivity(action=action, message=message[:500], entity_type="account_registration", entity_id=user_id))


def _notify(db: Session, title: str, message: str, user_id: int, *, recipient_user_id: int | None, admin_only: bool = False) -> None:
    entity_type = "user" if admin_only else "account_status"
    duplicate = db.query(models.Notification).filter_by(
        title=title,
        entity_type=entity_type,
        entity_id=user_id,
        recipient_user_id=recipient_user_id,
    ).first()
    if not duplicate:
        db.add(models.Notification(
            title=title,
            message=message[:500],
            type="info",
            entity_type=entity_type,
            entity_id=user_id,
            recipient_user_id=recipient_user_id,
        ))


def register_local_account(db: Session, request: Request, payload) -> tuple[UserAccount, dict]:
    config = get_config()
    if not config.local_login_enabled or not config.self_registration_enabled or config.registration_mode == "disabled":
        raise HTTPException(status_code=403, detail="Local account registration is unavailable")
    ip_hash = client_ip_hash(request)
    try:
        email_normalized = normalize_email(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not email_normalized:
        raise HTTPException(status_code=422, detail="Email address is required")
    if is_registration_rate_limited(db, email_normalized, ip_hash):
        raise HTTPException(status_code=429, detail="Registration temporarily unavailable. Try again later.")
    try:
        if not payload.terms_accepted:
            raise ValueError("Terms and privacy acknowledgement is required")
        if payload.privacy_notice_version != config.privacy_notice_version:
            raise ValueError("The current privacy notice must be accepted")
        if payload.password != payload.password_confirmation:
            raise ValueError("Password confirmation does not match")
        username = payload.username.strip() if payload.username else generated_username(db, email_normalized)
        username_normalized = normalize_username(username)
        display_name = validate_display_name(payload.display_name)
        if db.query(UserAccount).filter_by(email_normalized=email_normalized).first() or db.query(UserAccount).filter_by(username_normalized=username_normalized).first():
            raise ValueError("Account registration could not be completed")
        local_part = email_normalized.split("@", 1)[0]
        digest = hash_password(payload.password, username_normalized, (local_part,))
        status = "pending_approval" if config.registration_mode == "approval_required" else "active"
        now = utcnow()
        user = UserAccount(
            username=username,
            username_normalized=username_normalized,
            display_name=display_name,
            email=payload.email.strip(),
            email_normalized=email_normalized,
            password_hash=digest,
            status=status,
            is_system_admin=False,
            must_change_password=False,
            password_changed_at=now,
            registration_source="local",
            terms_accepted_at=now,
            privacy_notice_version=config.privacy_notice_version,
            email_verified=False,
            is_demo_account=False,
            approved_at=now if status == "active" else None,
        )
        db.add(user)
        db.flush()
        assign_roles(db, user, ["registered_user"])
        db.commit()
        db.refresh(user)
        # A visitor may have attempted this identifier before registering it.
        # Successful registration establishes new credentials, so those stale
        # unknown-account failures must not block the newly created account.
        clear_user_login_attempts(db, user)
        db.commit()
    except (ValueError, PasswordPolicyError) as exc:
        db.rollback()
        record_registration_attempt(db, email_normalized, ip_hash, False, "validation")
        message = str(exc)
        if "already" in message.lower() or "could not be completed" in message.lower():
            message = "Account registration could not be completed"
        raise HTTPException(status_code=422, detail=message) from exc
    record_registration_attempt(db, email_normalized, ip_hash, True, None)
    _activity(db, "account_registered", f"Local account {user.username} registered with status {user.status}.", user.id)
    if status == "pending_approval":
        _notify(db, "Registration Submitted", f"Registration for {user.username} requires administrator review.", user.id, recipient_user_id=None, admin_only=True)
    else:
        _notify(db, "Registration Activated", "Your limited local ThreatScope account is ready.", user.id, recipient_user_id=user.id)
    db.commit()
    return user, {
        "registration_status": user.status,
        "username": user.username,
        "display_name": user.display_name,
        "email": mask_email(user.email),
        "email_verified": False,
        "approval_required": user.status == "pending_approval",
        "next_route": "/account-pending",
    }


def registration_dict(db: Session, user: UserAccount) -> dict:
    data = user_dict(db, user)
    data.pop("rejection_reason", None)
    data.update({
        "safe_email": mask_email(user.email) if user.email else None,
        "approved_by_user_id": user.approved_by_user_id,
        "rejected_by_user_id": user.rejected_by_user_id,
        "terms_accepted_at": user.terms_accepted_at,
    })
    return data


def approve_registration(db: Session, user: UserAccount, actor: UserAccount, keys: list[str], confirm_administrator: bool) -> UserAccount:
    if user.status not in {"pending_approval", "rejected"}:
        raise ValueError("Only pending or reopened registrations can be approved")
    unique = list(dict.fromkeys(keys or ["registered_user"]))
    if "administrator" in unique and not confirm_administrator:
        raise ValueError("Administrator assignment requires explicit confirmation")
    roles = db.query(AccessRole).filter(AccessRole.role_key.in_(unique)).all()
    if len(roles) != len(unique) or any(not role.enabled for role in roles):
        raise ValueError("One or more roles are invalid or disabled")
    assign_roles(db, user, unique, actor.id)
    user.status = "active"
    user.is_system_admin = "administrator" in unique
    user.approved_at = utcnow()
    user.approved_by_user_id = actor.id
    db.commit()
    _activity(db, "account_approved", f"Registration {user.username} approved.", user.id)
    _notify(db, "Registration Approved", "Your local ThreatScope account was approved.", user.id, recipient_user_id=user.id)
    db.commit()
    return user


def reject_registration(db: Session, user: UserAccount, actor: UserAccount, reason: str) -> UserAccount:
    bounded = " ".join(reason.strip().split())
    if not 3 <= len(bounded) <= 500:
        raise ValueError("A bounded rejection reason is required")
    if user.status not in {"pending_approval", "active"}:
        raise ValueError("Registration cannot be rejected from its current status")
    ensure_not_last_admin(db, user)
    user.status = "rejected"
    user.rejected_at = utcnow()
    user.rejected_by_user_id = actor.id
    user.rejection_reason = bounded
    db.commit()
    revoke_user_sessions(db, user.id, "registration_rejected")
    _activity(db, "account_rejected", f"Registration {user.username} rejected.", user.id)
    _notify(db, "Registration Rejected", "Your local account registration was not approved. Contact an administrator.", user.id, recipient_user_id=user.id)
    db.commit()
    return user


def reopen_registration(db: Session, user: UserAccount, actor: UserAccount) -> UserAccount:
    if user.status != "rejected":
        raise ValueError("Only rejected registrations can be reopened")
    user.status = "pending_approval"
    db.commit()
    _activity(db, "account_reopened", f"Registration {user.username} reopened for review.", user.id)
    _notify(db, "Registration Reopened", f"Registration {user.username} returned to the approval queue.", user.id, recipient_user_id=None, admin_only=True)
    db.commit()
    return user
