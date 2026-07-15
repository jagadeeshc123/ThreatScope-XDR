import re
import secrets
import string
import unicodedata
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import AccessRole, UserAccount, UserRoleAssignment
from .password_service import hash_password
from .role_service import assign_roles
from .session_service import revoke_user_sessions


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_username(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value.strip()).casefold()
    if not USERNAME_RE.fullmatch(value.strip()) or len(normalized) > 64:
        raise ValueError("Username must be 3-64 characters using letters, numbers, dot, underscore, or hyphen")
    return normalized


def normalize_email(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    email = unicodedata.normalize("NFKC", value.strip()).casefold()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise ValueError("Email address is invalid")
    return email


def validate_display_name(value: str) -> str:
    result = " ".join(value.strip().split())
    if not 2 <= len(result) <= 120:
        raise ValueError("Display name must be 2-120 characters")
    return result


def create_user(
    db: Session,
    *,
    username: str,
    display_name: str,
    password: str,
    email: str | None = None,
    role_keys: list[str] | None = None,
    must_change_password: bool = True,
    is_system_admin: bool = False,
    actor_id: int | None = None,
    registration_source: str = "administrator",
    status: str | None = None,
    terms_accepted_at: datetime | None = None,
    privacy_notice_version: str | None = None,
    is_demo_account: bool = False,
) -> UserAccount:
    username_normalized = normalize_username(username)
    email_normalized = normalize_email(email)
    if db.query(UserAccount).filter_by(username_normalized=username_normalized).first():
        raise ValueError("Username is already in use")
    if email_normalized and db.query(UserAccount).filter_by(email_normalized=email_normalized).first():
        raise ValueError("Email is already in use")
    now = utcnow()
    user = UserAccount(
        username=username.strip(),
        username_normalized=username_normalized,
        display_name=validate_display_name(display_name),
        email=email.strip() if email and email.strip() else None,
        email_normalized=email_normalized,
        password_hash=hash_password(password, username_normalized),
        status=status or ("pending_password_change" if must_change_password else "active"),
        is_system_admin=is_system_admin,
        must_change_password=must_change_password,
        password_changed_at=now,
        registration_source=registration_source,
        terms_accepted_at=terms_accepted_at,
        privacy_notice_version=privacy_notice_version,
        email_verified=False,
        is_demo_account=is_demo_account,
    )
    db.add(user)
    db.flush()
    assign_roles(db, user, role_keys or (["administrator"] if is_system_admin else []), actor_id)
    db.commit()
    db.refresh(user)
    return user


def active_administrator_count(db: Session, exclude_user_id: int | None = None) -> int:
    query = db.query(UserAccount).filter(
        UserAccount.is_system_admin.is_(True),
        UserAccount.status.in_(["active", "pending_password_change"]),
    )
    if exclude_user_id is not None:
        query = query.filter(UserAccount.id != exclude_user_id)
    return query.count()


def ensure_not_last_admin(db: Session, user: UserAccount) -> None:
    if user.is_system_admin and active_administrator_count(db, user.id) == 0:
        raise ValueError("The last active system administrator cannot be disabled or demoted")


def set_password(db: Session, user: UserAccount, password: str, must_change: bool, reason: str, current_session_id: int | None = None) -> None:
    preserved_status = user.status if user.status in {"disabled", "pending_approval", "rejected"} else None
    user.password_hash = hash_password(password, user.username_normalized)
    user.password_changed_at = utcnow()
    user.must_change_password = must_change
    user.status = preserved_status or ("pending_password_change" if must_change else "active")
    db.commit()
    revoke_user_sessions(db, user.id, reason, except_session_id=current_session_id)


def generate_temporary_password(username: str) -> str:
    alphabet = string.ascii_letters + string.digits + "-_.!@#$%"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(20))
        if username.casefold() not in password.casefold():
            return password


def user_dict(db: Session, user: UserAccount, *, include_permissions: bool = False) -> dict:
    from .role_service import effective_permissions, role_keys

    data = {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "status": user.status,
        "is_system_admin": user.is_system_admin,
        "must_change_password": user.must_change_password,
        "mfa_enabled": user.mfa_enabled,
        "last_login_at": user.last_login_at,
        "password_changed_at": user.password_changed_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "registration_source": user.registration_source,
        "approved_at": user.approved_at,
        "rejected_at": user.rejected_at,
        "rejection_reason": user.rejection_reason,
        "privacy_notice_version": user.privacy_notice_version,
        "email_verified": user.email_verified,
        "onboarding_completed_at": user.onboarding_completed_at,
        "is_demo_account": user.is_demo_account,
        "roles": role_keys(db, user.id),
    }
    if include_permissions:
        data["permissions"] = sorted(effective_permissions(db, user))
    return data
