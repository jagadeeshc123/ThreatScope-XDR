from datetime import timedelta

from sqlalchemy.orm import Session

from .config import get_config
from .models import LoginAttempt, UserAccount
from .session_service import hash_value, utcnow


class ManagementRateLimitError(ValueError):
    pass


def username_hash(username_normalized: str) -> str:
    return hash_value(f"username:{username_normalized}")


def registration_hash(email_normalized: str) -> str:
    return hash_value(f"registration:{email_normalized}")


def management_hash(actor_user_id: int, action: str) -> str:
    return hash_value(f"registration-management:{actor_user_id}:{action}")


def is_registration_rate_limited(db: Session, normalized: str, ip_hash: str | None) -> bool:
    since = utcnow() - timedelta(minutes=15)
    query = db.query(LoginAttempt).filter(
        LoginAttempt.username_hash == registration_hash(normalized),
        LoginAttempt.success.is_(False),
        LoginAttempt.attempted_at >= since,
    )
    if ip_hash:
        query = query.filter(LoginAttempt.client_ip_hash == ip_hash)
    return query.count() >= 5


def record_registration_attempt(db: Session, normalized: str, ip_hash: str | None, success: bool, reason: str | None) -> None:
    db.add(LoginAttempt(
        username_hash=registration_hash(normalized),
        client_ip_hash=ip_hash,
        success=success,
        failure_reason_code=None if success else f"registration_{reason or 'rejected'}"[:64],
    ))
    db.commit()


def record_management_attempt(db: Session, actor_user_id: int, action: str, ip_hash: str | None) -> None:
    """Count bounded approval mutations without retaining a raw actor/action identifier."""
    since = utcnow() - timedelta(minutes=5)
    identity_hash = management_hash(actor_user_id, action)
    attempts = db.query(LoginAttempt).filter(
        LoginAttempt.username_hash == identity_hash,
        LoginAttempt.client_ip_hash == ip_hash,
        LoginAttempt.attempted_at >= since,
    ).count()
    if attempts >= 20:
        raise ManagementRateLimitError("Registration management is temporarily rate limited")
    db.add(LoginAttempt(
        username_hash=identity_hash,
        client_ip_hash=ip_hash,
        success=True,
        failure_reason_code=None,
    ))
    db.commit()


def is_rate_limited(db: Session, normalized: str, ip_hash: str | None) -> bool:
    config = get_config()
    since = utcnow() - timedelta(minutes=15)
    query = db.query(LoginAttempt).filter(
        LoginAttempt.username_hash == username_hash(normalized),
        LoginAttempt.success.is_(False),
        LoginAttempt.attempted_at >= since,
    )
    if ip_hash:
        query = query.filter(LoginAttempt.client_ip_hash == ip_hash)
    return query.count() >= config.login_max_attempts


def record_attempt(db: Session, normalized: str, ip_hash: str | None, success: bool, reason: str | None) -> None:
    if success:
        db.query(LoginAttempt).filter(
            LoginAttempt.username_hash == username_hash(normalized),
            LoginAttempt.success.is_(False),
        ).delete(synchronize_session=False)
    db.add(LoginAttempt(
        username_hash=username_hash(normalized),
        client_ip_hash=ip_hash,
        success=success,
        failure_reason_code=None if success else (reason or "invalid_credentials")[:64],
    ))
    cutoff = utcnow() - timedelta(days=30)
    db.query(LoginAttempt).filter(LoginAttempt.attempted_at < cutoff).delete(synchronize_session=False)
    db.commit()


def register_user_failure(db: Session, user: UserAccount) -> None:
    config = get_config()
    user.failed_login_count += 1
    if user.failed_login_count >= config.login_max_attempts:
        user.status = "locked"
        user.locked_until = utcnow() + timedelta(minutes=config.lockout_minutes)
    db.commit()


def clear_failures(db: Session, user: UserAccount) -> None:
    user.failed_login_count = 0
    user.locked_until = None
    if user.status == "locked":
        user.status = "active"
    db.commit()


def unlock_if_expired(db: Session, user: UserAccount) -> bool:
    if user.status == "locked" and user.locked_until and user.locked_until <= utcnow():
        clear_failures(db, user)
        return True
    return False
