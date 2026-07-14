from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .models import LoginAttempt, UserAccount
from .password_service import verify_password
from .rate_limit_service import (
    clear_failures,
    is_rate_limited,
    record_attempt,
    register_user_failure,
    unlock_if_expired,
    username_hash,
)
from .session_service import client_ip_hash, utcnow
from .user_service import normalize_username


GENERIC_LOGIN_ERROR = "Invalid username or password"


def authenticate_password(db: Session, request: Request, username: str, password: str) -> UserAccount:
    try:
        normalized = normalize_username(username)
    except ValueError:
        normalized = username.strip().casefold()[:64]
    user = db.query(UserAccount).filter_by(username_normalized=normalized).first()
    expired_lock = unlock_if_expired(db, user) if user else False
    ip_hash = client_ip_hash(request)
    if expired_lock:
        db.query(LoginAttempt).filter_by(
            username_hash=username_hash(normalized),
            success=False,
        ).delete(synchronize_session=False)
        db.commit()
    if is_rate_limited(db, normalized, ip_hash):
        raise HTTPException(status_code=429, detail="Login temporarily unavailable. Try again later.")
    valid = verify_password(user.password_hash if user else None, password)
    if not user or not valid or user.status in {"disabled", "locked"}:
        if user and user.status not in {"disabled", "locked"}:
            register_user_failure(db, user)
        record_attempt(db, normalized, ip_hash, False, "invalid_credentials")
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
    clear_failures(db, user)
    record_attempt(db, normalized, ip_hash, True, None)
    user.last_login_at = utcnow()
    user.last_login_ip_hash = ip_hash
    db.commit()
    return user
