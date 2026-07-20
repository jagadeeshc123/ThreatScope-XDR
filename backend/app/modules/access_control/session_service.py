import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy.orm import Session

from .config import get_config
from .models import AuthSession, UserAccount


COOKIE_NAME = "threatscope_session"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_value(value: str) -> str:
    pepper = get_config().session_secret.encode("utf-8")
    return hashlib.sha256(pepper + value.encode("utf-8")).hexdigest()


def summarize_user_agent(value: str | None) -> str | None:
    if not value:
        return None
    return " ".join(value.split())[:200]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def client_ip_hash(request: Request) -> str | None:
    value = client_ip(request)
    return hash_value(f"ip:{value}") if value else None


def create_session(db: Session, user: UserAccount, request: Request, *, mfa_verified: bool = False) -> tuple[AuthSession, str, str]:
    config = get_config()
    now = utcnow()
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    auth_session = AuthSession(
        user_id=user.id,
        token_hash=hash_value(token),
        csrf_token_hash=hash_value(csrf),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=config.session_hours),
        idle_expires_at=now + timedelta(minutes=config.idle_minutes),
        user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
        client_ip_hash=client_ip_hash(request),
        mfa_verified=mfa_verified,
    )
    db.add(auth_session)
    db.flush()
    return auth_session, token, csrf


def set_session_cookie(response: Response, token: str) -> None:
    config = get_config()
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=config.session_hours * 3600,
        httponly=True,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    config = get_config()
    response.delete_cookie(COOKIE_NAME, path="/", secure=config.cookie_secure, httponly=True, samesite=config.cookie_samesite)


def lookup_session(db: Session, request: Request, *, refresh: bool = True) -> AuthSession | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    auth_session = db.query(AuthSession).filter_by(token_hash=hash_value(token)).first()
    if not auth_session or auth_session.revoked_at:
        return None
    now = utcnow()
    if auth_session.expires_at <= now or auth_session.idle_expires_at <= now:
        auth_session.revoked_at = now
        auth_session.revoke_reason = "expired"
        db.commit()
        return None
    if not auth_session.user or auth_session.user.status in {"disabled", "locked"}:
        return None
    if refresh and (now - auth_session.last_seen_at).total_seconds() >= 60:
        auth_session.last_seen_at = now
        auth_session.idle_expires_at = min(
            auth_session.expires_at,
            now + timedelta(minutes=get_config().idle_minutes),
        )
        db.commit()
    return auth_session


def rotate_csrf(db: Session, auth_session: AuthSession) -> str:
    token = secrets.token_urlsafe(32)
    auth_session.csrf_token_hash = hash_value(token)
    auth_session.session_version += 1
    db.commit()
    return token


def revoke_session(db: Session, auth_session: AuthSession, reason: str) -> None:
    if not auth_session.revoked_at:
        auth_session.revoked_at = utcnow()
        auth_session.revoke_reason = reason[:120]
        db.commit()


def revoke_user_sessions(db: Session, user_id: int, reason: str, except_session_id: int | None = None) -> int:
    query = db.query(AuthSession).filter(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    if except_session_id is not None:
        query = query.filter(AuthSession.id != except_session_id)
    now = utcnow()
    count = query.update({AuthSession.revoked_at: now, AuthSession.revoke_reason: reason[:120]}, synchronize_session=False)
    db.commit()
    return count
