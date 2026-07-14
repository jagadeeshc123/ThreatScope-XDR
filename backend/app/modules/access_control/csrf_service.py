import hmac

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .models import AuthSession
from .session_service import hash_value


def validate_csrf(request: Request, auth_session: AuthSession) -> None:
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied or not hmac.compare_digest(hash_value(supplied), auth_session.csrf_token_hash):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def require_csrf(request: Request, db: Session, auth_session: AuthSession) -> None:
    del db
    validate_csrf(request, auth_session)

