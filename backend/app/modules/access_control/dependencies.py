from collections.abc import Generator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db

from .audit_service import append_event
from .authorization import required_permissions
from .csrf_service import validate_csrf
from .models import AuthSession, UserAccount
from .role_service import effective_permissions
from .session_service import client_ip_hash, lookup_session, summarize_user_agent


def get_current_session(request: Request, db: Session = Depends(get_db)) -> AuthSession:
    auth_session = lookup_session(db, request)
    if not auth_session:
        raise HTTPException(status_code=401, detail="Authentication required")
    request.state.auth_session = auth_session
    request.state.current_user = auth_session.user
    return auth_session


def get_current_user(auth_session: AuthSession = Depends(get_current_session)) -> UserAccount:
    return auth_session.user


def require_authenticated_user(user: UserAccount = Depends(get_current_user)) -> UserAccount:
    return user


def require_permission(permission: str):
    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        user: UserAccount = Depends(get_current_user),
    ) -> UserAccount:
        if user.must_change_password:
            raise HTTPException(status_code=403, detail="Password change required")
        if permission not in effective_permissions(db, user):
            append_event(
                db,
                event_type="authorization_denied",
                action="permission_check",
                request_id=getattr(request.state, "request_id", "unknown"),
                outcome="denied",
                actor=user,
                route_template=request.url.path,
                request_method=request.method,
                status_code=403,
                reason_code="permission_denied",
                metadata={"required_permission": permission},
                client_ip_hash=client_ip_hash(request),
                user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
            )
            raise HTTPException(status_code=403, detail="Permission denied")
        return user
    return dependency


def require_any_permission(*permissions: str):
    def dependency(
        db: Session = Depends(get_db),
        user: UserAccount = Depends(get_current_user),
    ) -> UserAccount:
        if user.must_change_password:
            raise HTTPException(status_code=403, detail="Password change required")
        if not effective_permissions(db, user).intersection(permissions):
            raise HTTPException(status_code=403, detail="Permission denied")
        return user
    return dependency


def require_all_permissions(*permissions: str):
    def dependency(
        db: Session = Depends(get_db),
        user: UserAccount = Depends(get_current_user),
    ) -> UserAccount:
        current = effective_permissions(db, user)
        if user.must_change_password or not set(permissions).issubset(current):
            raise HTTPException(status_code=403, detail="Permission denied")
        return user
    return dependency


def require_system_admin(user: UserAccount = Depends(get_current_user)) -> UserAccount:
    if not user.is_system_admin or user.must_change_password:
        raise HTTPException(status_code=403, detail="System administrator access required")
    return user


def require_authenticated_csrf(
    request: Request,
    db: Session = Depends(get_db),
    auth_session: AuthSession = Depends(get_current_session),
) -> AuthSession:
    del db
    validate_csrf(request, auth_session)
    return auth_session


def authorize_platform_request(
    request: Request,
    db: Session = Depends(get_db),
) -> Generator[UserAccount, None, None]:
    auth_session = lookup_session(db, request)
    if not auth_session:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = auth_session.user
    request.state.auth_session = auth_session
    request.state.current_user = user
    if user.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required")
    required, require_all = required_permissions(request)
    current = effective_permissions(db, user)
    allowed = required.issubset(current) if require_all else bool(required.intersection(current))
    if required and not allowed:
        append_event(
            db,
            event_type="authorization_denied",
            action="platform_request",
            request_id=getattr(request.state, "request_id", "unknown"),
            outcome="denied",
            actor=user,
            route_template=request.url.path,
            request_method=request.method,
            status_code=403,
            reason_code="permission_denied",
            metadata={"required_permissions": sorted(required)},
            client_ip_hash=client_ip_hash(request),
            user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
        )
        raise HTTPException(status_code=403, detail="Permission denied")
    if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        try:
            validate_csrf(request, auth_session)
        except HTTPException:
            append_event(
                db,
                event_type="csrf_failure",
                action="csrf_validation",
                request_id=getattr(request.state, "request_id", "unknown"),
                outcome="denied",
                actor=user,
                route_template=request.url.path,
                request_method=request.method,
                status_code=403,
                reason_code="csrf_invalid",
                client_ip_hash=client_ip_hash(request),
            )
            raise
    try:
        yield user
    except Exception:
        raise
    else:
        if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            append_event(
                db,
                event_type="module_mutation",
                action=f"{request.method.lower()} {request.url.path}",
                request_id=getattr(request.state, "request_id", "unknown"),
                outcome="success",
                actor=user,
                route_template=request.url.path,
                request_method=request.method,
                status_code=200,
                resource_type=request.url.path.split("/")[2] if len(request.url.path.split("/")) > 2 else "platform",
                client_ip_hash=client_ip_hash(request),
                user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
            )

