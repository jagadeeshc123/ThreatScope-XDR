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


def _integration_operation(method: str, path: str) -> tuple[str, str | None]:
    suffix=path.removeprefix("/api/integrations");parts=[p for p in suffix.split("/") if p];resource_id=next((p for p in parts if p.isdigit()),None)
    root=parts[0] if parts else "overview";method=method.upper();verb={"POST":"create","PATCH":"update","DELETE":"delete"}.get(method,method.lower())
    if root=="connectors":
        if "credentials" in parts:return ("credential_rotate" if "rotate" in parts else "credential_remove" if method=="DELETE" else "credential_replace"),resource_id
        if "network-policy" in parts:return "network_policy_update",resource_id
        if "taxii" in parts and "pull" in parts:return "taxii_pull",resource_id
        actions={"move-to-testing":"connector_move_to_testing","activate":"connector_activate","disable":"connector_disable","archive":"connector_archive","validate":"configuration_validate","test":"connector_test","send-test":"connector_test_send","reset-circuit":"circuit_reset"}
        for token,action in actions.items():
            if token in parts:return action,resource_id
        return ("connector_create" if method=="POST" else "connector_update" if method=="PATCH" else f"connector_{method.lower()}"),resource_id
    if root=="subscriptions":return f"subscription_{verb}",resource_id
    if root=="mappings":
        if "validate" in parts:return "mapping_validate",resource_id
        if "preview" in parts:return "mapping_preview",resource_id
        return f"mapping_{verb}",resource_id
    if root=="deliveries":
        if "retry" in parts:return "delivery_manual_retry",resource_id
        if "cancel" in parts:return "delivery_cancel",resource_id
        return "delivery_queue",resource_id
    if root=="dead-letters":return ("dead_letter_replay" if "replay" in parts else "dead_letter_cancel"),resource_id
    if root=="inbound-endpoints":
        if "rotate-secret" in parts:return "inbound_secret_rotate",resource_id
        if "disable" in parts:return "inbound_endpoint_disable",resource_id
        return f"inbound_endpoint_{verb}",resource_id
    if root=="inbound-events":return ("inbound_promote" if "promote" in parts else "inbound_reject"),resource_id
    if root=="stix":return ("stix_preview" if "preview" in parts else "stix_promote"),resource_id
    if root=="reports":return ("report_export" if "download" in parts else "report_generation"),resource_id
    if root=="process-due":return "delivery_process_due",resource_id
    return f"{root.replace('-','_')}_{method.lower()}",resource_id


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
            integration=request.url.path.startswith("/api/integrations");action,resource_id=_integration_operation(request.method,request.url.path) if integration else (f"{request.method.lower()} {request.url.path}",None)
            append_event(
                db,
                event_type="integration_operation" if integration else "module_mutation",
                action=action,
                request_id=getattr(request.state, "request_id", "unknown"),
                outcome="success",
                actor=user,
                route_template=request.url.path,
                request_method=request.method,
                status_code=200,
                resource_type="integration" if integration else (request.url.path.split("/")[2] if len(request.url.path.split("/")) > 2 else "platform"),
                resource_id=resource_id,
                client_ip_hash=client_ip_hash(request),
                user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
            )
