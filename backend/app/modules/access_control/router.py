import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db

from . import mfa_service
from .account_service import (
    approve_registration,
    mask_email,
    register_local_account,
    registration_dict,
    reject_registration,
    reopen_registration,
)
from .audit_service import LIMITATIONS, append_event, verify_integrity
from .authentication import authenticate_password
from .config import get_config
from .dependencies import (
    get_current_session,
    get_current_user,
    require_authenticated_csrf,
    require_permission,
)
from .models import (
    AccessPermission,
    AccessRole,
    AuthSession,
    MfaDevice,
    MfaRecoveryCode,
    RolePermissionAssignment,
    SecurityAuditEvent,
    UserAccount,
    UserRoleAssignment,
)
from .password_service import PasswordPolicyError, verify_password
from .rate_limit_service import ManagementRateLimitError, clear_failures, record_management_attempt
from .role_service import assign_roles, effective_permissions, role_keys, seed_roles_and_permissions
from .schemas import (
    LoginRequest,
    LogoutAllRequest,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrollRequest,
    MfaLoginRequest,
    MfaRecoveryRegenerateRequest,
    PasswordChangeRequest,
    RegistrationApprovalRequest,
    RegistrationRejectionRequest,
    RegistrationRequest,
    PermissionAssignments,
    ResetPasswordRequest,
    RoleAssignments,
    RoleCreate,
    RoleUpdate,
    UserCreate,
    UserUpdate,
)
from .session_service import (
    clear_session_cookie,
    client_ip_hash,
    create_session,
    revoke_session,
    revoke_user_sessions,
    rotate_csrf,
    set_session_cookie,
    summarize_user_agent,
    utcnow,
)
from .user_service import (
    active_administrator_count,
    create_user,
    ensure_not_last_admin,
    generate_temporary_password,
    normalize_email,
    set_password,
    user_dict,
    validate_display_name,
)


router = APIRouter()
admin_router = APIRouter()
audit_router = APIRouter()


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def _audit(db: Session, request: Request, event_type: str, action: str, outcome: str, actor=None, **kwargs):
    return append_event(
        db,
        event_type=event_type,
        action=action,
        request_id=_request_id(request),
        outcome=outcome,
        actor=actor,
        route_template=request.url.path,
        request_method=request.method,
        client_ip_hash=client_ip_hash(request),
        user_agent_summary=summarize_user_agent(request.headers.get("user-agent")),
        **kwargs,
    )


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if not get_config().local_login_enabled:
        raise HTTPException(status_code=403, detail="Local login is unavailable")
    try:
        user = authenticate_password(db, request, payload.identifier, payload.password)
    except HTTPException as exc:
        _audit(db, request, "login_failure", "login", "failure", status_code=exc.status_code, reason_code="invalid_credentials")
        raise
    if user.status == "pending_approval":
        _audit(db, request, "login_pending", "login", "denied", actor=user, status_code=200, reason_code="pending_approval")
        return {"requires_mfa": False, "account_status": "pending_approval", "next_route": "/account-pending", "account": {"username": user.username, "display_name": user.display_name, "email": mask_email(user.email) if user.email else None}}
    if user.status == "rejected":
        _audit(db, request, "login_rejected", "login", "denied", actor=user, status_code=200, reason_code="rejected")
        return {"requires_mfa": False, "account_status": "rejected", "next_route": "/account-rejected", "account": {"username": user.username, "display_name": user.display_name, "email": mask_email(user.email) if user.email else None, "rejection_reason": user.rejection_reason}}
    if user.mfa_enabled:
        challenge = mfa_service.create_challenge(db, user.id)
        _audit(db, request, "login_mfa_required", "login", "success", actor=user, status_code=200)
        return {"requires_mfa": True, "challenge_token": challenge, "expires_in_seconds": 300}
    auth_session, token, _ = create_session(db, user, request, mfa_verified=False)
    db.commit()
    set_session_cookie(response, token)
    identifier_type = "email" if "@" in payload.identifier else "username"
    _audit(db, request, f"{identifier_type}_login_success", "login", "success", actor=user, status_code=200, resource_type="auth_session", resource_id=auth_session.id, metadata={"identifier_type": identifier_type})
    return {"requires_mfa": False, "user": user_dict(db, user, include_permissions=True)}


@router.get("/providers")
def providers():
    config = get_config()
    registration_enabled = config.local_login_enabled and config.self_registration_enabled and config.registration_mode != "disabled"
    return {
        "local_login_enabled": config.local_login_enabled,
        "self_registration_enabled": registration_enabled,
        "registration_mode": config.registration_mode if registration_enabled else "disabled",
        "approval_required": registration_enabled and config.registration_mode == "approval_required",
        "password_policy_summary": {"minimum_length": 12, "maximum_length": 128, "common_passwords_rejected": True, "identifier_inclusion_rejected": True},
        "privacy_notice_version": config.privacy_notice_version,
    }


@router.post("/register", status_code=201)
def register(payload: RegistrationRequest, request: Request, db: Session = Depends(get_db)):
    try:
        user, result = register_local_account(db, request, payload)
    except HTTPException as exc:
        _audit(db, request, "registration_failure", "register", "failure", status_code=exc.status_code, reason_code="registration_rejected")
        raise
    _audit(db, request, "registration_success", "register", "success", actor=user, status_code=201, resource_type="user", resource_id=user.id, metadata={"status": user.status, "source": "local"})
    return result


@router.post("/mfa/verify-login")
def verify_mfa_login(payload: MfaLoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    challenge = mfa_service.get_challenge(db, payload.challenge_token)
    if not challenge:
        raise HTTPException(status_code=401, detail="MFA challenge is invalid or expired")
    user = db.get(UserAccount, challenge.user_id)
    if not user or user.status in {"disabled", "locked"}:
        raise HTTPException(status_code=401, detail="MFA challenge is invalid or expired")
    if not mfa_service.verify_user_factor(db, user, payload.code, payload.recovery_code):
        challenge.failed_attempts += 1
        db.commit()
        _audit(db, request, "mfa_login_failure", "mfa_login", "failure", actor=user, status_code=401, reason_code="invalid_factor")
        raise HTTPException(status_code=401, detail="MFA verification failed")
    challenge.used_at = utcnow()
    auth_session, token, _ = create_session(db, user, request, mfa_verified=True)
    db.commit()
    set_session_cookie(response, token)
    _audit(db, request, "login_success", "mfa_login", "success", actor=user, status_code=200, resource_type="auth_session", resource_id=auth_session.id, metadata={"recovery_code_used": payload.recovery_code})
    return {"requires_mfa": False, "user": user_dict(db, user, include_permissions=True)}


@router.get("/me")
def me(db: Session = Depends(get_db), user: UserAccount = Depends(get_current_user)):
    return user_dict(db, user, include_permissions=True)


@router.get("/csrf")
def csrf(db: Session = Depends(get_db), auth_session: AuthSession = Depends(get_current_session)):
    return {"csrf_token": rotate_csrf(db, auth_session)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    revoke_session(db, auth_session, "logout")
    clear_session_cookie(response)
    _audit(db, request, "logout", "logout", "success", actor=user, status_code=200, resource_type="auth_session", resource_id=auth_session.id)
    return {"ok": True}


@router.post("/logout-all")
def logout_all(payload: LogoutAllRequest, request: Request, response: Response, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    count = revoke_user_sessions(db, auth_session.user_id, "logout_all", auth_session.id if payload.preserve_current else None)
    if not payload.preserve_current:
        clear_session_cookie(response)
    _audit(db, request, "logout_all", "logout_all", "success", actor=auth_session.user, status_code=200, metadata={"sessions_revoked": count, "preserved_current": payload.preserve_current})
    return {"ok": True, "sessions_revoked": count}


@router.post("/password/change")
def change_password(payload: PasswordChangeRequest, request: Request, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    try:
        set_password(db, user, payload.new_password, False, "password_changed", auth_session.id)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rotate_csrf(db, auth_session)
    _audit(db, request, "password_changed", "password_change", "success", actor=user, status_code=200)
    return {"ok": True}


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), auth_session: AuthSession = Depends(get_current_session)):
    items = db.query(AuthSession).filter_by(user_id=auth_session.user_id).order_by(AuthSession.created_at.desc()).all()
    return [{
        "id": item.id,
        "current": item.id == auth_session.id,
        "created_at": item.created_at,
        "last_seen_at": item.last_seen_at,
        "expires_at": item.expires_at,
        "idle_expires_at": item.idle_expires_at,
        "revoked_at": item.revoked_at,
        "user_agent_summary": item.user_agent_summary,
        "client_ip_hash": item.client_ip_hash[:12] if item.client_ip_hash else None,
        "mfa_verified": item.mfa_verified,
    } for item in items]


@router.delete("/sessions/{session_id}")
def delete_session(session_id: int, request: Request, response: Response, db: Session = Depends(get_db), current: AuthSession = Depends(require_authenticated_csrf)):
    item = db.query(AuthSession).filter_by(id=session_id, user_id=current.user_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Session not found")
    revoke_session(db, item, "user_revoked")
    if item.id == current.id:
        clear_session_cookie(response)
    _audit(db, request, "session_revoked", "revoke_session", "success", actor=current.user, status_code=200, resource_type="auth_session", resource_id=item.id)
    return {"ok": True}


@router.post("/mfa/enroll")
def enroll_mfa(payload: MfaEnrollRequest, request: Request, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    try:
        device, secret, uri = mfa_service.begin_enrollment(db, user, payload.label)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"device_id": device.id, "secret": secret, "provisioning_uri": uri, "warning": "The secret is shown only until enrollment is confirmed."}


@router.post("/mfa/confirm")
def confirm_mfa(payload: MfaConfirmRequest, request: Request, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    device = db.query(MfaDevice).filter_by(id=payload.device_id, user_id=user.id, enabled=False).first()
    if not device or not mfa_service.verify_totp(device, payload.code):
        raise HTTPException(status_code=422, detail="MFA confirmation code is invalid")
    device.enabled = True
    device.confirmed_at = utcnow()
    user.mfa_enabled = True
    db.commit()
    codes = mfa_service.generate_recovery_codes(db, user.id)
    rotate_csrf(db, auth_session)
    _audit(db, request, "mfa_enrolled", "mfa_enroll", "success", actor=user, status_code=200, resource_type="mfa_device", resource_id=device.id)
    return {"ok": True, "recovery_codes": codes, "warning": "Store these recovery codes now. They cannot be displayed again."}


@router.post("/mfa/disable")
def disable_mfa(payload: MfaDisableRequest, request: Request, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    if not verify_password(user.password_hash, payload.current_password) or not mfa_service.verify_user_factor(db, user, payload.code, payload.recovery_code):
        raise HTTPException(status_code=400, detail="MFA could not be disabled")
    now = utcnow()
    db.query(MfaDevice).filter_by(user_id=user.id, enabled=True).update({MfaDevice.enabled: False, MfaDevice.disabled_at: now}, synchronize_session=False)
    db.query(MfaRecoveryCode).filter_by(user_id=user.id).delete(synchronize_session=False)
    user.mfa_enabled = False
    db.commit()
    rotate_csrf(db, auth_session)
    _audit(db, request, "mfa_disabled", "mfa_disable", "success", actor=user, status_code=200)
    return {"ok": True}


@router.post("/mfa/recovery/regenerate")
def regenerate_recovery(payload: MfaRecoveryRegenerateRequest, request: Request, db: Session = Depends(get_db), auth_session: AuthSession = Depends(require_authenticated_csrf)):
    user = auth_session.user
    if not verify_password(user.password_hash, payload.current_password) or not mfa_service.verify_user_factor(db, user, payload.code, payload.recovery_code):
        raise HTTPException(status_code=400, detail="Recovery codes could not be regenerated")
    codes = mfa_service.generate_recovery_codes(db, user.id)
    _audit(db, request, "recovery_codes_regenerated", "mfa_recovery_regenerate", "success", actor=user, status_code=200)
    return {"recovery_codes": codes, "warning": "Previous recovery codes are now invalid. Store these codes now."}


def _user_or_404(db: Session, user_id: int) -> UserAccount:
    user = db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@admin_router.get("/registrations", dependencies=[Depends(require_permission("users:manage"))])
def registrations(
    db: Session = Depends(get_db),
    status: str | None = None,
    email: str | None = Query(None, max_length=254),
    username: str | None = Query(None, max_length=64),
    source: str | None = Query(None, max_length=32),
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    pending_age_days: int | None = Query(None, ge=0, le=3650),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
):
    query = db.query(UserAccount).filter(UserAccount.registration_source == "local")
    if status: query = query.filter(UserAccount.status == status)
    if email: query = query.filter(UserAccount.email_normalized.ilike(f"%{email.strip().casefold()}%"))
    if username: query = query.filter(UserAccount.username_normalized.ilike(f"%{username.strip().casefold()}%"))
    if source: query = query.filter(UserAccount.registration_source == source)
    if created_from: query = query.filter(UserAccount.created_at >= created_from)
    if created_to: query = query.filter(UserAccount.created_at <= created_to)
    if pending_age_days is not None: query = query.filter(UserAccount.status == "pending_approval", UserAccount.created_at <= utcnow() - timedelta(days=pending_age_days))
    total = query.count()
    items = query.order_by(UserAccount.created_at.desc()).offset(skip).limit(limit).all()
    return {"items": [registration_dict(db, item) for item in items], "total": total}


@admin_router.get("/registrations/{user_id}", dependencies=[Depends(require_permission("users:manage"))])
def registration_detail(user_id: int, db: Session = Depends(get_db)):
    user = _user_or_404(db, user_id)
    if user.registration_source != "local": raise HTTPException(status_code=404, detail="Registration not found")
    data = registration_dict(db, user)
    data["rejection_reason"] = user.rejection_reason
    return data


@admin_router.post("/registrations/{user_id}/approve", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def approve(user_id: int, payload: RegistrationApprovalRequest, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id)
    try:
        record_management_attempt(db, actor.id, "approve", client_ip_hash(request))
        approve_registration(db, user, actor, payload.role_keys, payload.confirm_administrator)
    except ManagementRateLimitError as exc: db.rollback(); raise HTTPException(status_code=429, detail="Registration management is temporarily unavailable") from exc
    except ValueError as exc: db.rollback(); raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "account_approved", "approve_registration", "success", actor=actor, status_code=200, resource_type="user", resource_id=user.id, metadata={"role_keys": payload.role_keys})
    return registration_dict(db, user)


@admin_router.post("/registrations/{user_id}/reject", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def reject(user_id: int, payload: RegistrationRejectionRequest, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id)
    try:
        record_management_attempt(db, actor.id, "reject", client_ip_hash(request))
        reject_registration(db, user, actor, payload.reason)
    except ManagementRateLimitError as exc: db.rollback(); raise HTTPException(status_code=429, detail="Registration management is temporarily unavailable") from exc
    except ValueError as exc: db.rollback(); raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "account_rejected", "reject_registration", "success", actor=actor, status_code=200, resource_type="user", resource_id=user.id)
    return registration_dict(db, user)


@admin_router.post("/registrations/{user_id}/reopen", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def reopen(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id)
    try:
        record_management_attempt(db, actor.id, "reopen", client_ip_hash(request))
        reopen_registration(db, user, actor)
    except ManagementRateLimitError as exc: db.rollback(); raise HTTPException(status_code=429, detail="Registration management is temporarily unavailable") from exc
    except ValueError as exc: db.rollback(); raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "account_reopened", "reopen_registration", "success", actor=actor, status_code=200, resource_type="user", resource_id=user.id)
    return registration_dict(db, user)


@admin_router.get("/users", dependencies=[Depends(require_permission("users:read"))])
def admin_users(db: Session = Depends(get_db), skip: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=200)):
    return [user_dict(db, user) for user in db.query(UserAccount).order_by(UserAccount.username_normalized).offset(skip).limit(limit).all()]


@admin_router.post("/users", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def admin_create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    temporary_password = payload.temporary_password or generate_temporary_password(payload.username)
    try:
        user = create_user(
            db,
            username=payload.username,
            display_name=payload.display_name,
            email=payload.email,
            password=temporary_password,
            role_keys=payload.role_keys,
            must_change_password=True,
            is_system_admin=payload.is_system_admin,
            actor_id=actor.id,
        )
    except (ValueError, PasswordPolicyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "user_created", "create_user", "success", actor=actor, status_code=200, resource_type="user", resource_id=user.id)
    return {"user": user_dict(db, user), "temporary_password": temporary_password, "warning": "The temporary password is shown only once."}


@admin_router.get("/users/{user_id}", dependencies=[Depends(require_permission("users:read"))])
def admin_user(user_id: int, db: Session = Depends(get_db)):
    return user_dict(db, _user_or_404(db, user_id))


@admin_router.patch("/users/{user_id}", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def admin_update_user(user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id)
    try:
        if payload.display_name is not None: user.display_name = validate_display_name(payload.display_name)
        if payload.email is not None:
            normalized = normalize_email(payload.email)
            duplicate = db.query(UserAccount).filter(UserAccount.email_normalized == normalized, UserAccount.id != user.id).first() if normalized else None
            if duplicate: raise ValueError("Email is already in use")
            user.email = payload.email.strip() or None
            user.email_normalized = normalized
        if payload.must_change_password is not None:
            user.must_change_password = payload.must_change_password
            user.status = "pending_password_change" if payload.must_change_password else "active"
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "user_updated", "update_user", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return user_dict(db, user)


@admin_router.post("/users/{user_id}/disable", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def disable_user(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id)
    try: ensure_not_last_admin(db, user)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc
    user.status = "disabled"; user.disabled_at = utcnow(); db.commit()
    revoke_user_sessions(db, user.id, "account_disabled")
    _audit(db, request, "user_disabled", "disable_user", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return user_dict(db, user)


@admin_router.post("/users/{user_id}/enable", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def enable_user(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id); user.status = "pending_password_change" if user.must_change_password else "active"; user.disabled_at = None; db.commit()
    _audit(db, request, "user_enabled", "enable_user", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return user_dict(db, user)


@admin_router.post("/users/{user_id}/unlock", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def unlock_user(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id); clear_failures(db, user)
    _audit(db, request, "account_unlocked", "unlock_user", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return user_dict(db, user)


@admin_router.post("/users/{user_id}/reset-password", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def reset_password(user_id: int, payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id); temporary = payload.temporary_password or generate_temporary_password(user.username)
    try: set_password(db, user, temporary, True, "administrator_password_reset")
    except PasswordPolicyError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc
    _audit(db, request, "password_reset", "reset_password", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return {"ok": True, "temporary_password": temporary, "warning": "The temporary password is shown only once."}


@admin_router.post("/users/{user_id}/reset-mfa", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("users:manage"))])
def reset_mfa(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id); now = utcnow(); was_disabled = user.status == "disabled"
    db.query(MfaDevice).filter_by(user_id=user.id).update({MfaDevice.enabled: False, MfaDevice.disabled_at: now}, synchronize_session=False)
    db.query(MfaRecoveryCode).filter_by(user_id=user.id).delete(synchronize_session=False)
    user.mfa_enabled = False; user.must_change_password = True; user.status = "disabled" if was_disabled else "pending_password_change"; db.commit(); revoke_user_sessions(db, user.id, "administrator_mfa_reset")
    _audit(db, request, "mfa_reset", "reset_mfa", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200)
    return {"ok": True}


@admin_router.get("/users/{user_id}/sessions", dependencies=[Depends(require_permission("sessions:manage_all"))])
def admin_user_sessions(user_id: int, db: Session = Depends(get_db)):
    _user_or_404(db, user_id)
    return [{"id": s.id, "created_at": s.created_at, "last_seen_at": s.last_seen_at, "expires_at": s.expires_at, "revoked_at": s.revoked_at, "user_agent_summary": s.user_agent_summary, "client_ip_hash": s.client_ip_hash[:12] if s.client_ip_hash else None} for s in db.query(AuthSession).filter_by(user_id=user_id).all()]


@admin_router.delete("/users/{user_id}/sessions/{session_id}", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("sessions:manage_all"))])
def admin_revoke_session(user_id: int, session_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    item = db.query(AuthSession).filter_by(id=session_id, user_id=user_id).first()
    if not item: raise HTTPException(status_code=404, detail="Session not found")
    revoke_session(db, item, "administrator_revoked")
    _audit(db, request, "session_revoked", "admin_revoke_session", "success", actor=actor, resource_type="auth_session", resource_id=item.id, status_code=200)
    return {"ok": True}


@admin_router.post("/users/{user_id}/revoke-all-sessions", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("sessions:manage_all"))])
def admin_revoke_all(user_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    _user_or_404(db, user_id); count = revoke_user_sessions(db, user_id, "administrator_revoked_all")
    _audit(db, request, "session_revoked", "admin_revoke_all_sessions", "success", actor=actor, resource_type="user", resource_id=user_id, status_code=200, metadata={"sessions_revoked": count})
    return {"ok": True, "sessions_revoked": count}


def _role_dict(db: Session, role: AccessRole) -> dict:
    permissions = [row[0] for row in db.query(AccessPermission.permission_key).join(RolePermissionAssignment).filter(RolePermissionAssignment.role_id == role.id).order_by(AccessPermission.permission_key).all()]
    assigned_users = db.query(UserRoleAssignment).filter_by(role_id=role.id).count()
    return {"id": role.id, "role_key": role.role_key, "name": role.name, "description": role.description, "system_role": role.system_role, "enabled": role.enabled, "permission_keys": permissions, "assigned_users": assigned_users, "created_at": role.created_at, "updated_at": role.updated_at}


@admin_router.get("/roles", dependencies=[Depends(require_permission("roles:read"))])
def admin_roles(db: Session = Depends(get_db)):
    return [_role_dict(db, role) for role in db.query(AccessRole).order_by(AccessRole.system_role.desc(), AccessRole.name).all()]


@admin_router.post("/roles", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("roles:manage"))])
def create_role(payload: RoleCreate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    if db.query(AccessRole).filter_by(role_key=payload.role_key).first(): raise HTTPException(status_code=409, detail="Role key already exists")
    permissions = db.query(AccessPermission).filter(AccessPermission.permission_key.in_(set(payload.permission_keys))).all() if payload.permission_keys else []
    if len(permissions) != len(set(payload.permission_keys)): raise HTTPException(status_code=422, detail="One or more permission keys are invalid")
    role = AccessRole(role_key=payload.role_key, name=payload.name.strip(), description=payload.description.strip(), enabled=payload.enabled, system_role=False); db.add(role); db.flush()
    for permission in permissions: db.add(RolePermissionAssignment(role_id=role.id, permission_id=permission.id))
    db.commit(); db.refresh(role)
    _audit(db, request, "role_created", "create_role", "success", actor=actor, resource_type="role", resource_id=role.id, status_code=200)
    return _role_dict(db, role)


def _role_or_404(db: Session, role_id: int) -> AccessRole:
    role = db.get(AccessRole, role_id)
    if not role: raise HTTPException(status_code=404, detail="Role not found")
    return role


@admin_router.get("/roles/{role_id}", dependencies=[Depends(require_permission("roles:read"))])
def admin_role(role_id: int, db: Session = Depends(get_db)): return _role_dict(db, _role_or_404(db, role_id))


@admin_router.patch("/roles/{role_id}", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("roles:manage"))])
def update_role(role_id: int, payload: RoleUpdate, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    role = _role_or_404(db, role_id)
    if role.system_role and (payload.name is not None or payload.description is not None): raise HTTPException(status_code=422, detail="System role identity cannot be changed")
    if payload.name is not None: role.name = payload.name.strip()
    if payload.description is not None: role.description = payload.description.strip()
    if payload.enabled is not None:
        if role.system_role and not payload.enabled: raise HTTPException(status_code=422, detail="System roles cannot be disabled")
        role.enabled = payload.enabled
    affected = [row[0] for row in db.query(UserRoleAssignment.user_id).filter_by(role_id=role.id).all()]; db.commit()
    for user_id in affected: revoke_user_sessions(db, user_id, "role_changed")
    _audit(db, request, "role_changed", "update_role", "success", actor=actor, resource_type="role", resource_id=role.id, status_code=200)
    return _role_dict(db, role)


@admin_router.delete("/roles/{role_id}", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("roles:manage"))])
def delete_role(role_id: int, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    role = _role_or_404(db, role_id)
    if role.system_role: raise HTTPException(status_code=422, detail="System roles cannot be deleted")
    if db.query(UserRoleAssignment).filter_by(role_id=role.id).count(): raise HTTPException(status_code=422, detail="Assigned roles cannot be deleted")
    db.delete(role); db.commit(); _audit(db, request, "role_deleted", "delete_role", "success", actor=actor, resource_type="role", resource_id=role_id, status_code=200); return {"ok": True}


@admin_router.get("/permissions", dependencies=[Depends(require_permission("roles:read"))])
def permissions(db: Session = Depends(get_db)):
    return [{"id": p.id, "permission_key": p.permission_key, "name": p.name, "description": p.description, "category": p.category} for p in db.query(AccessPermission).order_by(AccessPermission.category, AccessPermission.permission_key).all()]


@admin_router.get("/roles/{role_id}/permissions", dependencies=[Depends(require_permission("roles:read"))])
def role_permissions(role_id: int, db: Session = Depends(get_db)): return _role_dict(db, _role_or_404(db, role_id))["permission_keys"]


@admin_router.put("/roles/{role_id}/permissions", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("roles:manage"))])
def set_role_permissions(role_id: int, payload: PermissionAssignments, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    role = _role_or_404(db, role_id)
    if role.system_role: raise HTTPException(status_code=422, detail="System role permissions are deterministic and cannot be edited")
    items = db.query(AccessPermission).filter(AccessPermission.permission_key.in_(set(payload.permission_keys))).all() if payload.permission_keys else []
    if len(items) != len(set(payload.permission_keys)): raise HTTPException(status_code=422, detail="One or more permission keys are invalid")
    affected = [row[0] for row in db.query(UserRoleAssignment.user_id).filter_by(role_id=role.id).all()]
    db.query(RolePermissionAssignment).filter_by(role_id=role.id).delete(synchronize_session=False)
    for item in items: db.add(RolePermissionAssignment(role_id=role.id, permission_id=item.id))
    db.commit()
    for user_id in affected: revoke_user_sessions(db, user_id, "role_permissions_changed")
    _audit(db, request, "permission_set_changed", "set_role_permissions", "success", actor=actor, resource_type="role", resource_id=role.id, status_code=200, metadata={"permission_count": len(items)})
    return _role_dict(db, role)


@admin_router.get("/users/{user_id}/roles", dependencies=[Depends(require_permission("roles:read"))])
def user_roles(user_id: int, db: Session = Depends(get_db)): _user_or_404(db, user_id); return role_keys(db, user_id)


@admin_router.put("/users/{user_id}/roles", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("roles:manage"))])
def set_user_roles(user_id: int, payload: RoleAssignments, request: Request, db: Session = Depends(get_db), actor: UserAccount = Depends(get_current_user)):
    user = _user_or_404(db, user_id); becoming_admin = "administrator" in payload.role_keys
    if user.is_system_admin and not becoming_admin:
        try: ensure_not_last_admin(db, user)
        except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc
    try: assign_roles(db, user, payload.role_keys, actor.id)
    except ValueError as exc: db.rollback(); raise HTTPException(status_code=422, detail=str(exc)) from exc
    user.is_system_admin = becoming_admin; db.commit(); revoke_user_sessions(db, user.id, "role_assignment_changed")
    _audit(db, request, "role_assigned", "set_user_roles", "success", actor=actor, resource_type="user", resource_id=user.id, status_code=200, metadata={"role_keys": payload.role_keys})
    return role_keys(db, user.id)


def _audit_dict(item: SecurityAuditEvent) -> dict:
    return {"id": item.id, "sequence_number": item.sequence_number, "event_type": item.event_type, "actor_user_id": item.actor_user_id, "actor_username_snapshot": item.actor_username_snapshot, "actor_role_keys": json.loads(item.actor_role_keys_json), "action": item.action, "resource_type": item.resource_type, "resource_id": item.resource_id, "route_template": item.route_template, "request_method": item.request_method, "request_id": item.request_id, "outcome": item.outcome, "status_code": item.status_code, "reason_code": item.reason_code, "metadata": json.loads(item.metadata_json), "client_ip_hash": item.client_ip_hash[:12] if item.client_ip_hash else None, "user_agent_summary": item.user_agent_summary, "occurred_at": item.occurred_at, "previous_event_hash": item.previous_event_hash, "event_hash": item.event_hash}


@audit_router.get("/events", dependencies=[Depends(require_permission("audit:read"))])
def audit_events(db: Session = Depends(get_db), actor: str | None = None, event_type: str | None = None, action: str | None = None, outcome: str | None = None, resource_type: str | None = None, status_code: int | None = None, request_id: str | None = None, q: str | None = Query(None, max_length=200), date_from: datetime | None = None, date_to: datetime | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    if date_from and date_to and date_from > date_to: raise HTTPException(status_code=422, detail="date_from must not be after date_to")
    query = db.query(SecurityAuditEvent)
    for field, value in [(SecurityAuditEvent.event_type, event_type), (SecurityAuditEvent.action, action), (SecurityAuditEvent.outcome, outcome), (SecurityAuditEvent.resource_type, resource_type), (SecurityAuditEvent.request_id, request_id)]:
        if value: query = query.filter(field == value)
    if actor: query = query.filter(SecurityAuditEvent.actor_username_snapshot.ilike(f"%{actor}%"))
    if status_code is not None: query = query.filter(SecurityAuditEvent.status_code == status_code)
    if date_from: query = query.filter(SecurityAuditEvent.occurred_at >= date_from)
    if date_to: query = query.filter(SecurityAuditEvent.occurred_at <= date_to)
    if q:
        term = f"%{q}%"; query = query.filter(or_(SecurityAuditEvent.action.ilike(term), SecurityAuditEvent.event_type.ilike(term), SecurityAuditEvent.resource_id.ilike(term), SecurityAuditEvent.request_id.ilike(term)))
    total = query.count(); items = query.order_by(SecurityAuditEvent.sequence_number.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_audit_dict(item) for item in items], "total": total, "page": page, "page_size": page_size}


@audit_router.get("/events/{event_id}", dependencies=[Depends(require_permission("audit:read"))])
def audit_event(event_id: int, db: Session = Depends(get_db)):
    item = db.get(SecurityAuditEvent, event_id)
    if not item: raise HTTPException(status_code=404, detail="Audit event not found")
    return _audit_dict(item)


@audit_router.post("/verify-integrity", dependencies=[Depends(require_authenticated_csrf), Depends(require_permission("audit:verify"))])
def audit_verify(db: Session = Depends(get_db)): return verify_integrity(db)


@audit_router.get("/overview", dependencies=[Depends(require_permission("audit:read"))])
def audit_overview(db: Session = Depends(get_db)):
    total = db.query(SecurityAuditEvent).count(); denied = db.query(SecurityAuditEvent).filter_by(outcome="denied").count(); failures = db.query(SecurityAuditEvent).filter_by(outcome="failure").count(); latest = db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number.desc()).first()
    return {"total_events": total, "denied_events": denied, "failed_events": failures, "latest_sequence": latest.sequence_number if latest else 0, "limitations": LIMITATIONS}
