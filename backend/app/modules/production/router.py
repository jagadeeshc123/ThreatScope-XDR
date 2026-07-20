from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.access_control.audit_service import append_event
from app.modules.access_control.dependencies import get_current_user, require_authenticated_csrf, require_permission, require_system_admin
from app.modules.access_control.models import AuthSession, UserAccount
from app.modules.platform_operations.maintenance_service import notify
from app.version import version_info

from .config import get_runtime_config
from .health import production_readiness
from .preflight import run_preflight
from .schemas import PreflightResponse


router = APIRouter()
_PREFLIGHT_ATTEMPTS: dict[int, float] = {}


@router.get("/readiness", dependencies=[Depends(require_permission("operations:view"))])
def readiness(db: Session = Depends(get_db)):
    return production_readiness(db)


@router.get("/build-info", dependencies=[Depends(require_permission("operations:view"))])
def build_info():
    config = get_runtime_config()
    info = version_info()
    return {
        "application_name": info["application_name"],
        "application_version": config.application_version,
        "schema_identifier": config.schema_identifier,
        "source_revision": config.source_revision,
        "build_timestamp": config.build_timestamp,
        "runtime_profile": config.profile.value,
        "frontend_build_identifier": config.frontend_build_id,
        "backend_build_identifier": config.backend_build_id,
    }


@router.get("/security-posture", dependencies=[Depends(require_permission("operations:diagnostics"))])
def security_posture():
    config = get_runtime_config()
    return {
        "profile": config.profile.value,
        "debug_enabled": config.debug,
        "api_documentation_enabled": config.api_docs,
        "secure_cookies": config.cookie_secure,
        "csrf_enabled": config.csrf_enabled,
        "exact_hosts_configured": bool(config.allowed_hosts) and "*" not in config.allowed_hosts,
        "exact_origins_configured": bool(config.allowed_origins) and "*" not in config.allowed_origins,
        "trusted_proxy_configured": bool(config.trusted_proxy_networks),
        "tls_proxy_expected": config.tls_proxy_expected,
        "connector_egress_enabled": config.connector_egress_enabled,
        "public_registration_enabled": config.public_registration,
        "secret_values_exposed": False,
    }


@router.post("/preflight", response_model=PreflightResponse)
def active_preflight(
    request: Request,
    db: Session = Depends(get_db),
    actor: UserAccount = Depends(require_system_admin),
    auth_session: AuthSession = Depends(require_authenticated_csrf),
):
    del auth_session
    now = time.monotonic()
    if now - _PREFLIGHT_ATTEMPTS.get(actor.id, 0.0) < 10:
        raise HTTPException(status_code=429, detail="Production preflight is rate limited", headers={"Retry-After": "10"})
    _PREFLIGHT_ATTEMPTS[actor.id] = now
    result = run_preflight(config=get_runtime_config(), create_directories=False, db=db)
    append_event(db, event_type="production_preflight", action="production_preflight", request_id=getattr(request.state, "request_id", "unknown"), outcome="success" if result["ready"] else "failure", actor=actor, resource_type="production_runtime", route_template=request.url.path, request_method=request.method, status_code=200, metadata={"ready": result["ready"], "failure_count": result["failure_count"], "warning_count": result["warning_count"]})
    if not result["ready"]:
        notify(db, "Production readiness degraded", "Active production preflight detected one or more failed safety checks.", "danger", "production_runtime", None)
        db.commit()
    return result
