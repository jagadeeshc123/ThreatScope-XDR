from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import models
from app.database import Base, SessionLocal, engine
from app.modules.access_control.audit_middleware import SecurityMiddleware
from app.modules.access_control.config import get_config
from app.modules.access_control.dependencies import authorize_platform_request, get_current_user
from app.modules.access_control.role_service import seed_roles_and_permissions
from app.modules.access_control.migration import ensure_local_account_schema
from app.modules.platform_operations.configuration_service import get_operations_config
from app.modules.integrations.security import IntegrationSecurityError
from app.modules.analytics.router import router as analytics_router
from app.modules.production.config import get_runtime_config
from app.modules.production.preflight import ensure_schema_metadata, run_preflight


runtime_config = get_runtime_config()
if runtime_config.production:
    startup_preflight = run_preflight(config=runtime_config, create_directories=True)
    if not startup_preflight["ready"]:
        failed = ", ".join(item["name"] for item in startup_preflight["checks"] if item["state"] == "failure")
        raise RuntimeError(f"Production startup preflight failed: {failed}")

Base.metadata.create_all(bind=engine)
ensure_local_account_schema(engine)

app = FastAPI(
    title="ThreatScope XDR API",
    description="Local security assessment and response platform API",
    debug=runtime_config.debug,
    docs_url="/docs" if runtime_config.api_docs else None,
    redoc_url="/redoc" if runtime_config.api_docs else None,
    openapi_url="/openapi.json" if runtime_config.api_docs else None,
)
app.add_middleware(SecurityMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(runtime_config.allowed_hosts))

config = get_config()
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(config.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": getattr(request.state, "request_id", "unknown")},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for item in exc.errors()[:20]:
        errors.append({"loc": item.get("loc", ()), "msg": item.get("msg", "Invalid input"), "type": item.get("type", "value_error")})
    return JSONResponse(status_code=422, content={"detail": errors, "request_id": getattr(request.state, "request_id", "unknown")})


@app.exception_handler(IntegrationSecurityError)
async def integration_exception_handler(request: Request, exc: IntegrationSecurityError):
    conflicts = {"CONNECTOR_OPTIMISTIC_LOCK_CONFLICT", "CONNECTOR_DELIVERY_CONFLICT", "CONNECTOR_NOT_ACTIVE", "CONNECTOR_CIRCUIT_OPEN", "CONNECTOR_REPLAY_DETECTED"}
    denied = {"CONNECTOR_PERMISSION_DENIED", "CONNECTOR_NETWORK_POLICY_DENIED", "CONNECTOR_SSRF_BLOCKED", "CONNECTOR_DNS_REBINDING_BLOCKED"}
    status = 409 if exc.code in conflicts else 403 if exc.code in denied else 422
    return JSONResponse(status_code=status, content={"detail": {"code": exc.code, "message": str(exc)}, "request_id": getattr(request.state, "request_id", "unknown")})


@app.on_event("startup")
def startup_event():
    get_operations_config(create=True)
    db = SessionLocal()
    try:
        ensure_schema_metadata(db)
        settings = db.query(models.AppSettings).first()
        if not settings:
            db.add(models.AppSettings())
        profile = db.query(models.UserProfile).first()
        if not profile:
            db.add(models.UserProfile(
                full_name="Local User",
                email="",
                organization="ThreatScope XDR",
                role="Local account",
                avatar_initials="LU",
            ))
        db.commit()
        seed_roles_and_permissions(db)
        from app.modules.platform_operations.retention_service import seed_policies
        seed_policies(db)
        from app.modules.soc_monitor.detection_rules import seed_default_rules
        seed_default_rules(db)
        from app.modules.threat_intelligence.service import seed_watchlists
        seed_watchlists(db)
        from app.modules.detection_engineering.service import seed_catalog_and_packs
        seed_catalog_and_packs(db)
        from app.modules.vulnerability_management.service import seed_defaults as seed_vulnerability_management
        seed_vulnerability_management(db)
        from app.modules.soar.service import seed_defaults as seed_soar
        seed_soar(db)
        from app.modules.integrations.service import seed_defaults as seed_integrations
        seed_integrations(db)
    finally:
        db.close()
    # Environment bootstrap is explicit and no-op unless all bootstrap variables are supplied.
    if not runtime_config.production:
        from scripts.create_admin import bootstrap_from_environment
        bootstrap_from_environment()
    # A first-run environment administrator is created after the initial seed transaction.
    # Re-open the session so protected IOC watchlists are also present on that first run.
    db = SessionLocal()
    try:
        from app.modules.threat_intelligence.service import seed_watchlists
        seed_watchlists(db)
        from app.modules.detection_engineering.service import seed_catalog_and_packs
        seed_catalog_and_packs(db)
        from app.modules.vulnerability_management.service import seed_defaults as seed_vulnerability_management
        seed_vulnerability_management(db)
        from app.modules.soar.service import seed_defaults as seed_soar
        seed_soar(db)
        from app.modules.integrations.service import seed_defaults as seed_integrations
        seed_integrations(db)
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/")
def read_root(user=Depends(get_current_user)):
    return {"message": "Welcome to ThreatScope XDR", "user": user.username}


from app.routers import dashboard, notifications, policies, profile, reports, scans, search, settings, targets
from app.modules.api_security.router import router as api_security_router
from app.modules.document_threats.router import router as document_threats_router
from app.modules.governance.router import router as governance_router
from app.modules.threat_intelligence.router import router as threat_intel_router
from app.modules.detection_engineering.router import router as detection_engineering_router
from app.modules.vulnerability_management.router import router as vulnerability_management_router
from app.modules.soar.router import router as soar_router
from app.modules.integrations.router import public_router as integrations_public_router, router as integrations_router
from app.modules.phishing_defense.router import router as phishing_defense_router
from app.modules.soc_monitor.router import router as soc_monitor_router
from app.modules.unified_correlation.router import router as correlation_router
from app.modules.access_control.router import admin_router, audit_router, router as auth_router
from app.modules.platform_operations.router import health_router, router as operations_router
from app.modules.production.router import router as production_router


protected = [Depends(authorize_platform_request)]
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin_router, prefix="/api/admin", tags=["Access Administration"])
app.include_router(audit_router, prefix="/api/security-audit", tags=["Security Audit"])
app.include_router(health_router, prefix="/api/health", tags=["Health"])
app.include_router(operations_router, prefix="/api/operations", tags=["Platform Operations"])
app.include_router(production_router, prefix="/api/operations/production", tags=["Production Operations"])
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"], dependencies=protected)
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"], dependencies=protected)
app.include_router(policies.router, prefix="/api/policies", tags=["Policies"], dependencies=protected)
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"], dependencies=protected)
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"], dependencies=protected)
app.include_router(notifications.router, prefix="/api/notifications", tags=["Notifications"], dependencies=protected)
app.include_router(profile.router, prefix="/api/profile", tags=["Profile"], dependencies=protected)
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"], dependencies=protected)
app.include_router(search.router, prefix="/api/search", tags=["Search"], dependencies=protected)
app.include_router(api_security_router, prefix="/api/api-security", tags=["API Security"], dependencies=protected)
app.include_router(soc_monitor_router, prefix="/api/soc", tags=["SOC Monitor"], dependencies=protected)
app.include_router(document_threats_router, prefix="/api/document-threats", tags=["Document Threats"], dependencies=protected)
app.include_router(phishing_defense_router, prefix="/api/phishing-defense", tags=["Phishing Defense"], dependencies=protected)
app.include_router(correlation_router, prefix="/api/correlation", tags=["Correlation & Cases"], dependencies=protected)
app.include_router(governance_router, prefix="/api/governance", tags=["Governance & Reporting"], dependencies=protected)
app.include_router(threat_intel_router, prefix="/api/threat-intel", tags=["Threat Intelligence"], dependencies=protected)
app.include_router(detection_engineering_router, prefix="/api/detections", tags=["Detection Engineering"], dependencies=protected)
app.include_router(vulnerability_management_router, prefix="/api/vulnerability-management", tags=["Vulnerability Management"], dependencies=protected)
app.include_router(soar_router, prefix="/api/soar", tags=["SOAR-Lite"], dependencies=protected)
app.include_router(integrations_router, prefix="/api/integrations", tags=["Security Integrations"], dependencies=protected)
app.include_router(integrations_public_router, prefix="/api/integrations", tags=["Signed Inbound Integrations"])
app.include_router(analytics_router, prefix="/api/analytics", tags=["Advanced Security Analytics"], dependencies=protected)
