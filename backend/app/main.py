from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import models
from app.database import Base, SessionLocal, engine
from app.modules.access_control.audit_middleware import SecurityMiddleware
from app.modules.access_control.config import get_config
from app.modules.access_control.dependencies import authorize_platform_request, get_current_user
from app.modules.access_control.role_service import seed_roles_and_permissions


Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatScope XDR API", description="Local security assessment and response platform API")
app.add_middleware(SecurityMiddleware)

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


@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
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
        from app.modules.soc_monitor.detection_rules import seed_default_rules
        seed_default_rules(db)
    finally:
        db.close()
    # Environment bootstrap is explicit and no-op unless all bootstrap variables are supplied.
    from scripts.create_admin import bootstrap_from_environment
    bootstrap_from_environment()


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
from app.modules.phishing_defense.router import router as phishing_defense_router
from app.modules.soc_monitor.router import router as soc_monitor_router
from app.modules.unified_correlation.router import router as correlation_router
from app.modules.access_control.router import admin_router, audit_router, router as auth_router


protected = [Depends(authorize_platform_request)]
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin_router, prefix="/api/admin", tags=["Access Administration"])
app.include_router(audit_router, prefix="/api/security-audit", tags=["Security Audit"])
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
