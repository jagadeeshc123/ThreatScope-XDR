from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base

from app import models
from sqlalchemy.orm import Session
from app.database import SessionLocal

# For MVP, create tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnScope API", description="Automated Web Application Security Assessment Platform API")

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        # Seed Settings
        settings = db.query(models.AppSettings).first()
        if not settings:
            settings = models.AppSettings()
            db.add(settings)
        
        # Seed Profile
        profile = db.query(models.UserProfile).first()
        if not profile:
            profile = models.UserProfile(
                full_name="Security Analyst",
                email="analyst@vulnscope.local",
                organization="VulnScope",
                role="Security Analyst",
                avatar_initials="SA"
            )
            db.add(profile)
            
        db.commit()
        from app.modules.soc_monitor.detection_rules import seed_default_rules
        seed_default_rules(db)
    finally:
        db.close()

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/")
def read_root():
    return {"message": "Welcome to VulnScope API"}

from app.routers import targets, scans, dashboard, reports, notifications, profile, settings, search, policies
from app.modules.api_security.router import router as api_security_router
from app.modules.soc_monitor.router import router as soc_monitor_router
from app.modules.document_threats.router import router as document_threats_router
from app.modules.phishing_defense.router import router as phishing_defense_router
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(policies.router, prefix="/api/policies", tags=["Policies"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(profile.router, prefix="/api/profile", tags=["Profile"])
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
app.include_router(search.router, prefix="/api/search", tags=["Search"])
app.include_router(api_security_router, prefix="/api/api-security", tags=["API Security"])
app.include_router(soc_monitor_router, prefix="/api/soc", tags=["SOC Monitor"])
app.include_router(document_threats_router, prefix="/api/document-threats", tags=["Document Threats"])
app.include_router(phishing_defense_router, prefix="/api/phishing-defense", tags=["Phishing Defense"])
