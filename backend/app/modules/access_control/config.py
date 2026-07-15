import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class AccessConfig:
    enabled: bool
    environment: str
    session_secret: str
    mfa_encryption_key: str
    allowed_origins: tuple[str, ...]
    cookie_secure: bool
    session_hours: int
    idle_minutes: int
    login_max_attempts: int
    lockout_minutes: int
    local_login_enabled: bool
    self_registration_enabled: bool
    registration_mode: str
    privacy_notice_version: str


def get_config() -> AccessConfig:
    environment = os.getenv("THREATSCOPE_ENV", "development").strip().lower()
    origins = tuple(
        item.strip() for item in os.getenv("THREATSCOPE_ALLOWED_ORIGINS", "http://localhost:5173").split(",") if item.strip()
    )
    default_mode = "approval_required" if environment == "production" else "auto_activate_limited"
    registration_mode = os.getenv("THREATSCOPE_REGISTRATION_MODE", "").strip().lower() or default_mode
    if registration_mode not in {"disabled", "approval_required", "auto_activate_limited"}:
        registration_mode = default_mode
    config = AccessConfig(
        enabled=_bool("THREATSCOPE_AUTH_ENABLED", True),
        environment=environment,
        session_secret=os.getenv("THREATSCOPE_SESSION_SECRET", ""),
        mfa_encryption_key=os.getenv("THREATSCOPE_MFA_ENCRYPTION_KEY", ""),
        allowed_origins=origins,
        cookie_secure=_bool("THREATSCOPE_COOKIE_SECURE", environment == "production"),
        session_hours=_int("THREATSCOPE_SESSION_HOURS", 8, 1, 168),
        idle_minutes=_int("THREATSCOPE_IDLE_MINUTES", 30, 5, 1440),
        login_max_attempts=_int("THREATSCOPE_LOGIN_MAX_ATTEMPTS", 5, 2, 20),
        lockout_minutes=_int("THREATSCOPE_LOCKOUT_MINUTES", 15, 1, 1440),
        local_login_enabled=_bool("THREATSCOPE_LOCAL_LOGIN_ENABLED", True),
        self_registration_enabled=_bool("THREATSCOPE_SELF_REGISTRATION_ENABLED", True),
        registration_mode=registration_mode,
        privacy_notice_version=os.getenv("THREATSCOPE_PRIVACY_NOTICE_VERSION", "").strip()[:64] or "local-privacy-v1",
    )
    if config.environment == "production":
        if len(config.session_secret) < 32:
            raise RuntimeError("THREATSCOPE_SESSION_SECRET must contain at least 32 characters in production")
        if not config.allowed_origins or "*" in config.allowed_origins:
            raise RuntimeError("Production requires explicit THREATSCOPE_ALLOWED_ORIGINS")
        if not config.cookie_secure:
            raise RuntimeError("Production authentication requires secure cookies")
    return config
