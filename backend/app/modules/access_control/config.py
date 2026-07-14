import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


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


def get_config() -> AccessConfig:
    environment = os.getenv("THREATSCOPE_ENV", "development").strip().lower()
    origins = tuple(
        item.strip() for item in os.getenv("THREATSCOPE_ALLOWED_ORIGINS", "http://localhost:5173").split(",") if item.strip()
    )
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
    )
    if config.environment == "production":
        if len(config.session_secret) < 32:
            raise RuntimeError("THREATSCOPE_SESSION_SECRET must contain at least 32 characters in production")
        if not config.allowed_origins or "*" in config.allowed_origins:
            raise RuntimeError("Production requires explicit THREATSCOPE_ALLOWED_ORIGINS")
        if not config.cookie_secure:
            raise RuntimeError("Production authentication requires secure cookies")
    return config

