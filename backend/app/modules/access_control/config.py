import os
from dataclasses import dataclass

from app.modules.production.config import get_runtime_config


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
    cookie_samesite: str
    session_hours: int
    idle_minutes: int
    login_max_attempts: int
    lockout_minutes: int
    local_login_enabled: bool
    self_registration_enabled: bool
    registration_mode: str
    privacy_notice_version: str


def get_config() -> AccessConfig:
    runtime = get_runtime_config()
    environment = runtime.profile.value
    origins = runtime.allowed_origins
    default_mode = "approval_required" if environment == "production" else "auto_activate_limited"
    registration_mode = os.getenv("THREATSCOPE_REGISTRATION_MODE", "").strip().lower() or default_mode
    if registration_mode not in {"disabled", "approval_required", "auto_activate_limited"}:
        registration_mode = default_mode
    config = AccessConfig(
        enabled=_bool("THREATSCOPE_AUTH_ENABLED", True),
        environment=environment,
        session_secret=runtime.secrets["THREATSCOPE_SESSION_SECRET"],
        mfa_encryption_key=runtime.secrets["THREATSCOPE_MFA_ENCRYPTION_KEY"],
        allowed_origins=origins,
        cookie_secure=runtime.cookie_secure,
        cookie_samesite=runtime.cookie_samesite,
        session_hours=runtime.session_hours,
        idle_minutes=runtime.idle_minutes,
        login_max_attempts=_int("THREATSCOPE_LOGIN_MAX_ATTEMPTS", 5, 2, 20),
        lockout_minutes=_int("THREATSCOPE_LOCKOUT_MINUTES", 15, 1, 1440),
        local_login_enabled=_bool("THREATSCOPE_LOCAL_LOGIN_ENABLED", True),
        self_registration_enabled=runtime.public_registration,
        registration_mode=registration_mode,
        privacy_notice_version=os.getenv("THREATSCOPE_PRIVACY_NOTICE_VERSION", "").strip()[:64] or "local-privacy-v1",
    )
    return config
