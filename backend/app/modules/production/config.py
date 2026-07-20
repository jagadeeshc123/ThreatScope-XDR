from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

from app.version import SCHEMA_IDENTIFIER, version_info

from .secrets import SecretLoadError, SecretStatus, load_application_secrets


class ConfigurationError(RuntimeError):
    pass


class RuntimeProfile(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


def _raw(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be an explicit boolean")


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(_raw(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _items(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in _raw(name, default).split(",") if item.strip()))


def _directory(name: str, default: str) -> Path:
    path = Path(_raw(name, default)).expanduser()
    return path.resolve()


@dataclass(frozen=True)
class RuntimeConfig:
    profile: RuntimeProfile
    debug: bool
    reload: bool
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    trusted_proxy_networks: tuple[str, ...]
    cookie_secure: bool
    cookie_samesite: str
    session_hours: int
    idle_minutes: int
    csrf_enabled: bool
    database_url: str
    data_dir: Path
    upload_dir: Path
    backup_dir: Path
    report_dir: Path
    runtime_dir: Path
    export_dir: Path
    release_dir: Path
    log_level: str
    json_logging: bool
    max_request_bytes: int
    max_upload_bytes: int
    request_timeout_seconds: int
    graceful_shutdown_seconds: int
    worker_count: int
    public_registration: bool
    registration_acknowledged: bool
    demo_seed: bool
    api_docs: bool
    connector_egress_enabled: bool
    tls_proxy_expected: bool
    schema_identifier: str
    application_version: str
    source_revision: str
    build_timestamp: str
    frontend_build_id: str
    backend_build_id: str
    minimum_free_bytes: int
    tls_certificate_file: str
    tls_private_key_file: str
    secrets: dict[str, str]
    secret_statuses: tuple[SecretStatus, ...]

    @property
    def production(self) -> bool:
        return self.profile is RuntimeProfile.PRODUCTION

    def public_summary(self) -> dict[str, object]:
        return {
            "profile": self.profile.value,
            "application_version": self.application_version,
            "schema_identifier": self.schema_identifier,
            "source_revision": self.source_revision,
            "tls_proxy_expected": self.tls_proxy_expected,
            "connector_egress_enabled": self.connector_egress_enabled,
            "public_registration_enabled": self.public_registration,
            "api_documentation_enabled": self.api_docs,
            "worker_count": self.worker_count,
            "secret_loader": [
                {"name": item.name, "configured": item.configured, "source": item.source}
                for item in self.secret_statuses
            ],
        }


def _validate_production(config: RuntimeConfig) -> None:
    errors: list[str] = []
    registration_mode = _raw("THREATSCOPE_REGISTRATION_MODE", "disabled").casefold()
    if registration_mode not in {"disabled", "approval_required", "auto_activate_limited"}:
        errors.append("THREATSCOPE_REGISTRATION_MODE is unsupported")
    if config.debug:
        errors.append("THREATSCOPE_DEBUG must be disabled")
    if config.reload:
        errors.append("THREATSCOPE_RELOAD must be disabled")
    if config.api_docs:
        errors.append("THREATSCOPE_API_DOCS must be disabled")
    if not config.cookie_secure:
        errors.append("THREATSCOPE_COOKIE_SECURE must be enabled")
    if config.cookie_samesite not in {"lax", "strict"}:
        errors.append("THREATSCOPE_COOKIE_SAMESITE must be lax or strict")
    if not config.csrf_enabled:
        errors.append("THREATSCOPE_CSRF_ENABLED must be enabled")
    if not config.allowed_hosts or any(host == "*" or "*" in host for host in config.allowed_hosts):
        errors.append("THREATSCOPE_ALLOWED_HOSTS must contain exact hosts")
    if not config.allowed_origins or any(origin == "*" for origin in config.allowed_origins):
        errors.append("THREATSCOPE_ALLOWED_ORIGINS must contain exact origins")
    smoke = _bool("THREATSCOPE_LOCAL_PRODUCTION_SMOKE", False)
    for origin in config.allowed_origins:
        parsed = urlsplit(origin)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            errors.append("Production origins must not contain userinfo, query, or fragment")
        if parsed.scheme != "https" and not (smoke and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}):
            errors.append("Production origins must use HTTPS")
        if not parsed.hostname:
            errors.append("Production origins must be absolute")
    if not config.trusted_proxy_networks:
        errors.append("THREATSCOPE_TRUSTED_PROXY_NETWORKS is required")
    for network in config.trusted_proxy_networks:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            errors.append("THREATSCOPE_TRUSTED_PROXY_NETWORKS contains an invalid network")
    if not config.tls_proxy_expected:
        errors.append("THREATSCOPE_TLS_PROXY_EXPECTED must be enabled")
    if not config.database_url.startswith("sqlite:////"):
        errors.append("Production SQLite DATABASE_URL must use an absolute persistent path")
    if config.worker_count != 1:
        errors.append("SQLite production mode requires exactly one worker")
    if config.demo_seed:
        errors.append("THREATSCOPE_DEMO_MODE must be disabled")
    if _raw("THREATSCOPE_BOOTSTRAP_ADMIN_USERNAME") or _raw("THREATSCOPE_BOOTSTRAP_ADMIN_PASSWORD"):
        errors.append("Environment password bootstrap is disabled in production")
    if config.public_registration and not config.registration_acknowledged:
        errors.append("Public registration requires explicit production acknowledgement")
    if registration_mode == "disabled" and config.public_registration:
        errors.append("Disabled registration mode cannot enable public registration")
    if config.schema_identifier != SCHEMA_IDENTIFIER:
        errors.append("Configured schema identifier is unsupported")
    if config.source_revision in {"", "development", "unknown"}:
        errors.append("THREATSCOPE_BUILD_COMMIT is required")
    if config.application_version in {"", "development"}:
        errors.append("THREATSCOPE_APP_VERSION is required")
    if len(config.secrets["THREATSCOPE_SESSION_SECRET"]) < 32 or len(set(config.secrets["THREATSCOPE_SESSION_SECRET"])) < 12:
        errors.append("Session signing secret does not meet the strength requirement")
    for name in ("THREATSCOPE_MFA_ENCRYPTION_KEY", "THREATSCOPE_CONNECTOR_SECRETS_KEY"):
        try:
            Fernet(config.secrets[name].encode("ascii"))
        except (ValueError, TypeError):
            errors.append(f"{name}_FILE does not contain a structurally valid Fernet key")
    if _bool("THREATSCOPE_REQUIRE_BACKUP_ENCRYPTION", False):
        try:
            Fernet(config.secrets["THREATSCOPE_BACKUP_ENCRYPTION_KEY"].encode("ascii"))
        except (ValueError, TypeError):
            errors.append("THREATSCOPE_BACKUP_ENCRYPTION_KEY_FILE does not contain a structurally valid Fernet key")
    if errors:
        raise ConfigurationError("Unsafe production configuration: " + "; ".join(dict.fromkeys(errors)))


def get_runtime_config() -> RuntimeConfig:
    profile_name = _raw("THREATSCOPE_PROFILE", _raw("THREATSCOPE_ENV", "development")).casefold()
    try:
        profile = RuntimeProfile(profile_name)
    except ValueError as exc:
        raise ConfigurationError("THREATSCOPE_PROFILE must be development, test, or production") from exc
    production = profile is RuntimeProfile.PRODUCTION
    try:
        secret_values, secret_statuses = load_application_secrets(production=production)
    except SecretLoadError as exc:
        raise ConfigurationError(str(exc)) from exc
    runtime_default = "/var/lib/threatscope/runtime" if production else "./runtime"
    runtime_dir = _directory("THREATSCOPE_RUNTIME_DIR", runtime_default)
    data_dir = _directory("THREATSCOPE_DATA_DIR", str(runtime_dir / "data"))
    info = version_info()
    registration_mode = _raw("THREATSCOPE_REGISTRATION_MODE", "disabled" if production else "auto_activate_limited")
    public_registration = _bool("THREATSCOPE_SELF_REGISTRATION_ENABLED", not production) and registration_mode != "disabled"
    config = RuntimeConfig(
        profile=profile,
        debug=_bool("THREATSCOPE_DEBUG", False),
        reload=_bool("THREATSCOPE_RELOAD", False),
        allowed_hosts=_items("THREATSCOPE_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver" if not production else ""),
        allowed_origins=_items("THREATSCOPE_ALLOWED_ORIGINS", "http://localhost:5173" if not production else ""),
        trusted_proxy_networks=_items("THREATSCOPE_TRUSTED_PROXY_NETWORKS", "127.0.0.1/32" if not production else ""),
        cookie_secure=_bool("THREATSCOPE_COOKIE_SECURE", production),
        cookie_samesite=_raw("THREATSCOPE_COOKIE_SAMESITE", "lax").casefold(),
        session_hours=_integer("THREATSCOPE_SESSION_HOURS", 8, 1, 24 if production else 168),
        idle_minutes=_integer("THREATSCOPE_IDLE_MINUTES", 30, 5, 240 if production else 1440),
        csrf_enabled=_bool("THREATSCOPE_CSRF_ENABLED", True),
        database_url=_raw("DATABASE_URL", "sqlite:///./vulnscope.db"),
        data_dir=data_dir,
        upload_dir=_directory("THREATSCOPE_UPLOAD_DIR", str(runtime_dir / "uploads")),
        backup_dir=_directory("THREATSCOPE_BACKUP_DIR", str(runtime_dir / "backups")),
        report_dir=_directory("THREATSCOPE_REPORT_DIR", str(runtime_dir / "reports")),
        runtime_dir=runtime_dir,
        export_dir=_directory("THREATSCOPE_EXPORT_DIR", str(runtime_dir / "exports")),
        release_dir=_directory("THREATSCOPE_RELEASE_DIR", str(runtime_dir / "releases")),
        log_level=_raw("THREATSCOPE_LOG_LEVEL", "INFO").upper(),
        json_logging=_bool("THREATSCOPE_JSON_LOGS", production),
        max_request_bytes=_integer("THREATSCOPE_MAX_REQUEST_BYTES", 10_485_760, 1_024, 52_428_800),
        max_upload_bytes=_integer("THREATSCOPE_MAX_UPLOAD_BYTES", 10_485_760, 1_024, 26_214_400),
        request_timeout_seconds=_integer("THREATSCOPE_REQUEST_TIMEOUT_SECONDS", 30, 1, 120),
        graceful_shutdown_seconds=_integer("THREATSCOPE_GRACEFUL_SHUTDOWN_SECONDS", 30, 5, 120),
        worker_count=_integer("THREATSCOPE_WORKERS", 1, 1, 32),
        public_registration=public_registration,
        registration_acknowledged=_bool("THREATSCOPE_PUBLIC_REGISTRATION_ACKNOWLEDGED", False),
        demo_seed=_bool("THREATSCOPE_DEMO_MODE", False),
        api_docs=_bool("THREATSCOPE_API_DOCS", not production),
        connector_egress_enabled=_bool("THREATSCOPE_CONNECTOR_EGRESS_ENABLED", False),
        tls_proxy_expected=_bool("THREATSCOPE_TLS_PROXY_EXPECTED", production),
        schema_identifier=_raw("THREATSCOPE_SCHEMA_IDENTIFIER", SCHEMA_IDENTIFIER),
        application_version=_raw("THREATSCOPE_APP_VERSION", info["version"]),
        source_revision=_raw("THREATSCOPE_BUILD_COMMIT", info["commit_hash"]),
        build_timestamp=_raw("THREATSCOPE_BUILD_TIMESTAMP", info["build_timestamp"]),
        frontend_build_id=_raw("THREATSCOPE_FRONTEND_BUILD_ID", "development"),
        backend_build_id=_raw("THREATSCOPE_BACKEND_BUILD_ID", "development"),
        minimum_free_bytes=_integer("THREATSCOPE_MINIMUM_FREE_BYTES", 268_435_456, 16_777_216, 1_099_511_627_776),
        tls_certificate_file=_raw("THREATSCOPE_TLS_CERTIFICATE_FILE"),
        tls_private_key_file=_raw("THREATSCOPE_TLS_PRIVATE_KEY_FILE"),
        secrets=secret_values,
        secret_statuses=secret_statuses,
    )
    if production:
        _validate_production(config)
    return config
