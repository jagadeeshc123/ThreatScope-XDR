import os
from dataclasses import dataclass
from pathlib import Path
from cryptography.fernet import Fernet

from app.modules.access_control.config import get_config as get_access_config
from app.modules.production.config import get_runtime_config


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(low, min(high, value))


@dataclass(frozen=True)
class OperationsConfig:
    runtime_dir: Path
    backup_dir: Path
    export_dir: Path
    release_dir: Path
    backup_encryption_key: str
    require_backup_encryption: bool
    max_backup_bytes: int
    max_import_bytes: int
    backup_max_count: int
    backup_max_age_days: int
    backup_min_keep: int
    demo_mode: bool


def get_operations_config(create: bool = False) -> OperationsConfig:
    production = get_runtime_config()
    runtime = production.runtime_dir
    result = OperationsConfig(
        runtime_dir=runtime,
        backup_dir=production.backup_dir,
        export_dir=production.export_dir,
        release_dir=production.release_dir,
        backup_encryption_key=production.secrets["THREATSCOPE_BACKUP_ENCRYPTION_KEY"],
        require_backup_encryption=_bool("THREATSCOPE_REQUIRE_BACKUP_ENCRYPTION", False),
        max_backup_bytes=_int("THREATSCOPE_MAX_BACKUP_BYTES", 2_147_483_648, 1_048_576, 10_737_418_240),
        max_import_bytes=_int("THREATSCOPE_MAX_IMPORT_BYTES", 104_857_600, 1_024, 2_147_483_648),
        backup_max_count=_int("THREATSCOPE_BACKUP_MAX_COUNT", 20, 1, 1000),
        backup_max_age_days=_int("THREATSCOPE_BACKUP_MAX_AGE_DAYS", 90, 1, 3650),
        backup_min_keep=_int("THREATSCOPE_BACKUP_MIN_KEEP", 3, 1, 100),
        demo_mode=_bool("THREATSCOPE_DEMO_MODE", False),
    )
    if create:
        for directory in (result.runtime_dir, result.backup_dir, result.export_dir, result.release_dir):
            directory.mkdir(parents=True, exist_ok=True)
    return result


def _issue(key: str, status: str, summary: str, action: str) -> dict[str, str]:
    return {"setting": key, "status": status, "summary": summary, "recommended_action": action}


def validate_configuration(create_directories: bool = False) -> dict:
    access = get_access_config()
    ops = get_operations_config(create=create_directories)
    production = access.environment == "production"
    issues = []
    issues.append(_issue("authentication_mode", "valid" if access.enabled else "invalid", "Authentication is enabled." if access.enabled else "Authentication is disabled.", "Keep local authentication enabled."))
    secret_valid = len(access.session_secret) >= 32 and len(set(access.session_secret)) >= 12
    issues.append(_issue("session_secret", "valid" if secret_valid else ("invalid" if production else "degraded"), "Session signing material meets the configured environment requirement." if secret_valid else "Session signing material does not meet the length and entropy minimum.", "Generate at least 32 random characters outside the repository."))
    try:
        if access.mfa_encryption_key: Fernet(access.mfa_encryption_key.encode("ascii"))
        mfa_valid = True
    except (ValueError, TypeError):
        mfa_valid = False
    issues.append(_issue("mfa_encryption_key", "valid" if mfa_valid else "invalid", "MFA key configuration format is acceptable." if mfa_valid else "MFA key material is too short.", "Configure a Fernet key or at least 32 characters of random material."))
    cookie_valid = access.cookie_secure or not production
    issues.append(_issue("cookie_secure", "valid" if cookie_valid else "invalid", "Cookie transport policy matches runtime mode." if cookie_valid else "Production cookies are not marked secure.", "Enable THREATSCOPE_COOKIE_SECURE."))
    cors_valid = bool(access.allowed_origins) and "*" not in access.allowed_origins
    issues.append(_issue("allowed_origins", "valid" if cors_valid else "invalid", "Origins are explicitly constrained." if cors_valid else "Wildcard or empty origins are not allowed.", "Set explicit trusted local origins."))
    encrypted = bool(ops.backup_encryption_key)
    try:
        if encrypted: Fernet(ops.backup_encryption_key.encode("ascii"))
        backup_key_valid = True
    except (ValueError, TypeError):
        backup_key_valid = False
    encryption_status = "valid" if backup_key_valid and encrypted else ("degraded" if backup_key_valid and not (production or ops.require_backup_encryption) else "invalid")
    issues.append(_issue("backup_encryption", encryption_status, "Backup encryption is configured." if encrypted else "Backups are unencrypted; this is permitted only for development.", "Configure THREATSCOPE_BACKUP_ENCRYPTION_KEY before production backups."))
    for name, directory in (("runtime_directory", ops.runtime_dir), ("backup_directory", ops.backup_dir), ("export_directory", ops.export_dir), ("release_directory", ops.release_dir)):
        accessible = directory.exists() and directory.is_dir()
        issues.append(_issue(name, "valid" if accessible else "invalid", "Configured directory is accessible." if accessible else "Configured directory is not accessible.", "Create the local directory with restrictive permissions."))
    issues.extend([
        _issue("session_lifetime", "valid", "Session lifetime is bounded.", "Review local policy periodically."),
        _issue("idle_timeout", "valid", "Idle timeout is bounded.", "Review local policy periodically."),
        _issue("login_limits", "valid", "Login rate limits are bounded.", "Review local policy periodically."),
        _issue("retention_limits", "valid", "Backup retention values are bounded.", "Preview every retention run before apply."),
        _issue("maximum_backup_size", "valid", "Maximum backup size is bounded.", "Increase only after local capacity review."),
        _issue("maximum_import_size", "valid", "Maximum import size is bounded.", "Increase only after local capacity review."),
    ])
    invalid = sum(item["status"] == "invalid" for item in issues)
    degraded = sum(item["status"] == "degraded" for item in issues)
    return {"valid": invalid == 0, "status": "invalid" if invalid else ("degraded" if degraded else "valid"), "environment": access.environment, "invalid_count": invalid, "degraded_count": degraded, "settings": issues}
