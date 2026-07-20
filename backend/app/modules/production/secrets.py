from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_SECRET_BYTES = 65_536


class SecretLoadError(ValueError):
    """A secret reference is unsafe or invalid. Values are never included."""


@dataclass(frozen=True)
class SecretStatus:
    name: str
    configured: bool
    source: str
    permission_warning: bool = False


def _read_only_mount(path: Path) -> bool:
    """Accept permissive-looking Docker Desktop secret modes only on a read-only mount."""
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (AttributeError, OSError):
        return False


def _read_secret_file(name: str, raw_path: str) -> tuple[str, bool]:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise SecretLoadError(f"{name}_FILE must reference an absolute path")
    if path.is_symlink():
        raise SecretLoadError(f"{name}_FILE must not be a symbolic link")
    try:
        info = path.stat()
    except OSError as exc:
        raise SecretLoadError(f"{name}_FILE is unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SecretLoadError(f"{name}_FILE must reference a regular file")
    if info.st_size <= 0:
        raise SecretLoadError(f"{name}_FILE is empty")
    if info.st_size > MAX_SECRET_BYTES:
        raise SecretLoadError(f"{name}_FILE exceeds the safe size limit")
    try:
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as exc:
        raise SecretLoadError(f"{name}_FILE could not be read safely") from exc
    if not value:
        raise SecretLoadError(f"{name}_FILE is empty")
    world_writable = bool(info.st_mode & stat.S_IWOTH)
    if os.name != "nt" and world_writable and not _read_only_mount(path):
        raise SecretLoadError(f"{name}_FILE must not be world-writable")
    return value, world_writable


def load_secret(name: str, *, production: bool, required: bool = False) -> tuple[str, SecretStatus]:
    direct = os.getenv(name)
    file_ref = os.getenv(f"{name}_FILE")
    direct_present = direct is not None and bool(direct.strip())
    file_present = file_ref is not None and bool(file_ref.strip())
    if production and direct_present and file_present:
        raise SecretLoadError(f"{name} and {name}_FILE cannot both be set in production")
    if production and direct_present:
        raise SecretLoadError(f"{name} must use {name}_FILE in production")
    if file_present:
        value, warning = _read_secret_file(name, file_ref.strip())
        return value, SecretStatus(name=name, configured=True, source="file", permission_warning=warning)
    value = direct.strip() if direct_present else ""
    if required and not value:
        source_name = f"{name}_FILE" if production else name
        raise SecretLoadError(f"Required secret reference {source_name} is not configured")
    return value, SecretStatus(name=name, configured=bool(value), source="environment" if value else "none")


def load_application_secrets(*, production: bool) -> tuple[dict[str, str], tuple[SecretStatus, ...]]:
    definitions = (
        ("THREATSCOPE_SESSION_SECRET", production),
        ("THREATSCOPE_MFA_ENCRYPTION_KEY", production),
        ("THREATSCOPE_CONNECTOR_SECRETS_KEY", production),
        ("THREATSCOPE_BACKUP_ENCRYPTION_KEY", False),
        ("THREATSCOPE_PASSWORD_PEPPER", False),
    )
    values: dict[str, str] = {}
    statuses: list[SecretStatus] = []
    for name, required in definitions:
        value, status = load_secret(name, production=production, required=required)
        values[name] = value
        statuses.append(status)
    return values, tuple(statuses)
