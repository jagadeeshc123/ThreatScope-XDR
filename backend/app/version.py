import os
from datetime import datetime, timezone
from pathlib import Path

APPLICATION_NAME = "ThreatScope XDR"
SCHEMA_IDENTIFIER = "threatscope-schema-v13"
BACKUP_MANIFEST_VERSION = "1"
EXPORT_MANIFEST_VERSION = "1"


def _version_file() -> Path:
    return Path(__file__).resolve().parents[2] / "VERSION"


def version_info() -> dict[str, str]:
    try:
        file_version = _version_file().read_text(encoding="utf-8").strip()
    except OSError:
        file_version = "1.0.0-rc1"
    return {
        "application_name": APPLICATION_NAME,
        "version": os.getenv("THREATSCOPE_APP_VERSION", file_version)[:40],
        "commit_hash": os.getenv("THREATSCOPE_BUILD_COMMIT", "development")[:64],
        "build_timestamp": os.getenv("THREATSCOPE_BUILD_TIMESTAMP", "local-development")[:64],
        "schema_identifier": SCHEMA_IDENTIFIER,
        "frontend_version": "0.0.0",
        "supported_export_manifest_version": EXPORT_MANIFEST_VERSION,
        "supported_backup_manifest_version": BACKUP_MANIFEST_VERSION,
    }


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
