import hashlib
import io
import json
import zipfile
from pathlib import Path, PurePosixPath

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.database import engine
from app.version import EXPORT_MANIFEST_VERSION, version_info

from .backup_service import safe_path, sha256_file
from .configuration_service import get_operations_config
from .maintenance_service import add_activity, new_key, notify
from .models import ExportPackage, utcnow
from .redaction import redact

MODULES = {
    "web_exposure": {"permission": "web:read", "tables": {"targets": ["id", "name", "domain", "environment", "created_at"], "scans": ["id", "target_id", "profile", "status", "total_findings", "risk_score", "created_at", "started_at", "completed_at"], "findings": ["id", "scan_id", "target_id", "title", "severity", "category", "description", "impact", "remediation", "confidence", "risk_score", "created_at"]}},
    "api_security": {"permission": "api:read", "tables": {"api_assessments": ["id", "name", "status", "created_at", "updated_at"], "api_findings": ["id", "assessment_id", "title", "severity", "category", "description", "remediation", "created_at"]}},
    "soc_summaries": {"permission": "soc:read", "tables": {"soc_alerts": ["id", "title", "severity", "status", "confidence", "created_at", "updated_at"], "soc_reports": ["id", "title", "created_at"]}},
    "document_threat_summaries": {"permission": "document:read", "tables": {"document_analyses": ["id", "filename_sanitized", "analysis_status", "classification", "risk_score", "created_at", "completed_at"], "document_findings": ["id", "analysis_id", "title", "severity", "category", "description", "remediation", "created_at"]}},
    "phishing_summaries": {"permission": "phishing:read", "tables": {"phishing_analyses": ["id", "source_type", "analysis_status", "classification", "risk_score", "created_at", "completed_at"], "phishing_findings": ["id", "analysis_id", "title", "severity", "category", "description", "remediation", "created_at"]}},
    "correlation": {"permission": "correlation:read", "tables": {"unified_entities": ["id", "entity_key", "entity_type", "display_value", "risk_score", "created_at"], "correlation_matches": ["id", "rule_id", "status", "severity", "confidence", "created_at"]}},
    "incident_cases": {"permission": "cases:read", "tables": {"incident_cases": ["id", "case_key", "title", "severity", "status", "summary", "created_at", "updated_at"]}},
    "governance": {"permission": "governance:read", "tables": {"governance_risks": ["id", "risk_key", "title", "severity", "status", "likelihood", "impact", "created_at", "updated_at"], "governance_reports": ["id", "title", "created_at"]}},
    "reports_metadata": {"permission": "reports:read_all", "tables": {"reports": ["id", "title", "scan_id", "target_id", "created_at"]}},
    "security_audit_metadata": {"permission": "audit:read", "tables": {"security_audit_events": ["id", "sequence_number", "event_type", "action", "resource_type", "outcome", "status_code", "reason_code", "occurred_at", "event_hash"]}},
}
FORBIDDEN_ENTRY_SUFFIXES = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".py", ".js", ".html", ".htm", ".jar", ".zip", ".tar", ".gz", ".7z")


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _rows(db: Session, table: str, allowed: list[str]) -> list[dict]:
    columns = {column["name"] for column in inspect(db.get_bind()).get_columns(table)}
    selected = [name for name in allowed if name in columns]
    if not selected: return []
    quoted = ",".join(f'"{name}"' for name in selected)
    rows = db.execute(text(f'SELECT {quoted} FROM "{table}" ORDER BY id LIMIT 5000')).mappings().all()
    return [redact(dict(row)) for row in rows]


def allowed_modules(permissions: set[str]) -> list[str]:
    return [key for key, value in MODULES.items() if value["permission"] in permissions]


def create_export(db: Session, user_id: int, requested: list[str], permissions: set[str]) -> ExportPackage:
    cfg = get_operations_config(True)
    unique = sorted(set(requested))
    invalid = set(unique) - set(MODULES)
    unauthorized = [name for name in unique if MODULES.get(name, {}).get("permission") not in permissions]
    if invalid or unauthorized: raise PermissionError("One or more export modules are unavailable")
    key = new_key("export"); filename = f"{key}.tsxdr-export.zip"; path = safe_path(cfg.export_dir, filename)
    entries = {}; counts = {}
    for module in unique:
        payload = {"module": module, "records": {}}
        for table, fields in MODULES[module]["tables"].items():
            if table not in inspect(db.get_bind()).get_table_names(): continue
            values = _rows(db, table, fields); payload["records"][table] = values; counts[f"{module}.{table}"] = len(values)
        entries[f"data/{module}.json"] = _canonical(payload)
    manifest = {"manifest_version": EXPORT_MANIFEST_VERSION, "application_version": version_info()["version"], "package_type": "safe_local_json_export", "included_modules": unique, "record_counts": counts, "files": {name: hashlib.sha256(content).hexdigest() for name, content in sorted(entries.items())}, "excluded_categories": ["authentication", "sessions", "credentials", "environment", "original_files", "raw_email", "raw_pdf", "attachments", "raw_logs"], "limitations": ["This package is for validation and analyst-readable transfer; automatic live import is not implemented."]}
    manifest_bytes = _canonical(manifest); entries["manifest.json"] = manifest_bytes
    try:
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(entries.items()):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o600 << 16
                archive.writestr(info, content)
        record = ExportPackage(package_key=key, filename=filename, relative_path=filename, status="verified", size_bytes=path.stat().st_size, sha256=sha256_file(path), manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), included_modules_json=json.dumps(unique), record_counts_json=json.dumps(counts, sort_keys=True), created_by_user_id=user_id, verified_at=utcnow(), verification_status="valid")
        db.add(record); db.flush(); add_activity(db, "export_created", f"Safe export {record.package_key} created.", "operational_export", record.id); notify(db, "Export created", f"Safe export {record.package_key} is ready.", "success", "operational_export", record.id); db.commit(); db.refresh(record); return record
    except Exception:
        path.unlink(missing_ok=True); db.rollback(); raise


def validate_archive(path: Path, expected_sha: str | None = None) -> dict:
    cfg = get_operations_config(True)
    if path.stat().st_size > cfg.max_import_bytes: raise ValueError("Package exceeds configured maximum size")
    if expected_sha and sha256_file(path) != expected_sha: raise ValueError("Package checksum mismatch")
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > 30: raise ValueError("Package contains too many entries")
        names = [item.filename for item in infos]
        for item in infos:
            pure = PurePosixPath(item.filename)
            if pure.is_absolute() or ".." in pure.parts or item.is_dir() or item.filename.lower().endswith(FORBIDDEN_ENTRY_SUFFIXES) or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Package contains an unsafe entry")
            if item.file_size > cfg.max_import_bytes or item.compress_size and item.file_size / item.compress_size > 100:
                raise ValueError("Package entry exceeds safe expansion limits")
        if "manifest.json" not in names: raise ValueError("Package manifest is missing")
        manifest_bytes = archive.read("manifest.json"); manifest = json.loads(manifest_bytes)
        if manifest.get("manifest_version") != EXPORT_MANIFEST_VERSION: raise ValueError("Unsupported export manifest version")
        for name, digest in manifest.get("files", {}).items():
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != digest: raise ValueError("Package content checksum mismatch")
        rejected = sorted(set(names) - {"manifest.json", *manifest.get("files", {}).keys()})
        if rejected: raise ValueError("Package contains unrecognized entries")
    return {"valid": True, "manifest_valid": True, "checksum_valid": True, "package_version": manifest["manifest_version"], "supported_modules": manifest.get("included_modules", []), "record_counts": manifest.get("record_counts", {}), "rejected_fields": [], "compatibility_status": "compatible_for_validation_only", "warnings": [], "limitations": manifest.get("limitations", []) + ["No source records were created or modified."]}


def verify_export(db: Session, record: ExportPackage) -> dict:
    path = safe_path(get_operations_config(True).export_dir, record.relative_path)
    try: result = validate_archive(path, record.sha256); valid = hashlib.sha256(zipfile.ZipFile(path).read("manifest.json")).hexdigest() == record.manifest_sha256
    except Exception: result = {"valid": False}; valid = False
    record.verification_status = "valid" if valid else "invalid"; record.verified_at = utcnow(); record.status = "verified" if valid else "invalid"; db.commit()
    return {**result, "valid": valid}


def delete_export(db: Session, record: ExportPackage):
    safe_path(get_operations_config(True).export_dir, record.relative_path).unlink(missing_ok=True)
    record.deleted_at = utcnow(); record.status = "deleted"; add_activity(db, "export_deleted", f"Export {record.package_key} deleted.", "operational_export", record.id); db.commit()
