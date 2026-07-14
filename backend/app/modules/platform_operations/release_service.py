import hashlib
import json
import os
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from app.version import APPLICATION_NAME, utc_iso, version_info

from .backup_service import safe_path, sha256_file
from .configuration_service import get_operations_config
from .inventory_service import generate_inventory, project_root
from .maintenance_service import add_activity, new_key, notify
from .models import ReleaseArtifact, utcnow

INCLUDE_ROOTS = {"backend", "frontend", "docs", "test-target", "demo-target", ".github"}
ROOT_FILES = {"VERSION", "docker-compose.yml", ".env.example", ".gitignore", "README.md", "PROJECT_OVERVIEW.md"}
EXCLUDED_PARTS = {".git", "references", "runtime", "backups", "exports", "releases", "reports", "uploads", "node_modules", "dist", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".idea", ".vscode", "coverage", "htmlcov", "Myfiles"}
EXCLUDED_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pyc", ".pyo", ".log", ".pem", ".key", ".p12", ".pfx", ".coverage"}


def git_state(root: Path) -> tuple[str, bool]:
    commit = os.getenv("THREATSCOPE_BUILD_COMMIT", "").strip()
    if not commit:
        try:
            head = (root / ".git" / "HEAD").read_text(encoding="ascii").strip()
            if head.startswith("ref: "):
                commit = (root / ".git" / head[5:]).read_text(encoding="ascii").strip()
            else:
                commit = head
        except OSError:
            commit = "development"
    # Builds cannot safely infer index state without invoking Git. Local API builds
    # therefore require explicit allow_dirty and are marked dirty unless CI supplies false.
    dirty = os.getenv("THREATSCOPE_BUILD_DIRTY", "true").strip().lower() not in {"0", "false", "no"}
    return commit[:64], dirty


def approved_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink(): continue
        rel = path.relative_to(root); parts = set(rel.parts)
        if rel.parts[0] not in INCLUDE_ROOTS and rel.as_posix() not in ROOT_FILES: continue
        if parts & EXCLUDED_PARTS or path.suffix.lower() in EXCLUDED_SUFFIXES or path.name == ".env": continue
        if any(part.startswith(".") and part not in {".github"} for part in rel.parts[1:]): continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def build_release(db: Session | None = None, user_id: int | None = None, allow_dirty: bool = False) -> tuple[dict, Path]:
    root = project_root(); cfg = get_operations_config(True); commit, dirty = git_state(root)
    if dirty and not allow_dirty: raise ValueError("Working tree is dirty; use explicit allow-dirty only for a marked local candidate")
    inventory = generate_inventory(); inventory_bytes = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    key = new_key("release"); filename = f"threatscope-xdr-{version_info()['version']}-{key}.zip"; path = safe_path(cfg.release_dir, filename)
    files = approved_files(root)
    suspicious_markers = (b"-----BEGIN " + b"PRIVATE KEY-----", b"-----BEGIN RSA " + b"PRIVATE KEY-----", b"AWS_SECRET_" + b"ACCESS_KEY=")
    for source in files:
        if source.stat().st_size <= 2_000_000 and any(marker in source.read_bytes() for marker in suspicious_markers):
            raise ValueError(f"Suspicious secret material detected in approved file {source.relative_to(root).as_posix()}")
    manifest = {"manifest_version": "1", "product_name": APPLICATION_NAME, "product_version": version_info()["version"], "commit_hash": commit, "build_timestamp": utc_iso(), "dirty_working_tree": dirty, "included_file_count": len(files) + 2, "excluded_categories": sorted(EXCLUDED_PARTS | {"secrets", "databases", "private_keys", "runtime_data"}), "release_artifact_sha256": "provided in adjacent .sha256 file and operational record", "dependency_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(), "backend_test_summary_reference": "docs/RELEASE_GUIDE.md", "frontend_verification_summary_reference": "docs/RELEASE_GUIDE.md", "known_limitations": ["Release candidate; not production-certified, externally audited, or claimed vulnerability-free."]}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in files:
            rel = source.relative_to(root).as_posix(); info = zipfile.ZipInfo(rel, (1980,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o644<<16; archive.writestr(info, source.read_bytes())
        for name, content in (("release/inventory.json", inventory_bytes), ("release/manifest.json", manifest_bytes)):
            info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o644<<16;archive.writestr(info,content)
    digest = sha256_file(path); (path.with_suffix(path.suffix + ".sha256")).write_text(f"{digest}  {filename}\n", encoding="ascii")
    result = {**manifest, "filename": filename, "size_bytes": path.stat().st_size, "sha256": digest, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "release_key": key, "status": "verified"}
    if db:
        item = ReleaseArtifact(release_key=key, version=version_info()["version"], commit_hash=commit, filename=filename, relative_path=filename, size_bytes=path.stat().st_size, sha256=digest, manifest_sha256=result["manifest_sha256"], status="verified", created_by_user_id=user_id)
        db.add(item); db.flush(); add_activity(db,"release_built",f"Release candidate {key} built locally.","operational_release",item.id);notify(db,"Release build succeeded",f"Release candidate {key} is ready.","success","operational_release",item.id);db.commit();db.refresh(item);result["id"]=item.id
    return result, path
