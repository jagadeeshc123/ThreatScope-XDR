import importlib.metadata
import json
import re
from pathlib import Path

from app.version import utc_iso, version_info

from .configuration_service import get_operations_config


def project_root() -> Path:
    source = Path(__file__).resolve()
    # Development checkouts resolve to ``<repo>/backend/app/...`` while the
    # backend image copies the package to ``/app/app/...``.  Pick the first
    # ancestor that contains the application source tree so inventory and
    # release metadata work in both layouts.
    for candidate in (source.parents[4], source.parents[3], source.parents[2]):
        if (candidate / "backend" / "app" / "modules").is_dir():
            return candidate
        if (candidate / "app" / "modules").is_dir():
            return candidate
    return source.parents[3]


def generate_inventory() -> dict:
    root = project_root(); components = []
    requirements = root / "backend" / "requirements.txt"
    if not requirements.exists():
        requirements = root / "requirements.txt"
    if requirements.exists():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            if "==" in line and not line.lstrip().startswith("#"):
                name, version = line.strip().split("==", 1); components.append({"name": name, "version": version, "ecosystem": "PyPI", "classification": "direct", "source_file": "backend/requirements.txt"})
    package = root / "frontend" / "package.json"
    if package.exists():
        data = json.loads(package.read_text(encoding="utf-8"))
        for group, classification in (("dependencies", "direct"), ("devDependencies", "development")):
            for name, version in sorted(data.get(group, {}).items()): components.append({"name": name, "version": version, "ecosystem": "npm", "classification": classification, "source_file": "frontend/package.json"})
    lock = root / "frontend" / "package-lock.json"
    if lock.exists():
        lock_data = json.loads(lock.read_text(encoding="utf-8"))
        direct_names = {item["name"] for item in components if item["ecosystem"] == "npm"}
        for path_key, metadata in sorted(lock_data.get("packages", {}).items()):
            if not path_key.startswith("node_modules/") or not metadata.get("version"): continue
            name = path_key.split("node_modules/")[-1]
            if name not in direct_names: components.append({"name": name, "version": str(metadata["version"]), "ecosystem": "npm", "classification": "transitive", "source_file": "frontend/package-lock.json"})
    dockerfiles = sorted(root.glob("*/Dockerfile"))
    for file in dockerfiles:
        for match in re.findall(r"^FROM\s+([^\s]+)", file.read_text(encoding="utf-8"), re.M | re.I): components.append({"name": match.split(":")[0], "version": match.split(":", 1)[1] if ":" in match else "unspecified", "ecosystem": "container", "classification": "base-image", "source_file": file.relative_to(root).as_posix()})
    modules_root = root / "backend" / "app" / "modules"
    if not modules_root.is_dir():
        modules_root = root / "app" / "modules"
    for module in sorted(modules_root.iterdir()):
        if module.is_dir() and (module / "__init__.py").exists(): components.append({"name": module.name, "version": version_info()["version"], "ecosystem": "ThreatScope module", "classification": "application", "source_file": "backend/app/modules"})
    pinned = {item["name"].lower().replace("_","-") for item in components if item["ecosystem"] == "PyPI"}
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata.get("Name") or "unknown")[:160]
        if name.lower().replace("_","-") in pinned: continue
        item = {"name": name, "version": distribution.version[:80], "ecosystem": "PyPI", "classification": "installed", "source_file": "installed package metadata"}
        license_name = distribution.metadata.get("License")
        if license_name and len(license_name) < 160: item["license"] = license_name
        components.append(item)
    components.sort(key=lambda item: (item["ecosystem"].lower(), item["name"].lower(), item["version"]))
    payload = {"schema": "threatscope-software-inventory-v1", "generated_timestamp": utc_iso(), "application_version": version_info()["version"], "components": components[:2000], "limitations": ["Inventory is based only on local manifests and metadata.", "It is not a vulnerability or license-compliance assessment."]}
    cfg = get_operations_config(True); path = cfg.runtime_dir / "software-inventory.json"; path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def read_inventory() -> dict:
    path = get_operations_config(True).runtime_dir / "software-inventory.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else generate_inventory()


def inventory_path() -> Path:
    read_inventory(); return get_operations_config(True).runtime_dir / "software-inventory.json"
