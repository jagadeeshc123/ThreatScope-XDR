from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a local dependency inventory (not a formal SBOM).")
    parser.add_argument("--output", default="dependency-inventory/dependencies.json")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = (repository / args.output).resolve()
    allowed = (repository / "dependency-inventory").resolve()
    if output.parent != allowed:
        raise SystemExit("Inventory output must be inside dependency-inventory")
    lock = json.loads((repository / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    npm = []
    for key, value in sorted(lock.get("packages", {}).items()):
        if key and value.get("version"):
            npm.append({"name": value.get("name") or key.removeprefix("node_modules/"), "version": value["version"]})
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
    payload = {
        "format": "threatscope-dependency-inventory-v1",
        "notice": "This inventory is not asserted to conform to SPDX or CycloneDX.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "application_version": (repository / "VERSION").read_text(encoding="utf-8").strip(),
        "schema_identifier": "threatscope-schema-v19",
        "git_revision": revision,
        "python": sorted(({"name": item.metadata["Name"], "version": item.version} for item in importlib.metadata.distributions()), key=lambda item: item["name"].casefold()),
        "npm": npm,
        "container_bases": ["python:3.11.9-slim-bookworm", "node:20.19.4-alpine3.21", "nginx:1.28.0-alpine3.21"],
        "manifest_sha256": {"backend/requirements.txt": sha256(repository / "backend" / "requirements.txt"), "frontend/package-lock.json": sha256(repository / "frontend" / "package-lock.json")},
    }
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(output.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
