from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deterministic-input ThreatScope release manifest.")
    parser.add_argument("--output", default="release-manifests/phase19.json")
    parser.add_argument("--test-summary", default="operator-verified")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = (repository / args.output).resolve()
    if output.parent != (repository / "release-manifests").resolve():
        raise SystemExit("Manifest output must be inside release-manifests")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
    files = ["backend/requirements.txt", "frontend/package-lock.json", "backend/Dockerfile.production", "deploy/nginx/Dockerfile", "docker-compose.production.yml", "deploy/nginx/nginx.conf.template"]
    payload = {
        "format": "threatscope-release-manifest-v1",
        "application_version": (repository / "VERSION").read_text(encoding="utf-8").strip(),
        "schema_identifier": "threatscope-schema-v19",
        "git_revision": revision,
        "frontend_build_identifier": f"frontend-{revision[:12]}",
        "backend_build_identifier": f"backend-{revision[:12]}",
        "artifact_hashes": {name: digest(repository / name) for name in files},
        "test_summary_reference": args.test_summary[:120],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(output.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
