"""Generate SHA-256 checksums for the reviewed source release inputs."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


RELEASE_INPUTS = (
    "VERSION",
    "README.md",
    "backend/requirements.txt",
    "frontend/package-lock.json",
    "backend/Dockerfile.production",
    "deploy/nginx/Dockerfile",
    "docker-compose.production.yml",
    "deploy/nginx/nginx.conf.template",
    "deploy/nginx/proxy-common.conf",
    "deploy/nginx/security-headers.conf",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic ThreatScope release-input checksums.")
    parser.add_argument("--output", default="release-manifests/v1.0.0.sha256")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = (repository / args.output).resolve()
    if output.parent != (repository / "release-manifests").resolve():
        raise SystemExit("Checksum output must be inside release-manifests")
    rows = []
    for relative in sorted(RELEASE_INPUTS):
        digest = hashlib.sha256((repository / relative).read_bytes()).hexdigest()
        rows.append(f"{digest}  {relative}")
    output.parent.mkdir(exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(output.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
