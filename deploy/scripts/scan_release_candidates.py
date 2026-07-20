"""Scan modified and untracked release candidates without printing file contents."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


def _git(repository: Path, *arguments: str) -> list[str]:
    result = subprocess.run(["git", *arguments], cwd=repository, check=True, capture_output=True, text=True)
    return result.stdout.splitlines()


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    candidates = sorted(set(_git(repository, "diff", "--name-only") + _git(repository, "ls-files", "--others", "--exclude-standard")))
    protected = [name for name in candidates if re.search(r"(^|/)references(/|$)", name.replace("\\", "/"))]
    forbidden_extensions = {".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".zip", ".tar", ".gz", ".bak", ".log", ".map", ".png", ".jpg", ".jpeg"}
    artifacts = [name for name in candidates if Path(name).suffix.casefold() in forbidden_extensions or Path(name).name in {".env", ".env.production"}]
    patterns = (
        re.compile(b"-----BEGIN " + b"PRIVATE KEY-----"),
        re.compile(b"-----BEGIN RSA " + b"PRIVATE KEY-----"),
        re.compile(b"-----BEGIN EC " + b"PRIVATE KEY-----"),
        re.compile(rb"AKIA[0-9A-Z]{16}"),
        re.compile(rb"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}"),
    )
    secret_hits: list[str] = []
    local_paths: list[str] = []
    binary_files: list[str] = []
    conflict_markers: list[str] = []
    for name in candidates:
        path = repository / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            binary_files.append(name)
        windows_home = b"C:" + b"\\Users\\" + b"jagadeesh"
        portable_home = b"C:/" + b"Users/" + b"jagadeesh"
        if windows_home in data or portable_home in data:
            local_paths.append(name)
        if any(pattern.search(data) for pattern in patterns):
            secret_hits.append(name)
        if re.search(rb"(?m)^(?:<{7}|={7}|>{7})(?: |$)", data):
            conflict_markers.append(name)
    failures = {
        "protected_references": protected,
        "forbidden_artifacts": artifacts,
        "secret_patterns": secret_hits,
        "local_paths": local_paths,
        "binary_candidates": binary_files,
        "conflict_markers": conflict_markers,
    }
    if any(failures.values()):
        print(json.dumps({"status": "failed", "candidate_count": len(candidates), "failures": failures}, sort_keys=True))
        return 1
    print(json.dumps({"status": "passed", "candidate_count": len(candidates), "checks": len(failures)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
