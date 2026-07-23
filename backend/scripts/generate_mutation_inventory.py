"""Generate the authenticated mutation/CSRF inventory from FastAPI routes."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from fastapi.routing import APIRoute

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DATABASE_URL", "sqlite://")

from app.main import app


MUTATIONS = {"POST", "PUT", "PATCH", "DELETE"}
INTENTIONAL_EXCEPTIONS = {
    ("POST", "/api/auth/login"): "Pre-authentication login; rate limit/account lockout applies",
    ("POST", "/api/auth/register"): "Pre-authentication registration; runtime registration policy/rate controls apply",
    ("POST", "/api/auth/mfa/verify-login"): "Pre-session MFA challenge; bounded signed challenge and failure controls apply",
    ("POST", "/api/integrations/inbound/{endpoint_uuid}"): "No browser session; endpoint secret signature, replay, size, rate, and quarantine controls apply",
}


def dependency_names(dependant) -> set[str]:
    names: set[str] = set()
    for dependency in dependant.dependencies:
        names.add(getattr(dependency.call, "__name__", type(dependency.call).__name__))
        names.update(dependency_names(dependency))
    return names


def render() -> str:
    rows = []
    counts = {"central": 0, "explicit": 0, "exception": 0}
    unknown = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted((route.methods or set()) & MUTATIONS):
            dependencies = dependency_names(route.dependant)
            if "authorize_platform_request" in dependencies:
                coverage = "Central authenticated session + permission + CSRF + audit"
                counts["central"] += 1
            elif "require_authenticated_csrf" in dependencies:
                coverage = "Explicit authenticated session + CSRF (permission dependency is route-owned)"
                counts["explicit"] += 1
            elif (method, route.path) in INTENTIONAL_EXCEPTIONS:
                coverage = INTENTIONAL_EXCEPTIONS[(method, route.path)]
                counts["exception"] += 1
            else:
                coverage = "UNCLASSIFIED"
                unknown.append(f"{method} {route.path}")
            rows.append((route.path, method, coverage))
    if unknown:
        raise RuntimeError("Unclassified mutation routes: " + ", ".join(unknown))
    rows.sort()
    lines = [
        "# CSRF mutation inventory",
        "",
        "Generated from the registered FastAPI route/dependency graph. GET/HEAD/OPTIONS routes are excluded. Central coverage validates CSRF only for authenticated browser mutations after session and permission checks; the four intentional non-session exceptions use the controls stated below.",
        "",
        f"Total mutation routes: {len(rows)}. Central coverage: {counts['central']}. Explicit authenticated CSRF coverage: {counts['explicit']}. Intentional non-session exceptions: {counts['exception']}. Unclassified: 0.",
        "",
        "| Method | Route | Coverage |",
        "| --- | --- | --- |",
    ]
    lines.extend(f"| {method} | `{path}` | {coverage} |" for path, method, coverage in rows)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = repository / "docs" / "CSRF_MUTATION_INVENTORY.md"
    content = render()
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != content:
            raise SystemExit("CSRF mutation inventory is out of date")
        print("CSRF mutation inventory is current")
        return 0
    output.write_text(content, encoding="utf-8")
    print(f"Wrote {output.relative_to(repository).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
