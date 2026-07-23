"""Generate the reviewed permission matrix from server-owned definitions."""
from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    rules = repository / "backend" / "app" / "modules" / "access_control" / "rules"
    permissions = json.loads((rules / "permissions.json").read_text(encoding="utf-8"))
    roles = json.loads((rules / "default_roles.json").read_text(encoding="utf-8"))
    high_risk_tokens = ("manage", "delete", "execute", "restore", "backup", "import", "export", "activate", "credentials", "policy", "run", "generate")
    lines = [
        "# Permissions matrix",
        "",
        "Generated from the server-owned `permissions.json` and `default_roles.json` definitions. Administrator has the server-owned `*` wildcard; the other columns show explicit defaults. Frontend visibility is convenience only; the backend is authoritative.",
        "",
        "| Permission | Description | Category | Administrator | Security Analyst | Auditor | Executive Viewer | Registered User | High-risk mutation/export |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    role_order = ("administrator", "security_analyst", "auditor", "executive_viewer", "registered_user")
    for identifier, description, category in permissions:
        assignments = []
        for role_key in role_order:
            defaults = roles[role_key]["permissions"]
            assignments.append("Yes" if "*" in defaults or identifier in defaults else "—")
        high_risk = "Yes" if any(token in identifier for token in high_risk_tokens) else "—"
        lines.append(f"| `{identifier}` | {description} | {category} | " + " | ".join(assignments) + f" | {high_risk} |")
    lines.extend([
        "",
        "## Review rules",
        "",
        "Role changes require `roles:manage`; account changes require `users:manage`; production operations, connector credentials/network policy, restore, SOAR execution, analytics policy, and exports require their specific server-owned permission. Mutating authenticated requests additionally require a valid CSRF token. Default mappings are seed defaults, not a substitute for reviewing effective permissions in a deployed database.",
        "",
        f"Permission count: {len(permissions)}. Default role count: {len(roles)}.",
    ])
    output = repository / "docs" / "PERMISSIONS_MATRIX.md"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {output.relative_to(repository).as_posix()} with {len(permissions)} permissions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
