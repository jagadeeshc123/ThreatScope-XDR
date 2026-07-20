"""Run a destructive, localhost-only production acceptance drill against the smoke stack.

The generated project and volumes must be dedicated to Phase 19. Credentials are random,
kept in process memory, never printed, and destroyed with the smoke volumes afterward.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import time
import warnings
from pathlib import Path

import httpx


PROJECT = "threatscope-phase19-smoke"
COMPOSE_FILES = ("docker-compose.production.yml", "docker-compose.production-smoke.yml")


def _environment(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _compose(repository: Path, env_file: Path, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    command = ["docker", "compose", "--env-file", str(env_file), "-p", PROJECT]
    for filename in COMPOSE_FILES:
        command.extend(("-f", filename))
    command.extend(arguments)
    return subprocess.run(command, cwd=repository, input=input_text, text=True, capture_output=True)


def _require(response: httpx.Response, status: int, label: str) -> httpx.Response:
    if response.status_code != status:
        raise RuntimeError(f"{label} returned HTTP {response.status_code}, expected {status}")
    return response


def _login(base: str, certificate: str, username: str, password: str) -> tuple[httpx.Client, str, httpx.Response]:
    client = httpx.Client(base_url=base, verify=certificate, timeout=20, follow_redirects=False)
    login = _require(client.post("/api/auth/login", json={"identifier": username, "password": password}), 200, f"login for {username}")
    token = _require(client.get("/api/auth/csrf"), 200, "CSRF token").json()["csrf_token"]
    return client, token, login


def _tls_handshake(host: str, port: int, certificate: str, minimum: ssl.TLSVersion, maximum: ssl.TLSVersion, server_name: str = "localhost") -> str:
    context = ssl.create_default_context(cafile=certificate)
    context.minimum_version = minimum
    context.maximum_version = maximum
    with socket.create_connection((host, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as secured:
            return secured.version() or "unknown"


def _route_inventory(repository: Path, client: httpx.Client) -> int:
    source = (repository / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    routes = sorted(set(re.findall(r'<Route\s+path="([^"]+)"', source)))
    for route in routes:
        candidate = re.sub(r":[A-Za-z][A-Za-z0-9_]*", "1", route)
        response = client.get(candidate)
        if response.status_code != 200 or '<div id="root"></div>' not in response.text:
            raise RuntimeError(f"SPA route failed: {candidate} ({response.status_code})")
    return len(routes)


def _wait_https(base: str, certificate: str, seconds: int = 75) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if httpx.get(base + "/api/health/live", verify=certificate, timeout=3).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError("HTTPS edge did not become ready")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Phase 19 HTTPS production acceptance drill")
    parser.add_argument("--env-file", default=".runtime/phase19-smoke/smoke.env")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    env_file = (repository / args.env_file).resolve()
    env = _environment(env_file)
    cert = env["THREATSCOPE_TLS_CERTIFICATE_HOST_FILE"]
    https_port = int(env["THREATSCOPE_HTTPS_PORT"])
    http_port = int(env["THREATSCOPE_HTTP_PORT"])
    base = f"https://localhost:{https_port}"
    _wait_https(base, cert)

    admin_username = "phase19_owner"
    admin_password = "TsX!9a" + secrets.token_urlsafe(24)
    bootstrap_code = (
        "import json,sys; from app import models; from app.database import Base,SessionLocal,engine; "
        "from app.modules.access_control.models import UserAccount; "
        "from app.modules.access_control.role_service import seed_roles_and_permissions; "
        "from app.modules.access_control.user_service import create_user; "
        "data=json.loads(sys.stdin.read()); Base.metadata.create_all(bind=engine); db=SessionLocal(); "
        "seed_roles_and_permissions(db); "
        "assert db.query(UserAccount).count()==0, 'smoke database must start empty'; "
        "create_user(db,username=data['username'],display_name='Phase 19 Owner',email=None,password=data['password'],"
        "role_keys=['administrator'],must_change_password=False,is_system_admin=True); db.close()"
    )
    bootstrap = _compose(
        repository, env_file, "exec", "-T", "backend", "python", "-c", bootstrap_code,
        input_text=json.dumps({"username": admin_username, "password": admin_password}),
    )
    if bootstrap.returncode:
        raise RuntimeError("Interactive administrator bootstrap failed")

    anonymous = httpx.Client(base_url=base, verify=cert, timeout=20, follow_redirects=False)
    _require(anonymous.get("/api/health/live"), 200, "public liveness")
    _require(anonymous.get("/api/health/ready"), 200, "public readiness")
    _require(anonymous.get("/api/operations/health/details"), 401, "protected detailed health")
    for path in ("/docs", "/redoc", "/openapi.json", "/.env", "/package.json", "/assets/main.js.map"):
        _require(anonymous.get(path), 404, f"blocked production path {path}")
    _require(anonymous.get("/", headers={"Host": "deceptive.example"}), 421, "unknown host")
    redirect = httpx.get(f"http://localhost:{http_port}/login", follow_redirects=False, timeout=10)
    _require(redirect, 308, "HTTP-to-HTTPS redirect")

    tls12 = _tls_handshake("127.0.0.1", https_port, cert, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    tls13 = _tls_handshake("127.0.0.1", https_port, cert, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            _tls_handshake("127.0.0.1", https_port, cert, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
            raise RuntimeError("legacy TLS unexpectedly succeeded")
        except (ssl.SSLError, OSError):
            pass
    try:
        _tls_handshake("127.0.0.1", https_port, cert, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, "invalid.example")
        raise RuntimeError("invalid TLS hostname unexpectedly succeeded")
    except ssl.SSLCertVerificationError:
        pass

    admin, csrf, login = _login(base, cert, admin_username, admin_password)
    cookie = login.headers.get("set-cookie", "").casefold()
    for requirement in ("secure", "httponly", "samesite=lax"):
        if requirement not in cookie:
            raise RuntimeError(f"session cookie is missing {requirement}")
    root_response = _require(admin.get("/"), 200, "production frontend")
    required_headers = (
        "content-security-policy", "strict-transport-security", "x-content-type-options",
        "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-resource-policy", "x-frame-options",
    )
    missing_headers = [name for name in required_headers if name not in root_response.headers]
    if missing_headers:
        raise RuntimeError("security headers missing: " + ", ".join(missing_headers))
    if "no-store" not in _require(admin.get("/api/auth/me"), 200, "authenticated identity").headers.get("cache-control", ""):
        raise RuntimeError("authenticated API response is cacheable")
    _require(admin.get("/api/auth/providers"), 200, "auth providers")
    if admin.get("/api/auth/providers").json()["self_registration_enabled"]:
        raise RuntimeError("self-registration is enabled")
    registration = {"email": "disabled@example.test", "username": "disabled_user", "display_name": "Disabled User", "password": admin_password, "password_confirmation": admin_password, "terms_accepted": True, "privacy_notice_version": "2025-01"}
    _require(admin.post("/api/auth/register", json=registration), 403, "disabled registration")

    for path in ("/api/dashboard/summary", "/api/targets/", "/api/notifications/", "/api/operations", "/api/operations/production/readiness", "/api/operations/production/build-info", "/api/operations/production/security-posture", "/api/analytics/catalog/features"):
        _require(admin.get(path), 200, f"authenticated module {path}")
    _require(admin.post("/api/operations/production/preflight"), 403, "missing CSRF")
    _require(admin.post("/api/operations/production/preflight", headers={"X-CSRF-Token": "invalid-token"}), 403, "invalid CSRF")
    _require(admin.get("/api/auth/me"), 200, "session after CSRF failure")
    preflight = _require(admin.post("/api/operations/production/preflight", headers={"X-CSRF-Token": csrf}), 200, "active preflight").json()
    if not preflight.get("ready") or preflight.get("failure_count"):
        raise RuntimeError("active production preflight is not ready")

    target = _require(admin.post("/api/targets/", headers={"X-CSRF-Token": csrf}, json={"name": "Phase 19 Persistence", "base_url": "https://example.test", "environment": "synthetic", "authorization_confirmed": True}), 200, "create synthetic target").json()
    target_id = target["id"]

    role_passwords: dict[str, tuple[str, str]] = {}
    for index, role in enumerate(("security_analyst", "auditor", "executive_viewer", "registered_user"), start=1):
        password = "TsX!8b" + secrets.token_urlsafe(22)
        username = f"phase19_{role}"
        created = _require(admin.post("/api/admin/users", headers={"X-CSRF-Token": csrf}, json={"username": username, "display_name": f"Phase 19 Role {index}", "temporary_password": password, "role_keys": [role], "is_system_admin": False}), 200, f"create {role}").json()
        user_id = created["user"]["id"]
        _require(admin.patch(f"/api/admin/users/{user_id}", headers={"X-CSRF-Token": csrf}, json={"must_change_password": False}), 200, f"activate {role}")
        role_passwords[role] = (username, password)

    matrix = {
        "security_analyst": (200, 200, 403),
        "auditor": (200, 200, 403),
        "executive_viewer": (403, 403, 403),
        "registered_user": (403, 403, 403),
    }
    for role, (readiness_status, posture_status, preflight_status) in matrix.items():
        username, password = role_passwords[role]
        role_client, role_csrf, _ = _login(base, cert, username, password)
        _require(role_client.get("/api/operations/production/readiness"), readiness_status, f"{role} readiness")
        _require(role_client.get("/api/operations/production/security-posture"), posture_status, f"{role} posture")
        _require(role_client.post("/api/operations/production/preflight", headers={"X-CSRF-Token": role_csrf}), preflight_status, f"{role} active preflight")
        _require(role_client.get("/api/dashboard/summary"), 200, f"{role} dashboard")
        _require(role_client.post("/api/auth/logout", headers={"X-CSRF-Token": role_csrf}), 200, f"{role} logout")
        role_client.close()

    route_count = _route_inventory(repository, admin)
    restart = _compose(repository, env_file, "restart", "backend")
    if restart.returncode:
        raise RuntimeError("backend restart failed")
    _wait_https(base, cert)
    _require(admin.get("/api/auth/me"), 200, "persisted session after restart")
    persisted = _require(admin.get(f"/api/targets/{target_id}"), 200, "persisted target after restart").json()
    if persisted["name"] != "Phase 19 Persistence":
        raise RuntimeError("persistent target changed during restart")

    csrf = _require(admin.get("/api/auth/csrf"), 200, "rotated CSRF").json()["csrf_token"]
    backup = _require(admin.post("/api/operations/backups/database", headers={"X-CSRF-Token": csrf}, json={"backup_type": "database"}), 200, "database backup").json()["backup"]
    backup_id = backup["id"]
    verified = _require(admin.post(f"/api/operations/backups/{backup_id}/verify", headers={"X-CSRF-Token": csrf}), 200, "backup verification").json()
    if not verified.get("valid"):
        raise RuntimeError("backup verification failed")
    _require(admin.patch(f"/api/targets/{target_id}", headers={"X-CSRF-Token": csrf}, json={"name": "Phase 19 Mutated"}), 200, "mutate target before restore")
    restore = _require(admin.post("/api/operations/restores/validate", headers={"X-CSRF-Token": csrf}, json={"backup_id": backup_id}), 200, "restore validation").json()
    restore_id = restore["id"]
    _require(admin.post(f"/api/operations/restores/{restore_id}/execute", headers={"X-CSRF-Token": csrf}, json={"confirmation_phrase": "RESTORE THREATSCOPE DATA", "current_password": admin_password}), 200, "restore staging")
    admin.close()

    stopped = _compose(repository, env_file, "stop", "backend")
    if stopped.returncode:
        raise RuntimeError("backend stop for offline restore failed")
    restore_env = os.environ.copy()
    restore_env["THREATSCOPE_RESTORE_CONFIRMATION"] = "RESTORE THREATSCOPE DATA"
    command = ["docker", "compose", "--env-file", str(env_file), "-p", PROJECT]
    for filename in COMPOSE_FILES:
        command.extend(("-f", filename))
    command.extend(("run", "--rm", "--no-deps", "--entrypoint", "python", "-e", "THREATSCOPE_RESTORE_CONFIRMATION", "backend", "scripts/restore_backup.py", str(backup_id), "--non-interactive"))
    offline = subprocess.run(command, cwd=repository, env=restore_env, text=True, capture_output=True)
    if offline.returncode:
        raise RuntimeError("offline database restore failed")
    started = _compose(repository, env_file, "up", "-d", "backend", "edge")
    if started.returncode:
        raise RuntimeError("production restart after restore failed")
    _wait_https(base, cert)
    restored_admin, restored_csrf, _ = _login(base, cert, admin_username, admin_password)
    restored_target = _require(restored_admin.get(f"/api/targets/{target_id}"), 200, "restored target").json()
    if restored_target["name"] != "Phase 19 Persistence":
        raise RuntimeError("restored target does not match the verified backup")
    integrity = _require(restored_admin.post("/api/security-audit/verify-integrity", headers={"X-CSRF-Token": restored_csrf}), 200, "restored audit integrity").json()
    if not integrity.get("valid_chain"):
        raise RuntimeError("audit-chain integrity failed after restore")
    _require(restored_admin.post("/api/auth/logout", headers={"X-CSRF-Token": restored_csrf}), 200, "final logout")
    restored_admin.close()
    anonymous.close()

    print(json.dumps({
        "status": "passed", "tls_1_2": tls12, "tls_1_3": tls13,
        "spa_routes": route_count, "role_profiles": len(matrix),
        "backup_verified": True, "offline_restore_verified": True,
        "session_persisted_restart": True, "sessions_revoked_restore": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
