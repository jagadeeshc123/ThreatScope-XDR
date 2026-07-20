"""Fail when running Phase 19 containers diverge from the hardening contract."""
from __future__ import annotations

import argparse
import json
import subprocess


def _run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default="threatscope-phase19-smoke")
    args = parser.parse_args()
    identifiers = _run(["docker", "ps", "--filter", f"label=com.docker.compose.project={args.project}", "-q"]).split()
    if len(identifiers) != 2:
        raise SystemExit("Expected exactly two running production containers")
    inspected = json.loads(_run(["docker", "inspect", *identifiers]))
    failures: list[str] = []
    services: dict[str, dict] = {}
    for item in inspected:
        service = item["Config"]["Labels"].get("com.docker.compose.service", "unknown")
        services[service] = item
        host = item["HostConfig"]
        state = item["State"]
        checks = {
            "non_root": bool(item["Config"].get("User")) and not item["Config"]["User"].startswith("0"),
            "read_only_root": host.get("ReadonlyRootfs") is True,
            "not_privileged": host.get("Privileged") is False,
            "all_capabilities_dropped": "ALL" in (host.get("CapDrop") or []),
            "no_new_privileges": any("no-new-privileges" in value for value in (host.get("SecurityOpt") or [])),
            "pid_limit": int(host.get("PidsLimit") or 0) > 0,
            "memory_limit": int(host.get("Memory") or 0) > 0,
            "cpu_limit": int(host.get("NanoCpus") or 0) > 0,
            "restart_policy": host.get("RestartPolicy", {}).get("Name") == "unless-stopped",
            "healthcheck": bool(item["Config"].get("Healthcheck")),
            "healthy": state.get("Health", {}).get("Status") == "healthy",
            "bounded_logging": host.get("LogConfig", {}).get("Type") == "json-file" and bool(host.get("LogConfig", {}).get("Config", {}).get("max-size")) and bool(host.get("LogConfig", {}).get("Config", {}).get("max-file")),
            "no_docker_socket": all("docker.sock" not in mount.get("Source", "") for mount in item.get("Mounts", [])),
            "no_direct_secret_environment": all(not entry.split("=", 1)[0] in {"THREATSCOPE_SESSION_SECRET", "THREATSCOPE_MFA_ENCRYPTION_KEY", "THREATSCOPE_CONNECTOR_SECRETS_KEY", "THREATSCOPE_BACKUP_ENCRYPTION_KEY"} for entry in item["Config"].get("Env", [])),
        }
        for name, passed in checks.items():
            if not passed:
                failures.append(f"{service}:{name}")
    backend = services.get("backend", {})
    edge = services.get("edge", {})
    if backend.get("NetworkSettings", {}).get("Ports", {}).get("8000/tcp"):
        failures.append("backend:host_port_exposed")
    if len(backend.get("NetworkSettings", {}).get("Networks", {})) != 1:
        failures.append("backend:network_scope")
    if len(edge.get("NetworkSettings", {}).get("Networks", {})) != 2:
        failures.append("edge:network_scope")
    if failures:
        raise SystemExit("Container hardening inspection failed: " + ", ".join(sorted(failures)))
    print(json.dumps({"status": "passed", "services": sorted(services), "checks_per_service": 14}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
