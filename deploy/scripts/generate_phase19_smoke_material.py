from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _revision(repository: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _write(path: Path, value: bytes, mode: int) -> None:
    path.write_bytes(value)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Create ephemeral localhost-only Phase 20 smoke material.")
    parser.add_argument("--output", default=".runtime/phase20-smoke")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = (repository / args.output).resolve()
    expected_parent = (repository / ".runtime").resolve()
    if expected_parent not in output.parents or output.name != "phase20-smoke":
        raise SystemExit("Smoke output must resolve to .runtime/phase20-smoke")
    output.mkdir(parents=True, exist_ok=True)
    secrets_dir = output / "secrets"
    tls_dir = output / "tls"
    secrets_dir.mkdir(exist_ok=True)
    tls_dir.mkdir(exist_ok=True)
    _write(secrets_dir / "session_secret", secrets.token_urlsafe(64).encode(), 0o600)
    for name in ("mfa_encryption_key", "connector_secrets_key", "backup_encryption_key"):
        _write(secrets_dir / name, Fernet.generate_key(), 0o600)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ThreatScope Phase 20 Local Smoke")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write(tls_dir / "tls.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o644)
    _write(tls_dir / "tls.crt", certificate.public_bytes(serialization.Encoding.PEM), 0o644)

    revision = _revision(repository)
    created = now.isoformat().replace("+00:00", "Z")
    path = lambda item: item.resolve().as_posix()
    values = {
        "THREATSCOPE_APP_VERSION": "1.0.0",
        "THREATSCOPE_BUILD_COMMIT": revision,
        "THREATSCOPE_BUILD_TIMESTAMP": created,
        "THREATSCOPE_FRONTEND_BUILD_ID": f"frontend-{revision[:12]}",
        "THREATSCOPE_BACKEND_BUILD_ID": f"backend-{revision[:12]}",
        "THREATSCOPE_PUBLIC_HOST": "localhost",
        "THREATSCOPE_ALLOWED_HOSTS": "localhost,127.0.0.1",
        "THREATSCOPE_ALLOWED_ORIGINS": "https://localhost:18443,https://127.0.0.1:18443",
        "THREATSCOPE_TRUSTED_PROXY_NETWORKS": "172.16.0.0/12",
        "THREATSCOPE_HTTP_PORT": "18080",
        "THREATSCOPE_HTTPS_PORT": "18443",
        "THREATSCOPE_TLS_CERTIFICATE_HOST_FILE": path(tls_dir / "tls.crt"),
        "THREATSCOPE_TLS_PRIVATE_KEY_HOST_FILE": path(tls_dir / "tls.key"),
        "THREATSCOPE_SESSION_SECRET_HOST_FILE": path(secrets_dir / "session_secret"),
        "THREATSCOPE_MFA_ENCRYPTION_KEY_HOST_FILE": path(secrets_dir / "mfa_encryption_key"),
        "THREATSCOPE_CONNECTOR_SECRETS_KEY_HOST_FILE": path(secrets_dir / "connector_secrets_key"),
        "THREATSCOPE_BACKUP_ENCRYPTION_KEY_HOST_FILE": path(secrets_dir / "backup_encryption_key"),
    }
    (output / "smoke.env").write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    print("Phase 20 localhost smoke material created beneath the ignored runtime directory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
