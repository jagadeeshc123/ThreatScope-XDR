import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from app.modules.production.config import get_runtime_config


class IntegrationSecurityError(ValueError):
    def __init__(self, code: str, summary: str):
        self.code = code
        super().__init__(summary)


SECRET_KEYS = {"password", "secret", "token", "api_key", "authorization", "credential", "webhook_url", "signing_secret", "hec_token", "csrf", "totp", "recovery_code"}
METADATA_NETWORKS = tuple(ipaddress.ip_network(x) for x in ("169.254.169.254/32", "100.100.100.200/32", "fd00:ec2::254/128"))


def _fernet() -> Fernet:
    raw = get_runtime_config().secrets["THREATSCOPE_CONNECTOR_SECRETS_KEY"]
    if not raw:
        raise IntegrationSecurityError("CONNECTOR_CREDENTIAL_UNAVAILABLE", "Connector secret encryption key is unavailable")
    try:
        return Fernet(raw.encode("ascii"))
    except Exception as exc:
        raise IntegrationSecurityError("CONNECTOR_CREDENTIAL_UNAVAILABLE", "Connector secret encryption key is invalid") from exc


def encrypt_secret(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")


def decrypt_secret(ciphertext: str) -> dict:
    try:
        value = json.loads(_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationSecurityError("CONNECTOR_CREDENTIAL_UNAVAILABLE", "Connector credential cannot be decrypted") from exc
    if not isinstance(value, dict):
        raise IntegrationSecurityError("CONNECTOR_SECRET_INVALID", "Connector credential format is invalid")
    return value


def redact(value, depth=0):
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(k)[:100]: ("[REDACTED]" if any(s in str(k).casefold() for s in SECRET_KEYS) else redact(v, depth + 1)) for k, v in list(value.items())[:100]}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return value[:4000]
    return value if isinstance(value, (int, float, bool)) or value is None else str(value)[:500]


def contains_secret_key(value, depth=0) -> bool:
    if depth > 8:
        return True
    if isinstance(value, dict):
        return any(any(s in str(k).casefold() for s in SECRET_KEYS) or contains_secret_key(v, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return any(contains_secret_key(v, depth + 1) for v in value)
    return False


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def sign_hmac(secret: str, timestamp: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def verify_hmac(secret: str, timestamp: str, body: bytes, presented: str) -> bool:
    return hmac.compare_digest(sign_hmac(secret, timestamp, body), presented.strip())


def last_four(payload: dict) -> str | None:
    candidates = [str(v) for k, v in payload.items() if any(x in k.casefold() for x in ("token", "secret", "password", "key")) and isinstance(v, str)]
    return candidates[0][-4:] if candidates and len(candidates[0]) >= 8 else None


@dataclass(frozen=True)
class ValidatedDestination:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def _prohibited_address(address: ipaddress._BaseAddress) -> bool:
    return bool(address.is_loopback or address.is_link_local or address.is_multicast or address.is_private or address.is_reserved or address.is_unspecified or any(address in network for network in METADATA_NETWORKS))


def _parse_cidrs(values: list[str]):
    result = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise IntegrationSecurityError("CONNECTOR_NETWORK_POLICY_DENIED", "An approved CIDR is invalid") from exc
        if network.prefixlen == 0 or any(address in network for metadata in METADATA_NETWORKS for address in (metadata.network_address,)):
            raise IntegrationSecurityError("CONNECTOR_NETWORK_POLICY_DENIED", "Broad or metadata CIDRs are prohibited")
        result.append(network)
    return result


def validate_destination(url: str, policy: dict, resolver: Callable = socket.getaddrinfo) -> ValidatedDestination:
    if len(url) > 2048:
        raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Destination URL is too long")
    parsed = urlsplit(url)
    if parsed.scheme.casefold() != "https":
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "Only HTTPS destinations are allowed")
    if parsed.username or parsed.password or parsed.fragment:
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "URL user information and fragments are prohibited")
    if parsed.query and re.search(r"(?i)(token|secret|password|api[_-]?key|signature)=", parsed.query):
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "Credential-bearing query strings are prohibited")
    try:
        raw_host = parsed.hostname or ""
        hostname = raw_host.rstrip(".").encode("idna").decode("ascii").casefold()
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Destination host or port is invalid") from exc
    if not hostname or hostname == "localhost" or hostname.endswith(".localhost"):
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "Localhost is prohibited")
    allowed_hosts = {str(x).rstrip(".").encode("idna").decode("ascii").casefold() for x in policy.get("allowed_hosts", [])}
    if any("*" in host for host in allowed_hosts):
        raise IntegrationSecurityError("CONNECTOR_NETWORK_POLICY_DENIED", "Wildcard hosts are prohibited")
    if allowed_hosts and hostname not in allowed_hosts:
        raise IntegrationSecurityError("CONNECTOR_NETWORK_POLICY_DENIED", "Destination host is not allowlisted")
    allowed_ports = {int(x) for x in policy.get("allowed_ports", [443])}
    if port not in allowed_ports or not 1 <= port <= 65535:
        raise IntegrationSecurityError("CONNECTOR_NETWORK_POLICY_DENIED", "Destination port is not allowlisted")
    try:
        literal = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None and policy.get("network_scope", "public_https") == "public_https":
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "IP-literal destinations require explicit approval")
    # Reject alternative numeric forms before the resolver can reinterpret them.
    if literal is None and (re.fullmatch(r"(?i)(0x[0-9a-f]+|0[0-7]+|[0-9]+)(\.(0x[0-9a-f]+|0[0-7]+|[0-9]+)){0,3}", hostname)):
        raise IntegrationSecurityError("CONNECTOR_SSRF_BLOCKED", "Ambiguous numeric hosts are prohibited")
    try:
        records = resolver(hostname, port, type=socket.SOCK_STREAM)
        addresses = tuple(sorted({str(row[4][0]).split("%")[0] for row in records}))
    except (OSError, UnicodeError) as exc:
        raise IntegrationSecurityError("CONNECTOR_TIMEOUT", "Destination DNS resolution failed") from exc
    if not addresses:
        raise IntegrationSecurityError("CONNECTOR_TIMEOUT", "Destination DNS resolution returned no addresses")
    scope = policy.get("network_scope", "public_https")
    approved = _parse_cidrs(list(policy.get("allowed_cidrs", []))) if scope == "approved_private" else []
    for text in addresses:
        try:
            address = ipaddress.ip_address(text)
        except ValueError as exc:
            raise IntegrationSecurityError("CONNECTOR_DNS_REBINDING_BLOCKED", "DNS returned an invalid address") from exc
        if _prohibited_address(address) and not (scope == "approved_private" and any(address in network for network in approved) and hostname in allowed_hosts):
            raise IntegrationSecurityError("CONNECTOR_DNS_REBINDING_BLOCKED", "Destination resolved to a prohibited address")
    return ValidatedDestination(url, hostname, port, addresses)


def credential_key_available() -> bool:
    try:
        _fernet()
        return True
    except IntegrationSecurityError:
        return False


def source_ip_summary(value: str | None) -> str | None:
    if not value:
        return None
    return "ip-sha256:" + sha256(value)[:16]
