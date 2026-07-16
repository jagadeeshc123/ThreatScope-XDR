import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit


INDICATOR_TYPES = {"ipv4", "ipv6", "cidr", "domain", "hostname", "url", "email", "sha256", "sha1", "md5", "file_name", "user_agent", "vulnerability_id", "custom"}
MAX_VALUE_LENGTH = 2048
_DOMAIN = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.I)


class IndicatorValidationError(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedIndicator:
    indicator_type: str
    original: str
    normalized: str
    value_hash: str


def _domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IndicatorValidationError("Invalid internationalized domain") from exc
    if not _DOMAIN.fullmatch(value) or "." not in value:
        raise IndicatorValidationError("Invalid domain or hostname")
    return value


def normalize_indicator(indicator_type: str, value: str) -> NormalizedIndicator:
    kind = str(indicator_type or "").strip().lower()
    if kind not in INDICATOR_TYPES:
        raise IndicatorValidationError("Unsupported indicator type")
    if not isinstance(value, str):
        raise IndicatorValidationError("Indicator value must be text")
    original = value.strip()
    if not original or len(original) > MAX_VALUE_LENGTH or any(ord(ch) < 32 and ch not in "\t" for ch in original):
        raise IndicatorValidationError("Indicator value is empty, contains control characters, or is too long")
    try:
        if kind in {"ipv4", "ipv6"}:
            address = ipaddress.ip_address(original)
            if (kind == "ipv4") != isinstance(address, ipaddress.IPv4Address):
                raise IndicatorValidationError(f"Value is not {kind}")
            normalized = address.compressed
        elif kind == "cidr":
            normalized = ipaddress.ip_network(original, strict=False).compressed
        elif kind in {"domain", "hostname"}:
            normalized = _domain(original)
        elif kind == "email":
            if original.count("@") != 1:
                raise IndicatorValidationError("Invalid email indicator")
            local, domain = original.rsplit("@", 1)
            if not local or len(local) > 64 or len(original) > 320 or any(ch.isspace() for ch in local):
                raise IndicatorValidationError("Invalid email indicator")
            normalized = f"{local}@{_domain(domain)}"
        elif kind == "url":
            parsed = urlsplit(original)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise IndicatorValidationError("URL must use HTTP(S), include a host, and contain no userinfo")
            host = _domain(parsed.hostname) if not _is_ip(parsed.hostname) else ipaddress.ip_address(parsed.hostname).compressed
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise IndicatorValidationError("Invalid URL port")
            netloc = f"[{host}]" if ":" in host else host
            if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
                netloc += f":{port}"
            path = quote(unquote(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
            normalized = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
        elif kind in {"sha256", "sha1", "md5"}:
            lengths = {"sha256": 64, "sha1": 40, "md5": 32}
            normalized = original.lower()
            if len(normalized) != lengths[kind] or not re.fullmatch(r"[0-9a-f]+", normalized):
                raise IndicatorValidationError(f"Invalid {kind} hash")
        elif kind == "file_name":
            normalized = original.casefold()
            if len(original) > 255 or any(ch in original for ch in "\0/\\"):
                raise IndicatorValidationError("Invalid file name")
        elif kind == "user_agent":
            normalized = " ".join(original.split()).casefold()
            if len(normalized) > 1000:
                raise IndicatorValidationError("User agent is too long")
        elif kind == "vulnerability_id":
            normalized = original.upper()
            if not _CVE.fullmatch(normalized):
                raise IndicatorValidationError("Vulnerability ID must be a CVE identifier")
        else:
            normalized = " ".join(original.split()).casefold()
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, IndicatorValidationError):
            raise
        raise IndicatorValidationError(f"Invalid {kind} indicator") from exc
    identity = f"{kind}\0{normalized}".encode("utf-8")
    return NormalizedIndicator(kind, original, normalized, hashlib.sha256(identity).hexdigest())


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def defang(value: str, indicator_type: str) -> str:
    text = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    if indicator_type in {"url", "domain", "hostname", "ipv4", "ipv6", "cidr", "email"}:
        text = text.replace(".", "[.]")
        if indicator_type == "email":
            text = text.replace("@", "[@]")
    return text
