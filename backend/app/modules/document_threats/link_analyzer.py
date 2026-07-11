import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from app.modules.document_threats.redaction import sanitize_url

CATALOG = json.loads((Path(__file__).parent / "rules" / "suspicious_schemes.json").read_text())
URI_RE = re.compile(r"(?i)(?:https?|ftp|file|javascript|data|smb):[^\s<>\[\](){}]+|\\\\[A-Za-z0-9_.-]+\\[^\s<>]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

def analyze_links(text: str, maximum: int = 500):
    indicators, features = [], {"unsafe_uri": False, "sensitive_url": False, "ip_literal_url": False, "punycode": False, "shortened_url": False, "remote_reference": False}
    seen = set()
    for raw in URI_RE.findall(text):
        clean, sensitive = sanitize_url(raw)
        if clean in seen: continue
        seen.add(clean)
        try: parts = urlsplit(clean); scheme = parts.scheme.lower(); host = parts.hostname or ""
        except ValueError: scheme, host = "", ""
        unsafe = scheme in CATALOG["unsafe"] or clean.startswith("\\\\")
        try: ipaddress.ip_address(host); ip_literal = True
        except ValueError: ip_literal = False
        features.update(unsafe_uri=features["unsafe_uri"] or unsafe, sensitive_url=features["sensitive_url"] or sensitive, ip_literal_url=features["ip_literal_url"] or ip_literal, punycode=features["punycode"] or "xn--" in host.lower(), shortened_url=features["shortened_url"] or host.lower() in CATALOG["shorteners"], remote_reference=features["remote_reference"] or scheme in {"file","ftp","smb"} or clean.startswith("\\\\"))
        severity = "high" if unsafe else "medium" if sensitive or ip_literal or "xn--" in host.lower() else "low"
        indicators.append({"indicator_type":"url","normalized_value":clean,"display_value_redacted":clean,"context":"Static URI string; destination was not contacted.","severity":severity,"confidence":"high","source_object":"PDF static content"})
        if host and len(indicators) < maximum:
            indicators.append({"indicator_type":"ip" if ip_literal else "domain","normalized_value":host.lower()[:500],"display_value_redacted":host.lower()[:500],"context":"Host parsed locally from a URI; no DNS lookup occurred.","severity":severity,"confidence":"high","source_object":"PDF URI"})
        if len(indicators) >= maximum: break
    for email in EMAIL_RE.findall(text):
        if len(indicators) >= maximum: break
        indicators.append({"indicator_type":"email","normalized_value":email.lower()[:500],"display_value_redacted":email.lower()[:500],"context":"Email-shaped text extracted statically.","severity":"info","confidence":"medium","source_object":"PDF text"})
    return indicators[:maximum], features
