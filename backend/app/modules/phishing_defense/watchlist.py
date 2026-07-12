import hashlib
from .redaction import redact_email, sanitize_url
def normalize(kind,value):
    value=str(value or "").strip()
    if kind=="sender_email":return value.lower(),redact_email(value)
    if kind=="domain":return value.lower().rstrip("."),value.lower().rstrip(".")
    if kind=="url_hash":return (value.lower() if len(value)==64 else hashlib.sha256(sanitize_url(value).encode()).hexdigest()),"sha256:"+(value.lower() if len(value)==64 else hashlib.sha256(sanitize_url(value).encode()).hexdigest())[:16]
    if kind=="attachment_hash":return value.lower(),"sha256:"+value.lower()[:16]
    raise ValueError("Unsupported watchlist indicator type")
DISCLAIMER="Local application watchlist only — this does not block real email, browser, DNS, firewall, or network traffic."
