import json, re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE={"password","passwd","token","access_token","refresh_token","api_key","key","secret","session","auth","code","otp","pin","authorization","cookie"}

def bounded(value, limit=500): return str(value or "").replace("\x00","")[:limit]
def redact_text(value, limit=500):
    text=bounded(value,limit*2)
    text=re.sub(r"(?i)\b("+"|".join(SENSITIVE)+r")\s*[:=]\s*([^\s;&]+)",r"\1=[REDACTED]",text)
    text=re.sub(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+",r"\1[REDACTED]",text)
    return text[:limit]
def sanitize_filename(value):
    raw=str(value or "")
    if not raw or raw!=Path(raw).name or ".." in raw.replace("\\","/").split("/"): raise ValueError("Unsafe filename")
    clean=re.sub(r"[^A-Za-z0-9._ -]","_",raw).strip(" .")[:255]
    if not clean: raise ValueError("Invalid filename")
    return clean
def redact_email(value):
    value=bounded(value,320).strip().lower()
    if "@" not in value:return redact_text(value,320)
    local,domain=value.rsplit("@",1); return f"{local[:2]}***@{domain}"
def sanitize_url(value):
    raw=bounded(value,4000).strip(); split=urlsplit(raw)
    host=(split.hostname or "").lower(); port=f":{split.port}" if split.port else ""
    netloc=host+port
    query=urlencode([(k,"[REDACTED]" if k.lower() in SENSITIVE else bounded(v,200)) for k,v in parse_qsl(split.query,keep_blank_values=True)])
    return urlunsplit((split.scheme.lower(),netloc,split.path[:1200],query,""))[:2000]
def redact_recursive(value):
    if isinstance(value,dict): return {k:("[REDACTED]" if str(k).lower() in SENSITIVE else redact_recursive(v)) for k,v in value.items()}
    if isinstance(value,list): return [redact_recursive(v) for v in value[:200]]
    return redact_text(value,1000) if isinstance(value,str) else value
