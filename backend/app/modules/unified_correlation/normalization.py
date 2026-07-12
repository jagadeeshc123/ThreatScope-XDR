import hashlib,ipaddress,re
from urllib.parse import parse_qsl,urlsplit,urlunsplit,urlencode
SENSITIVE={"password","passwd","token","access_token","refresh_token","api_key","secret","session","auth","code","otp","pin"}
def normalize(kind,value):
 v=str(value or "").strip()
 if kind in {"domain","hostname","sender_domain"}:
  x=v.lower().rstrip(".")[:253]
  if not x or " " in x:raise ValueError("invalid domain")
  return x,x
 if kind=="ip_address":x=str(ipaddress.ip_address(v));return x,x
 if kind=="email_address":
  if "@" not in v:raise ValueError("invalid email")
  local,domain=v.rsplit("@",1);x=f"{local.lower()}@{domain.lower().rstrip('.')}";return x,f"{local[:2]}***@{domain.lower()}"
 if kind in {"file_hash","attachment_hash","url_hash"}:
  x=v.lower()
  if not re.fullmatch(r"[0-9a-f]{64}",x):raise ValueError("invalid SHA-256")
  return x,"sha256:"+x[:16]
 if kind=="url":
  s=urlsplit(v);host=(s.hostname or "").lower();q=urlencode([(k,"[REDACTED]" if k.lower() in SENSITIVE else val[:100]) for k,val in parse_qsl(s.query,keep_blank_values=True)]);safe=urlunsplit((s.scheme.lower(),host+(f":{s.port}" if s.port else ""),s.path[:1000],q,""));x=hashlib.sha256(safe.encode()).hexdigest();return x,safe[:500]
 if kind=="api_endpoint":
  method,path=(v.split(" ",1)+[""])[:2];x=f"{method.upper()} {path.split('?')[0][:1000]}";return x,x
 if kind=="web_target":
  s=urlsplit(v);x=f"{s.scheme.lower()}://{(s.hostname or '').lower()}";return x,x
 x=v.lower()[:1000]
 if not x:raise ValueError("empty value")
 return x,x
def value_hash(value):return hashlib.sha256(value.encode()).hexdigest()
