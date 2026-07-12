import re
SENSITIVE=r"password|passwd|token|secret|authorization|cookie|api[_-]?key|otp|pin"
def redact(v,n=1000):return re.sub(rf"(?i)\b({SENSITIVE})\s*[:=]\s*[^\s;&]+",r"\1=[REDACTED]",str(v or "").replace("\x00","")[:n*2])[:n]
