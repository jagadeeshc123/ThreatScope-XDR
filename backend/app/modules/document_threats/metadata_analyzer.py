import re
from datetime import datetime, timezone

from app.modules.document_threats.redaction import redact

def analyze_metadata(reader):
    try: source = dict(reader.metadata or {})
    except Exception: source = {}
    metadata = redact({str(key).lstrip("/")[:100]: value for key, value in list(source.items())[:100]})
    combined = " ".join(str(v) for v in metadata.values())
    anomalies = []
    if len(combined) > 5000: anomalies.append("Excessive metadata length")
    if any(ord(char)<32 and char not in "\n\t" for char in combined): anomalies.append("Control characters in metadata")
    if re.search(r"(?i)(?:powershell|cmd\.exe|javascript:|/bin/sh|<script)", combined): anomalies.append("Command-like text in metadata")
    if re.search(r"(?:[A-Za-z]:\\|/home/|/Users/)", combined): anomalies.append("Local path-like metadata")
    future = datetime.now(timezone.utc).year + 2
    if re.search(rf"D:{future}|20(?:[3-9]\d)", combined): anomalies.append("Future-looking metadata date")
    return metadata, anomalies
