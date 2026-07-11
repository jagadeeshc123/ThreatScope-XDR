import hashlib
import json
from pathlib import Path

from app.modules.document_threats.redaction import sanitize_filename

CATALOG = json.loads((Path(__file__).parent / "rules" / "suspicious_extensions.json").read_text())

def analyze_attachments(reader, maximum: int = 100):
    artifacts = []
    try: attachments = reader.attachments
    except Exception: attachments = {}
    for raw_name, values in list(attachments.items())[:maximum]:
        try: filename = sanitize_filename(Path(str(raw_name)).name)
        except ValueError: filename = "sanitized_attachment"
        extension = Path(filename).suffix.lower().lstrip(".") or None
        lower_parts = filename.lower().split(".")
        double_extension = len(lower_parts) > 2 and lower_parts[-2] not in {"tar"}
        executable = extension in CATALOG["executable"]
        script = extension in CATALOG["script"]
        archive = extension in CATALOG["archive"]
        macro = extension in CATALOG["office_macro"]
        value_list = values if isinstance(values, list) else [values]
        data = value_list[0] if value_list and isinstance(value_list[0], bytes) else b""
        label = "high_risk_indicator" if executable else "needs_review" if script or archive or macro or double_extension else "metadata_only"
        artifacts.append({"filename_sanitized":filename,"extension":extension,"declared_mime_type":None,"file_size":len(data) if data else None,"sha256":hashlib.sha256(data).hexdigest() if data else None,"artifact_type":"embedded_file","executable_like":executable,"archive_like":archive,"script_like":script,"office_macro_like":macro,"risk_label":label,"evidence_summary":f"Embedded metadata: {filename}; extension={extension or 'missing'}; size={len(data) if data else 'unknown'}; bytes were not persisted.","double_extension":double_extension or not extension or len(filename)>180})
    return artifacts
