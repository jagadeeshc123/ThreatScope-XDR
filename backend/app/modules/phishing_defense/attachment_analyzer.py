import hashlib, mimetypes
from pathlib import Path
from .redaction import sanitize_filename

EXEC={"exe","dll","scr","bat","cmd","com","lnk","msi","reg","hta","chm"};SCRIPT={"ps1","js","jse","vbs","vbe","jar"};ARCHIVE={"zip","rar","7z","iso","img"};MACRO={"docm","xlsm","pptm"}
def analyze_attachment(filename,mime,data):
    try:name=sanitize_filename(filename or "attachment")
    except ValueError:name="attachment"
    ext=Path(name).suffix.lower().lstrip(".") or None; parts=name.lower().split("."); double=len(parts)>2 and parts[-1] in EXEC|SCRIPT and parts[-2] not in EXEC|SCRIPT
    guessed=mimetypes.guess_type(name)[0]; mismatch=bool(guessed and mime and guessed.split("/")[0]!=str(mime).split("/")[0])
    risky=ext in EXEC|SCRIPT|ARCHIVE|MACRO or double or mismatch or not ext
    return {"filename_sanitized":name,"extension":ext,"declared_mime_type":str(mime or "")[:100] or None,"file_size":len(data),"sha256":hashlib.sha256(data).hexdigest() if len(data)<=10*1024*1024 else None,"executable_like":ext in EXEC,"script_like":ext in SCRIPT,"archive_like":ext in ARCHIVE,"macro_capable":ext in MACRO,"double_extension":double,"mime_mismatch":mismatch,"risk_label":"needs_review" if risky else "low_observed_risk","evidence_summary":f"Static metadata only: {name}; extension={ext or 'missing'}; bytes were not retained."[:500]}
