from io import BytesIO

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from app.modules.document_threats.action_analyzer import analyze_actions
from app.modules.document_threats.embedded_analyzer import analyze_attachments
from app.modules.document_threats.link_analyzer import analyze_links
from app.modules.document_threats.metadata_analyzer import analyze_metadata
from app.modules.document_threats.structure_analyzer import analyze_structure
from app.modules.document_threats.text_features import analyze_text

MAX_PAGES=300; MAX_TEXT=250_000

class DocumentParseError(ValueError): pass

def inspect_pdf(data: bytes):
    structure = analyze_structure(data); actions = analyze_actions(data)
    try: reader = PdfReader(BytesIO(data), strict=False)
    except Exception as exc: raise DocumentParseError("PDF structure could not be parsed safely.") from exc
    encrypted = bool(reader.is_encrypted); limited = encrypted
    page_count = None; annotations = 0; text_parts=[]; annotation_uris=[]; attachments=[]; metadata={}; anomalies=[]
    if not encrypted:
        try:
            page_count=len(reader.pages)
            if page_count>MAX_PAGES: raise DocumentParseError("PDF exceeds the 300-page analysis limit.")
            for page in reader.pages:
                try:
                    page_annotations=page.get("/Annots",[]) or [];annotations += len(page_annotations)
                    for reference in page_annotations:
                        annotation=reference.get_object();action=annotation.get("/A")
                        if action:
                            action=action.get_object() if hasattr(action,"get_object") else action
                            if action.get("/URI"):annotation_uris.append(str(action.get("/URI")))
                except Exception: pass
                if sum(len(v) for v in text_parts)<MAX_TEXT:
                    try: text_parts.append((page.extract_text() or "")[:MAX_TEXT-sum(len(v) for v in text_parts)])
                    except Exception: pass
            attachments=analyze_attachments(reader)
            metadata,anomalies=analyze_metadata(reader)
        except DocumentParseError: raise
        except Exception: limited=True
    raw_text=data.decode("latin-1",errors="ignore")
    extracted="".join(text_parts)[:MAX_TEXT]
    indicators,link_features=analyze_links(raw_text+"\n"+extracted+"\n"+"\n".join(annotation_uris))
    text_features=analyze_text(extracted)
    return {**structure,**actions,"is_encrypted":encrypted,"encryption_limited_analysis":limited,"page_count":page_count,"annotation_count":annotations,"attachments":attachments,"metadata":metadata,"metadata_anomalies":anomalies,"indicators":indicators,"link_features":link_features,"text_features":text_features,"extracted_text_character_count":len(extracted),"has_embedded_files":bool(attachments) or b"/EmbeddedFiles" in data,"embedded_file_count":len(attachments),"has_external_uris":bool(indicators),"external_uri_count":len([i for i in indicators if i["indicator_type"]=="url"])}
