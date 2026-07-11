import re
def analyze_structure(data: bytes):
    return {"pdf_version": (re.match(br"%PDF-([0-9.]+)",data).group(1).decode() if re.match(br"%PDF-([0-9.]+)",data) else None), "object_count": len(re.findall(br"\b\d+\s+\d+\s+obj\b",data)), "eof_count": data.count(b"%%EOF"), "incremental_update": data.count(b"startxref")>1 or data.count(b"%%EOF")>1, "catalog_present": b"/Catalog" in data, "names_dictionary": b"/Names" in data}
