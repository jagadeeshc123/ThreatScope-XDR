import hashlib, ipaddress, json, re
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .redaction import sanitize_url

ROOT=Path(__file__).parent/"rules"
BRANDS=json.loads((ROOT/"brand_domains.json").read_text())
SHORTENERS=set(json.loads((ROOT/"url_shorteners.json").read_text()))
SENSITIVE=set(json.loads((ROOT/"sensitive_query_keys.json").read_text()))
UNSAFE={"javascript","data","file","ftp","smb"}

def analyze_url(raw, source="message"):
    raw=str(raw or "").strip()[:4000]
    candidate=raw if ":" in raw[:20] else "https://"+raw
    split=urlsplit(candidate); scheme=split.scheme.lower(); host=(split.hostname or "").lower().rstrip(".")
    try: ip_literal=bool(host and ipaddress.ip_address(host))
    except ValueError: ip_literal=False
    sensitive=[k for k,_ in parse_qsl(split.query,keep_blank_values=True) if k.lower() in SENSITIVE]
    labels=host.split(".") if host else []; protected=None; similarity=0.0
    for brand,domain in BRANDS.items():
        score=max(SequenceMatcher(None,host.replace("-",""),domain.replace("-","")).ratio(),SequenceMatcher(None,(host.split(".")[0] if host else "").replace("-",""),domain.split(".")[0].replace("-","")).ratio())
        token=domain.split(".")[0]
        if host!=domain and (token in host or token in split.path.lower() or score>0.78) and score>similarity: protected={"brand":brand,"domain":domain};similarity=score
    flags={"unsafe_scheme":scheme in UNSAFE or raw.startswith("\\\\"),"ip_literal":ip_literal,"punycode":"xn--" in host,"userinfo":bool(split.username or split.password or "@" in raw.split("/")[0]),"nonstandard_port":bool(split.port and split.port not in {80,443}),"shortener":host in SHORTENERS,"sensitive_query":bool(sensitive),"percent_encoding":raw.count("%")>=2,"long_url":len(raw)>180,"long_host":len(host)>80,"excessive_subdomains":len(labels)>4,"lookalike":bool(protected),"redirect_parameter":any(k.lower() in {"url","redirect","return","next","continue"} for k,_ in parse_qsl(split.query)),"suspicious_extension":bool(re.search(r"\.(exe|scr|js|zip|iso|html?)$",split.path,re.I))}
    score=min(45,sum(v*w for (v,w) in zip(flags.values(),[15,18,15,12,7,10,9,5,5,5,8,7,8,7])))
    safe=sanitize_url(candidate)
    return {"raw_hash":hashlib.sha256(raw.encode()).hexdigest(),"normalized":safe.lower(),"display":safe,"scheme":scheme,"host":host,"flags":flags,"sensitive_keys":sensitive,"protected_match":protected,"similarity":round(similarity,3),"score":score,"source":source}
