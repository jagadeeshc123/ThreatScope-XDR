from datetime import datetime, timezone, timedelta
from email.utils import getaddresses, parsedate_to_datetime

def address(value):
    rows=getaddresses([str(value or "")]); return rows[0] if rows else ("","")
def domain(value):
    addr=address(value)[1].lower(); return addr.rsplit("@",1)[-1] if "@" in addr else ""
def analyze_headers(headers):
    auth=str(headers.get("Authentication-Results", "")); spf=str(headers.get("Received-SPF", "")); date=str(headers.get("Date", "")); age=None
    try: age=(datetime.now(timezone.utc)-parsedate_to_datetime(date).astimezone(timezone.utc)).total_seconds()/86400
    except Exception: pass
    from_domain=domain(headers.get("From")); reply_domain=domain(headers.get("Reply-To")); return_domain=domain(headers.get("Return-Path"))
    return {"from_domain":from_domain,"reply_to_domain":reply_domain,"return_path_domain":return_domain,"reply_mismatch":bool(reply_domain and from_domain and reply_domain!=from_domain),"return_path_mismatch":bool(return_domain and from_domain and return_domain!=from_domain),"message_id_present":bool(headers.get("Message-ID")),"message_id_malformed":bool(headers.get("Message-ID") and "@" not in str(headers.get("Message-ID"))),"received_count":len(headers.get_all("Received",[])) if hasattr(headers,"get_all") else 0,"authentication_results_present":bool(auth or spf),"spf_failure":"spf=fail" in auth.lower() or spf.lower().startswith("fail"),"dkim_failure":"dkim=fail" in auth.lower(),"dmarc_failure":"dmarc=fail" in auth.lower(),"dkim_signature_present":bool(headers.get("DKIM-Signature")),"future_date":age is not None and age < -1,"very_old_date":age is not None and age > 3650}
