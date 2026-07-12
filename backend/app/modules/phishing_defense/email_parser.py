import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

from .attachment_analyzer import analyze_attachment
from .header_analyzer import analyze_headers
from .html_analyzer import analyze_html
from .url_analyzer import analyze_url

URL_RE=re.compile(r"(?i)(?:https?|mailto|javascript|data|file|ftp|smb)://?[^\s<>\"']+|\\\\[^\s<>]+")

def parse_eml(data):
    message=BytesParser(policy=policy.default).parsebytes(data)
    plain=[];html=[];attachments=[]
    for part in message.walk():
        if part.is_multipart():continue
        disposition=part.get_content_disposition(); filename=part.get_filename()
        payload=part.get_payload(decode=True) or b""
        if disposition=="attachment" or filename:
            if len(attachments)<50:attachments.append(analyze_attachment(filename or "attachment",part.get_content_type(),payload[:10*1024*1024+1]))
        elif part.get_content_type()=="text/plain": plain.append(payload.decode(part.get_content_charset() or "utf-8",errors="replace"))
        elif part.get_content_type()=="text/html": html.append(payload.decode(part.get_content_charset() or "utf-8",errors="replace"))
    return message,"\n".join(plain)[:100000],"\n".join(html)[:200000],attachments

def build_features(subject,sender,reply_to,body_text,body_html,headers=None,attachments=None):
    headers=headers or {}; header_map=headers
    if sender and not header_map.get("From"): header_map["From"]=sender
    if reply_to and not header_map.get("Reply-To"): header_map["Reply-To"]=reply_to
    html=analyze_html(body_html); urls=[]
    for raw in URL_RE.findall(f"{body_text}\n{body_html}")[:200]:
        try:urls.append(analyze_url(raw))
        except Exception:continue
    for item in html["links"]:
        if len(urls)<200 and item["raw_hash"] not in {u["raw_hash"] for u in urls}:urls.append(item)
    from .text_features import extract
    text=f"{subject}\n{body_text}\n{html['visible_text']}"[:100000]
    return {"headers":analyze_headers(header_map),"html":html,"urls":urls,"attachments":attachments or [],"text":extract(text),"bounded_text":text}

def message_fields(message):
    sender_name,sender_addr=(getaddresses([str(message.get("From", ""))]) or [("","")])[0]
    recipients=getaddresses([str(message.get("To","")),str(message.get("Cc",""))])
    return {"subject":str(message.get("Subject", ""))[:500],"sender":str(message.get("From", ""))[:500],"sender_name":sender_name,"sender_address":sender_addr,"reply_to":str(message.get("Reply-To", ""))[:320],"return_path":str(message.get("Return-Path", ""))[:320],"recipient_count":len([a for _,a in recipients if a])}
