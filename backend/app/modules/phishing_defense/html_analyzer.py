import re
from bs4 import BeautifulSoup
from .url_analyzer import analyze_url

def analyze_html(value):
    html=str(value or "")[:200000]; soup=BeautifulSoup(html,"html.parser")
    visible=soup.get_text(" ",strip=True)[:50000]; links=[]; mismatches=[]
    for anchor in soup.find_all("a",href=True)[:200]:
        target=analyze_url(anchor.get("href"),"html_anchor"); display=anchor.get_text(" ",strip=True)[:500]
        shown=re.search(r"(?:https?://)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})",display)
        if shown and shown.group(1).lower().rstrip(".") != target["host"]: mismatches.append({"display":display,"target":target["display"]})
        links.append(target|{"anchor_text":display})
    styles=" ".join(str(tag.get("style", "")) for tag in soup.find_all(style=True)[:100]).lower()
    return {"visible_text":visible,"links":links,"anchor_mismatches":mismatches[:50],"form_present":bool(soup.find("form")),"password_field":bool(soup.find("input",attrs={"type":re.compile("password",re.I)})),"hidden_content":"display:none" in styles or "visibility:hidden" in styles,"iframe":bool(soup.find("iframe")),"meta_refresh":bool(soup.find("meta",attrs={"http-equiv":re.compile("refresh",re.I)})),"external_resources":len(soup.find_all(["img","script","link"],src=True))+len(soup.find_all("link",href=True))}
