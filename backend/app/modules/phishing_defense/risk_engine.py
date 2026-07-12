METHODOLOGY="Offline static hybrid analysis combines bounded lexical rules, supplied-header consistency, inert HTML/link inspection, attachment metadata, local watchlist matches, and a bundled synthetic-data demonstration classifier. No external reputation or authentication verification is performed."
def score(features,model_probability,watchlist_matches=0):
    contributions=[]
    def add(name,value,cap=None):
        value=min(value,cap) if cap else value
        if value>0: contributions.append({"feature":name,"contribution":round(value,1)})
    headers=features["headers"]; text=features["text"]; urls=features["urls"]; html=features["html"]
    add("sender header mismatch",18 if headers.get("reply_mismatch") else 0);add("return-path mismatch",12 if headers.get("return_path_mismatch") else 0)
    add("header-reported authentication failures",sum(10 for k in ("spf_failure","dkim_failure","dmarc_failure") if headers.get(k)),20)
    add("missing authentication context",3 if not headers.get("authentication_results_present") else 0)
    add("URL lexical indicators",sum(u["score"] for u in urls),28);add("HTML/link indicators",12*len(html.get("anchor_mismatches",[]))+8*int(bool(html.get("form_present") or html.get("password_field"))),20)
    add("social-engineering language",4*text.get("urgency",0)+8*text.get("credential_request",0)+7*text.get("payment_request",0)+10*text.get("enable_content",0),24)
    add("attachment metadata",sum(15 if a.get("executable_like") or a.get("script_like") else 10 if a.get("double_extension") or a.get("macro_capable") else 5 for a in features["attachments"] if a["risk_label"]!="low_observed_risk"),25)
    add("local watchlist match",20*watchlist_matches,30);add("local demonstration classifier",max(0,(model_probability-.35)*30),20)
    heuristic=min(100,sum(c["contribution"] for c in contributions if c["feature"]!="local demonstration classifier")); final=min(100,round(heuristic+max(0,(model_probability-.35)*30),1))
    classification="low_observed_risk" if final<20 else "needs_review" if final<45 else "suspicious" if final<70 else "high_risk"
    structural=any(c["feature"] in {"sender header mismatch","URL lexical indicators","HTML/link indicators","attachment metadata","local watchlist match"} and c["contribution"]>=10 for c in contributions)
    confidence="high" if structural and final>=70 else "medium" if structural or final>=35 else "low"
    return {"heuristic_score":round(heuristic,1),"final_risk_score":final,"classification":classification,"confidence":confidence,"top_contributing_features":sorted(contributions,key=lambda x:x["contribution"],reverse=True)[:10]}
