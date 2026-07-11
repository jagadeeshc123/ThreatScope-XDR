METHODOLOGY="Explainable weighted static indicators are grouped to limit double-counting. No document content was executed, and the score is not a definitive malware verdict."
LIMITATION="Static analysis result — no document content was executed, and this is not a definitive malware verdict."

def score(findings):
    weights={item["rule_code"]:item["score"] for item in findings}
    related=[{"DOC-001","DOC-002","DOC-003","DOC-016"},{"DOC-004","DOC-005","DOC-014"}]
    consumed=set(); total=0
    for group in related:
        values=[weights[c] for c in group if c in weights]
        if values: total+=max(values)+min(8,sum(values)-max(values)); consumed|=group
    total+=sum(value for code,value in weights.items() if code not in consumed); total=min(100,total)
    classification="low_observed_risk" if total<20 else "needs_review" if total<45 else "suspicious" if total<70 else "high_risk"
    direct=[item for item in findings if item["confidence"]=="high" and item["severity"] in {"high","critical"}]
    confidence="high" if len(direct)>=2 else "medium" if direct or len(findings)>=2 else "low"
    top=sorted(({"rule_code":item["rule_code"],"title":item["title"],"contribution":item["score"]} for item in findings),key=lambda x:x["contribution"],reverse=True)[:5]
    return {"risk_score":total,"classification":classification,"confidence":confidence,"top_contributing_features":top,"methodology":METHODOLOGY,"limitation":LIMITATION}
