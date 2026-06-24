from typing import List

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0
}

def calculate_risk_score(findings: List[dict]) -> float:
    if not findings:
        return 0.0
        
    total_findings = len(findings)
    highest_severity_weight = 0.0
    total_weight = 0.0
    
    for f in findings:
        sev = f.get("severity", "info").lower()
        weight = SEVERITY_WEIGHTS.get(sev, 0.0)
        
        if weight > highest_severity_weight:
            highest_severity_weight = weight
            
        total_weight += weight
        
    # simple formula: base score is highest severity, plus a small bump for volume of other issues
    avg_weight = total_weight / total_findings
    
    score = highest_severity_weight + (avg_weight * 0.1)
    
    return min(round(score, 1), 10.0)
