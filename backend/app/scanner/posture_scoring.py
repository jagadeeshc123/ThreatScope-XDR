def calculate_posture_scores(findings_data: list) -> dict:
    scores = {
        "transport_security": 100,
        "browser_defense": 100,
        "session_safety": 100,
        "exposure_hygiene": 100,
        "authentication_surface": 100
    }
    
    severity_penalty = {
        "critical": 30,
        "high": 20,
        "medium": 10,
        "low": 5,
        "info": 0
    }
    
    for f in findings_data:
        cat = f.get("category", "").lower()
        title = f.get("title", "").lower()
        penalty = severity_penalty.get(f.get("severity", "info"), 0)
        
        if "tls" in cat or "https" in cat or "mixed content" in cat or "tls" in title or "https" in title:
            scores["transport_security"] -= penalty
        elif "header" in cat or "cors" in cat or "header" in title:
            scores["browser_defense"] -= penalty
        elif "cookie" in cat or "session" in cat or "cookie" in title:
            scores["session_safety"] -= penalty
        elif "exposed" in cat or "disclosure" in cat or "file" in cat or "directory" in title:
            scores["exposure_hygiene"] -= penalty
        elif "auth" in cat or "login" in cat or "password" in cat or "form" in title:
            scores["authentication_surface"] -= penalty
        else:
            scores["exposure_hygiene"] -= (penalty // 2)

    for k in scores:
        if scores[k] < 0:
            scores[k] = 0
            
    scores["overall_posture_score"] = sum(scores.values()) // 5
    
    return scores
