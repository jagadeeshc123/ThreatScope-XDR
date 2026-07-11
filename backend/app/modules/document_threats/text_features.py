import re

TERMS = ["urgent payment","wire transfer","verify your account","confirm your password","enable content","disable security","security warning","invoice attached","credential","login immediately"]

def analyze_text(text: str):
    lower = re.sub(r"\s+", " ", text.lower())
    matches = [term for term in TERMS if term in lower]
    return {"social_engineering_terms": matches[:20], "social_engineering_detected": len(matches) >= 2}
