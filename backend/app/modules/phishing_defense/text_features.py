import re
PATTERNS={"urgency":r"\b(urgent|immediately|within 24 hours|act now|suspend)\b","credential_request":r"\b(password|credential|login|verify your account|otp|pin)\b","payment_request":r"\b(payment|invoice|wire transfer|bank details|gift card)\b","enable_content":r"\b(enable content|enable macros|enable editing)\b","delivery_lure":r"\b(package|delivery|shipment|courier)\b","fear_language":r"\b(locked|terminated|legal action|security alert)\b","secrecy":r"\b(do not tell|confidential request|keep this secret)\b"}
def extract(text):
    value=str(text or "")[:100000]; lower=value.lower(); features={k:len(re.findall(p,lower,re.I)) for k,p in PATTERNS.items()};features.update({"exclamation_count":min(value.count("!"),20),"uppercase_ratio":round(sum(c.isupper() for c in value)/max(1,sum(c.isalpha() for c in value)),3),"character_count":len(value)})
    return features
