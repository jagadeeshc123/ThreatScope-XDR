import csv, hashlib
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

DISCLAIMER="Local demonstration classifier — trained on bundled synthetic examples and not validated for production email-security decisions."
DATA=Path(__file__).parent/"rules"/"synthetic_training_data.csv"

@lru_cache(maxsize=1)
def model_bundle():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    raw=DATA.read_bytes(); rows=list(csv.DictReader(raw.decode("utf-8").splitlines())); texts=[f"{r['subject']} {r['body']}" for r in rows]; labels=[int(r["label"]) for r in rows]
    vectorizer=TfidfVectorizer(lowercase=True,ngram_range=(1,2),max_features=1500,strip_accents="unicode")
    matrix=vectorizer.fit_transform(texts); model=LogisticRegression(class_weight="balanced",random_state=42,max_iter=300).fit(matrix,labels)
    return model,vectorizer,{"model_type":"TF-IDF + Logistic Regression","classifier_type":"LogisticRegression","tfidf_configuration":"lowercase word n-grams 1-2; max 1500 features","training_dataset_size":len(rows),"class_counts":{"legitimate":labels.count(0),"phishing_like":labels.count(1)},"feature_count":len(vectorizer.get_feature_names_out()),"model_version":"phish-demo-"+hashlib.sha256(raw+b"tfidf-1-2-lr42").hexdigest()[:16],"initialization_timestamp":datetime.now(timezone.utc).isoformat(),"evaluation_method":"No accuracy metrics published; bundled synthetic examples exercise deterministic demonstration behavior.","demonstration_metrics":None,"limitations":DISCLAIMER}
def predict(text):
    model,vectorizer,_=model_bundle(); probability=float(model.predict_proba(vectorizer.transform([str(text or "")[:100000]]))[0][1]);return {"probability":round(probability,4),"label":"phishing_risk_indicator" if probability>=0.55 else "low_observed_model_risk"}
def info(): return model_bundle()[2]
