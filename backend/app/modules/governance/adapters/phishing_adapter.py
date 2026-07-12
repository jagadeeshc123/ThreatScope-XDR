from app import models
from .common import row


def candidates(db, limit=500):
    out=[row("phishing_defense","finding",x,"phishing",x.title,x.evidence_summary,x.severity,x.confidence,f"/phishing-defense/analyses/{x.analysis_id}") for x in db.query(models.PhishingFinding).limit(limit)]
    for x in db.query(models.PhishingWatchlistEntry).filter_by(status="active").limit(limit):out.append(row("phishing_defense","watchlist",x,"phishing","Active local phishing watchlist observation",x.reason,"medium","high","/phishing-defense/watchlist"))
    return out
