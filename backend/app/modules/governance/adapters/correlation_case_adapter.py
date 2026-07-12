from app import models
from .common import row


def candidates(db, limit=500):
    out=[]
    for x in db.query(models.CorrelationMatch).filter(models.CorrelationMatch.status.notin_(["dismissed"]),models.CorrelationMatch.severity.in_(["high","critical"])).limit(limit):out.append(row("unified_correlation","correlation_match",x,"correlation",x.title,x.explanation,x.severity,x.confidence,f"/correlation/matches/{x.id}"))
    for x in db.query(models.IncidentCase).filter(models.IncidentCase.status.notin_(["resolved","closed"])).limit(limit):out.append(row("incident_case","incident_case",x,"incident",x.title,x.summary,x.severity,x.confidence,f"/correlation/cases/{x.id}"))
    return out
