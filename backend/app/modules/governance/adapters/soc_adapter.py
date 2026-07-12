from app import models
from .common import row


def candidates(db, limit=500):
    out=[]
    for x in db.query(models.SocAlert).filter(models.SocAlert.status.in_(["open","investigating"])).limit(limit):out.append(row("soc_monitor","alert",x,"soc",x.title,x.evidence_summary,x.severity,x.confidence,f"/soc/alerts/{x.id}"))
    for x in db.query(models.SocBlocklistEntry).filter_by(status="active").limit(limit):out.append(row("soc_monitor","blocklist",x,"soc","Simulated blocklist governance observation",x.reason,"medium","high","/soc/blocklist"))
    return out
