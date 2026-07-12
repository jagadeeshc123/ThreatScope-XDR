from app import models
from .common import row


def candidates(db, limit=500):
    out=[]
    for x in db.query(models.Finding).limit(limit):
        out.append(row("web_exposure","finding",x,"web_exposure",x.title,x.evidence,x.severity,x.confidence,f"/scans?highlight={x.scan_id}&tab=findings"))
    return out
