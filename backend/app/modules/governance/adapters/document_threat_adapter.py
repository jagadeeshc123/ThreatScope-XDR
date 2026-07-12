from app import models
from .common import row


def candidates(db, limit=500):
    return [row("document_threat","finding",x,"document",x.title,x.evidence_summary,x.severity,x.confidence,f"/document-threats/analyses/{x.analysis_id}") for x in db.query(models.DocumentFinding).limit(limit)]
