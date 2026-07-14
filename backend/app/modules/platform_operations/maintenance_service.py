import json
import secrets

from sqlalchemy.orm import Session

from app.modules.soc_monitor.models import SocActivity

from .models import OperationalJob, utcnow


def new_key(prefix: str) -> str:
    return f"{prefix}-{utcnow().strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(6)}"


def start_job(db: Session, job_type: str, user_id: int | None, metadata: dict | None = None) -> OperationalJob:
    job = OperationalJob(job_key=new_key("job"), job_type=job_type, status="running", requested_by_user_id=user_id, started_at=utcnow(), progress_percent=5, metadata_json=json.dumps(metadata or {}, sort_keys=True)[:8000])
    db.add(job); db.commit(); db.refresh(job)
    return job


def finish_job(db: Session, job: OperationalJob, summary: str, metadata: dict | None = None):
    job.status = "succeeded"; job.progress_percent = 100; job.completed_at = utcnow(); job.result_summary = summary[:1000]
    if metadata is not None: job.metadata_json = json.dumps(metadata, sort_keys=True)[:8000]
    db.commit()


def fail_job(db: Session, job: OperationalJob, code: str, summary: str):
    job.status = "failed"; job.completed_at = utcnow(); job.error_code = code[:80]; job.error_summary = summary[:500]; job.progress_percent = min(job.progress_percent, 99)
    db.commit()


def add_activity(db: Session, action: str, message: str, entity_type: str, entity_id: int | None):
    db.add(SocActivity(action=action[:100], message=message[:500], entity_type=entity_type[:80], entity_id=entity_id))


def notify(db: Session, title: str, message: str, level: str, entity_type: str, entity_id: int | None):
    from app.models import Notification
    duplicate = db.query(Notification).filter_by(title=title, message=message, entity_type=entity_type, entity_id=entity_id).first()
    if not duplicate:
        db.add(Notification(title=title[:150], message=message[:500], type=level, entity_type=entity_type[:80], entity_id=entity_id))
