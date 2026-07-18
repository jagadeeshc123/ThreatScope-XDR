import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .models import ConnectorInboundRateCounter

MAX_RETRY_AFTER = 300
DEFAULT_LIMITS = {"endpoint": (60, 60), "source": (30, 60), "global": (300, 60), "invalid": (20, 300), "signature": (10, 300), "replay": (5, 300)}


@dataclass(frozen=True)
class RateLimitExceeded(Exception):
    retry_after: int


def source_key(source: str | None) -> str:
    return hashlib.sha256(b"integration-inbound-source-v1:" + (source or "unknown").strip().casefold().encode()).hexdigest()


def _key(scope: str, endpoint_id: int | None, source_hash: str) -> str:
    raw = "global" if scope == "global" else f"{endpoint_id or 0}:{source_hash if scope in {'source','signature','replay','invalid'} else 'endpoint'}"
    return hashlib.sha256(f"integration-rate-v1:{scope}:{raw}".encode()).hexdigest()


def consume(db: Session, scope: str, endpoint_id: int | None, source_hash: str, *, now: float | None = None, limit: int | None = None, window: int | None = None) -> int:
    configured_limit, configured_window = DEFAULT_LIMITS[scope]
    limit = min(max(int(limit or configured_limit), 1), 1000); window = min(max(int(window or configured_window), 1), 300)
    instant = float(time.time() if now is None else now); bucket = int(instant // window) * window
    expires = datetime.fromtimestamp(bucket, timezone.utc).replace(tzinfo=None) + timedelta(seconds=window * 2); key_hash = _key(scope, endpoint_id, source_hash)
    statement = sqlite_insert(ConnectorInboundRateCounter).values(scope=scope,key_hash=key_hash,bucket_start=bucket,window_seconds=window,request_count=1,expires_at=expires).on_conflict_do_update(index_elements=["scope","key_hash","bucket_start"],set_={"request_count":ConnectorInboundRateCounter.request_count+1,"expires_at":expires},where=ConnectorInboundRateCounter.request_count < limit)
    result = db.execute(statement)
    if result.rowcount == 0:
        db.commit(); raise RateLimitExceeded(min(MAX_RETRY_AFTER, max(1, bucket + window - int(instant))))
    db.commit()
    count = db.query(ConnectorInboundRateCounter.request_count).filter_by(scope=scope,key_hash=key_hash,bucket_start=bucket).scalar()
    return limit - int(count)


def enforce_request(db: Session, endpoint_id: int, source: str | None, *, now: float | None = None, limits: dict | None = None) -> str:
    hashed=source_key(source); limits=limits or {}
    for scope in ("global","endpoint","source"):
        values=limits.get(scope,DEFAULT_LIMITS[scope]); consume(db,scope,endpoint_id,hashed,now=now,limit=values[0],window=values[1])
    return hashed


def record_failure(db: Session, endpoint_id: int, source_hash: str, kind: str, *, now: float | None = None, limits: dict | None = None) -> None:
    scope=kind if kind in {"signature","replay"} else "invalid"; values=(limits or {}).get(scope,DEFAULT_LIMITS[scope]); consume(db,scope,endpoint_id,source_hash,now=now,limit=values[0],window=values[1])


def cleanup(db: Session, *, now: datetime | None = None) -> int:
    result=db.execute(delete(ConnectorInboundRateCounter).where(ConnectorInboundRateCounter.expires_at < (now or datetime.now(timezone.utc).replace(tzinfo=None))));db.commit();return int(result.rowcount or 0)
