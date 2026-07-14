import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .models import SecurityAuditEvent, UserAccount
from .redaction import redact
from .role_service import role_keys


LIMITATIONS = (
    "Audit hash chaining provides local tamper evidence. It does not provide external notarization "
    "or prevent a privileged database administrator from rewriting the complete chain."
)


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_payload(event: SecurityAuditEvent) -> str:
    fields = {
        "sequence_number": event.sequence_number,
        "event_type": event.event_type,
        "actor_user_id": event.actor_user_id,
        "actor_username_snapshot": event.actor_username_snapshot,
        "actor_role_keys_json": event.actor_role_keys_json,
        "action": event.action,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "route_template": event.route_template,
        "request_method": event.request_method,
        "request_id": event.request_id,
        "outcome": event.outcome,
        "status_code": event.status_code,
        "reason_code": event.reason_code,
        "metadata_json": event.metadata_json,
        "client_ip_hash": event.client_ip_hash,
        "user_agent_summary": event.user_agent_summary,
        "occurred_at": event.occurred_at.isoformat(),
        "previous_event_hash": event.previous_event_hash,
    }
    return hashlib.sha256(_canonical(fields).encode("utf-8")).hexdigest()


def append_event(
    db: Session,
    *,
    event_type: str,
    action: str,
    request_id: str,
    outcome: str,
    actor: UserAccount | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    route_template: str | None = None,
    request_method: str | None = None,
    status_code: int | None = None,
    reason_code: str | None = None,
    metadata: dict[str, Any] | None = None,
    client_ip_hash: str | None = None,
    user_agent_summary: str | None = None,
) -> SecurityAuditEvent:
    previous = db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number.desc()).first()
    event = SecurityAuditEvent(
        sequence_number=(previous.sequence_number + 1) if previous else 1,
        event_type=event_type[:80],
        actor_user_id=actor.id if actor else None,
        actor_username_snapshot=actor.username[:64] if actor else None,
        actor_role_keys_json=_canonical(role_keys(db, actor.id) if actor else []),
        action=action[:120],
        resource_type=resource_type[:80] if resource_type else None,
        resource_id=str(resource_id)[:100] if resource_id is not None else None,
        route_template=route_template[:250] if route_template else None,
        request_method=request_method[:10] if request_method else None,
        request_id=request_id[:64],
        outcome=outcome,
        status_code=status_code,
        reason_code=reason_code[:80] if reason_code else None,
        metadata_json=_canonical(redact(metadata or {})),
        client_ip_hash=client_ip_hash,
        user_agent_summary=user_agent_summary[:200] if user_agent_summary else None,
        occurred_at=datetime.now(timezone.utc).replace(tzinfo=None),
        previous_event_hash=previous.event_hash if previous else None,
        event_hash="pending",
    )
    event.event_hash = _hash_payload(event)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def verify_integrity(db: Session) -> dict[str, Any]:
    events = db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number).all()
    previous_hash = None
    for expected_sequence, event in enumerate(events, 1):
        expected_hash = _hash_payload(event)
        if event.sequence_number != expected_sequence or event.previous_event_hash != previous_hash or event.event_hash != expected_hash:
            return {
                "events_examined": expected_sequence,
                "valid_chain": False,
                "first_invalid_sequence": event.sequence_number,
                "first_invalid_event_id": event.id,
                "expected_hash": expected_hash,
                "observed_hash": event.event_hash,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "limitations": LIMITATIONS,
            }
        previous_hash = event.event_hash
    return {
        "events_examined": len(events),
        "valid_chain": True,
        "first_invalid_sequence": None,
        "first_invalid_event_id": None,
        "expected_hash": None,
        "observed_hash": None,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "limitations": LIMITATIONS,
    }

