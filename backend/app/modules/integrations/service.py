import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.modules.access_control.audit_service import append_event
from app.modules.access_control.models import UserAccount
from app.modules.platform_operations.maintenance_service import add_activity, notify
from app.modules.production.config import RuntimeProfile, get_runtime_config

from . import adapters
from .catalog import AUTHENTICATION_METHODS, CONNECTOR_CATALOG, EVENT_TYPES, SAFE_API_KEY_HEADERS
from .mapping import apply_mapping, validate_mapping
from .models import (
    ConnectorCredential, ConnectorDeadLetter, ConnectorDelivery, ConnectorDeliveryAttempt,
    ConnectorExternalReference, ConnectorFieldMapping, ConnectorHealthCheck, ConnectorInboundEndpoint,
    ConnectorInboundEvent, ConnectorInstance, ConnectorNetworkPolicy, ConnectorReplayNonce,
    ConnectorReport, ConnectorSubscription, ConnectorSyncCursor, IntegrationOutboxEvent, StixImportRun, utcnow,
)
from .security import IntegrationSecurityError, canonical_json, contains_secret_key, credential_key_available, decrypt_secret, encrypt_secret, last_four, redact, sha256, validate_destination


MAX_JSON = 262144
TERMINAL = {"succeeded", "succeeded_with_warnings", "failed", "dead_letter", "cancelled"}
RETRYABLE_HTTP = {408, 425, 429, 500, 502, 503, 504}
RETRY_SCHEDULE = (0, 30, 120, 600, 1800, 3600, 7200)

NOTIFICATION_MATRIX = {
    "connector_activated": ("Connector activated","success","owner"), "connector_unhealthy": ("Connector unhealthy","danger","owner_admin"),
    "connector_recovered": ("Connector recovered","success","owner"), "circuit_opened": ("Connector circuit opened","danger","owner_admin"),
    "circuit_half_open": ("Connector circuit half-open","warning","owner_admin"), "circuit_reset": ("Connector circuit reset","success","owner_admin"),
    "credential_nearing_expiry": ("Connector credential nearing expiry","warning","admin"), "credential_rotated": ("Connector credential rotated","success","admin"),
    "private_network_policy_changed": ("Private connector policy changed","warning","admin"), "delivery_terminal_failure": ("Connector delivery failed","danger","owner"),
    "delivery_dead_lettered": ("Connector delivery moved to dead letter","danger","owner"), "dead_letter_replay_failed": ("Dead-letter replay failed","danger","owner_admin"),
    "signature_failure_threshold": ("Inbound signature failures detected","danger","admin"), "replay_attack_threshold": ("Inbound replay attempts detected","danger","admin"),
    "quarantined_high_severity": ("High-severity inbound event quarantined","warning","owner"), "taxii_sync_failed": ("TAXII synchronization failed","danger","owner_admin"),
    "external_ticket_created": ("External ticket created","success","owner"), "soar_connector_delivery": ("SOAR connector delivery queued","info","owner"),
}


def emit_notification(db, event_key, connector, entity_type, entity_id, message, actor_id=None):
    from app.models import Notification
    from app.modules.access_control.models import UserAccount
    from app.modules.access_control.role_service import effective_permissions
    if db.new or db.dirty or db.deleted:raise RuntimeError("Integration notifications require a committed source transaction")
    title, level, audience=NOTIFICATION_MATRIX[event_key];recipients=[]
    for user in db.query(UserAccount).filter_by(status="active").all():
        permissions=effective_permissions(db,user);owner=user.id in {connector.owner_user_id,connector.created_by_user_id,actor_id};admin=user.is_system_admin and "integrations:manage" in permissions
        if "integrations:view" in permissions and ((audience=="owner" and owner) or (audience=="admin" and admin) or (audience=="owner_admin" and (owner or admin))):recipients.append(user.id)
    from app.modules.soc_monitor.redaction import redact_text
    safe=redact_text(str(message),500).replace("http://","hxxp://").replace("https://","hxxps://")
    for recipient in sorted(set(recipients)):
        if not db.query(Notification).filter_by(title=title,entity_type=entity_type,entity_id=entity_id,recipient_user_id=recipient).first():db.add(Notification(title=title,message=safe,type=level,entity_type=entity_type,entity_id=entity_id,recipient_user_id=recipient))
    db.commit()


def seed_defaults(db: Session):
    """Seed only immutable safe mapping metadata; never credentials or live endpoints."""
    from app.modules.access_control.models import UserAccount
    admin=db.query(UserAccount).filter_by(is_system_admin=True).order_by(UserAccount.id).first()
    if not admin:return
    name="ThreatScope minimal notification mapping"
    if not db.query(ConnectorFieldMapping).filter_by(name=name,system_owned=True).first():
        rules=[{"target":"title","source":"title","transform":"truncate","length":240},{"target":"summary","source":"summary","transform":"truncate","length":1000},{"target":"severity","source":"severity","transform":"direct"},{"target":"event_id","source":"event_id","transform":"direct"}]
        encoded=canonical_json(rules);validation=validate_mapping(rules);db.add(ConnectorFieldMapping(mapping_uuid=str(uuid.uuid4()),name=name,direction="outbound",source_schema="threatscope.integration.event.v1",target_schema="minimal.notification.v1",mapping_json=encoded,validation_status="valid",validation_summary_json=canonical_json(validation),content_sha256=sha256(encoded),system_owned=True,created_by_user_id=admin.id));db.commit()


def row(item, exclude=()):
    data = {c.name: getattr(item, c.name) for c in item.__table__.columns if c.name not in set(exclude) | {"encrypted_payload", "html_content"}}
    for key in list(data):
        if key.endswith("_json"):
            try: data[key[:-5]] = json.loads(data.pop(key) or "{}")
            except (ValueError, TypeError): data[key[:-5]] = None
    return data


def page(query, page_number=1, page_size=50):
    page_number = max(1, int(page_number)); page_size = min(max(1, int(page_size)), 100); total = query.count()
    return {"items": [row(x) for x in query.offset((page_number - 1) * page_size).limit(page_size).all()], "page": page_number, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}


def _json(value, limit=MAX_JSON):
    encoded = canonical_json(value)
    if len(encoded.encode()) > limit: raise IntegrationSecurityError("CONNECTOR_PAYLOAD_TOO_LARGE", "JSON payload exceeds the configured bound")
    return encoded


def normalize_name(value):
    name = " ".join(str(value).split())[:160]
    if not name: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Connector name is required")
    return name, name.casefold()


def _policy_dict(policy):
    return {"network_scope": policy.network_scope, "allowed_hosts": json.loads(policy.allowed_hosts_json), "allowed_ports": json.loads(policy.allowed_ports_json), "allowed_cidrs": json.loads(policy.allowed_cidrs_json), "redirect_policy": policy.redirect_policy, "maximum_request_bytes": policy.maximum_request_bytes, "maximum_response_bytes": policy.maximum_response_bytes}


def create_connector(db: Session, payload: dict, actor_id: int):
    definition = CONNECTOR_CATALOG.get(payload.get("connector_type"))
    if not definition: raise IntegrationSecurityError("CONNECTOR_TYPE_UNKNOWN", "Unknown connector type")
    name, normalized = normalize_name(payload.get("name"))
    config = payload.get("configuration") or {}
    if not isinstance(config, dict) or contains_secret_key(config): raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Secrets must not be stored in connector configuration")
    encoded = _json(config)
    item = ConnectorInstance(connector_uuid=str(uuid.uuid4()), connector_type=definition.connector_type, name=name, normalized_name=normalized, description=str(payload.get("description") or "")[:2000] or None, direction=definition.direction, configuration_json=encoded, configuration_sha256=sha256(encoded), payload_profile=payload.get("payload_profile", "minimal"), timeout_seconds=int(payload.get("timeout_seconds", definition.default_timeout_seconds)), retry_limit=int(payload.get("retry_limit", definition.default_retry_limit)), created_by_user_id=actor_id, owner_user_id=payload.get("owner_user_id") or actor_id, demo_owned=bool(payload.get("demo_owned", False)))
    db.add(item); db.flush()
    host = _configured_host(config)
    db.add(ConnectorNetworkPolicy(connector_id=item.id, network_scope="local_test_only" if item.connector_type == "local_test_sink" else "public_https", allowed_hosts_json=_json([host] if host else []), allowed_ports_json="[443]", allowed_cidrs_json="[]"))
    add_activity(db, "connector_created", f"Integration connector {item.name} created as disabled draft.", "integration_connector", item.id)
    db.commit(); db.refresh(item); return item


def _configured_url(config):
    for key in ("url", "base_url", "api_root_url"):
        if config.get(key): return str(config[key])
    return None


def _configured_host(config):
    url = _configured_url(config)
    return (urlsplit(url).hostname or "").rstrip(".").casefold() if url else (str(config.get("host") or "").rstrip(".").casefold() or None)


def validate_configuration(db: Session, connector: ConnectorInstance, resolver=None):
    definition = CONNECTOR_CATALOG.get(connector.connector_type); errors=[]; warnings=[]
    if not definition: return {"valid": False, "errors": [{"code":"CONNECTOR_TYPE_UNKNOWN","message":"Unknown connector type"}], "warnings":[], "activation_eligible":False}
    try: config = json.loads(connector.configuration_json)
    except ValueError: config={}; errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"Configuration JSON is invalid"})
    required = definition.configuration_schema.get("required", [])
    for field in required:
        if config.get(field) in (None, "", []): errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","field":field,"message":f"{field} is required"})
    if connector.timeout_seconds < 1 or connector.timeout_seconds > definition.maximum_timeout_seconds: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","field":"timeout_seconds","message":"Timeout is outside safe bounds"})
    if connector.retry_limit < 0 or connector.retry_limit > definition.maximum_retry_limit: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","field":"retry_limit","message":"Retry limit is outside safe bounds"})
    if connector.payload_profile not in definition.supported_payload_profiles: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","field":"payload_profile","message":"Payload profile is unsupported"})
    if contains_secret_key(config): errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"Configuration contains a secret-like key"})
    if config.get("authentication_method") and config["authentication_method"] not in AUTHENTICATION_METHODS: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"Authentication method is unsupported"})
    header = str(config.get("api_key_header", "")).casefold()
    if header and header not in SAFE_API_KEY_HEADERS: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"API-key header is prohibited"})
    if connector.connector_type == "smtp_email":
        if config.get("tls_mode") not in {"starttls", "implicit_tls"}: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"SMTP TLS is required"})
        if int(config.get("maximum_recipients", 20)) > 20: errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"SMTP recipient limit exceeds the hard maximum"})
    if connector.connector_type == "servicenow_incident" and config.get("table", "incident") != "incident": errors.append({"code":"CONNECTOR_CONFIGURATION_INVALID","message":"Only the incident table is approved"})
    policy = db.query(ConnectorNetworkPolicy).filter_by(connector_id=connector.id).first()
    url = _configured_url(config)
    if url and policy:
        try: validate_destination(url, _policy_dict(policy), resolver=resolver) if resolver else validate_destination(url, _policy_dict(policy))
        except IntegrationSecurityError as exc: errors.append({"code":exc.code,"message":str(exc)})
    credential = db.query(ConnectorCredential).filter_by(connector_id=connector.id, configured=True).first()
    needs_credential = bool(definition.credential_schema.get("required"))
    if needs_credential and not credential: warnings.append({"code":"CONNECTOR_CREDENTIAL_REQUIRED","message":"A write-only credential must be configured before activation"})
    valid = not errors
    return {"valid":valid,"errors":errors[:30],"warnings":warnings[:30],"normalized_configuration":redact(config),"required_credentials":definition.credential_schema.get("required", []),"network_summary":_policy_dict(policy) if policy else {},"data_egress_summary":{"profile":connector.payload_profile,"raw_evidence":False,"secrets":False},"supported_capabilities":list(definition.supported_capabilities),"activation_eligible":valid and (not needs_credential or bool(credential)) and connector.last_test_status=="passed"}


def update_connector(db, item, payload):
    lock = payload.get("optimistic_lock_version")
    if lock is None or int(lock) != item.optimistic_lock_version: raise IntegrationSecurityError("CONNECTOR_OPTIMISTIC_LOCK_CONFLICT", "Connector was modified by another request")
    if item.lifecycle_status == "archived": raise IntegrationSecurityError("CONNECTOR_ARCHIVED", "Archived connector is immutable")
    if "name" in payload: item.name, item.normalized_name = normalize_name(payload["name"])
    if "description" in payload: item.description = str(payload["description"] or "")[:2000] or None
    if "configuration" in payload:
        if contains_secret_key(payload["configuration"]): raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID", "Secrets must use the credential endpoint")
        item.configuration_json=_json(payload["configuration"]); item.configuration_sha256=sha256(item.configuration_json); item.last_test_status=None; item.health_status="unknown"
    for field in ("payload_profile", "timeout_seconds", "retry_limit", "owner_user_id"):
        if field in payload: setattr(item, field, payload[field])
    item.optimistic_lock_version += 1; db.commit(); db.refresh(item); return item


def set_credential(db, connector, credential_type, secret_payload, actor_id, rotate=False):
    if not isinstance(secret_payload, dict) or not secret_payload: raise IntegrationSecurityError("CONNECTOR_SECRET_INVALID", "A non-empty credential is required")
    if any(str(v) in {"********", "••••••••", "[REDACTED]"} for v in secret_payload.values()): raise IntegrationSecurityError("CONNECTOR_SECRET_INVALID", "Masked placeholders are not credentials")
    definition=CONNECTOR_CATALOG[connector.connector_type]; required=definition.credential_schema.get("required", [])
    if any(not secret_payload.get(k) for k in required): raise IntegrationSecurityError("CONNECTOR_SECRET_INVALID", "Required credential fields are missing")
    item=db.query(ConnectorCredential).filter_by(connector_id=connector.id).first();stored_payload=dict(secret_payload)
    if rotate and item and connector.connector_type=="generic_hmac_webhook_inbound":
        previous=decrypt_secret(item.encrypted_payload);previous_secret=previous.get("signing_secret")
        if previous_secret and previous_secret!=stored_payload.get("signing_secret"):
            stored_payload["_previous_signing_secret"]=previous_secret;stored_payload["_previous_valid_until"]=(utcnow()+timedelta(minutes=5)).isoformat()
    ciphertext=encrypt_secret(stored_payload)
    if item:
        item.encrypted_payload=ciphertext; item.credential_type=credential_type; item.credential_version += 1; item.rotated_by_user_id=actor_id; item.rotated_at=utcnow(); item.configured=True; item.disabled_at=None
    else:
        item=ConnectorCredential(connector_id=connector.id,credential_type=credential_type,encrypted_payload=ciphertext,created_by_user_id=actor_id);db.add(item)
    connector.last_test_status=None; connector.health_status="unknown"; connector.optimistic_lock_version += 1
    add_activity(db,"credential_rotated" if rotate else "credential_configured",f"Write-only connector credential {'rotated' if rotate else 'configured'} for {connector.name}.","integration_connector",connector.id)
    db.commit(); db.refresh(item)
    if rotate: emit_notification(db,"credential_rotated",connector,"integration_connector",connector.id,f"Credential version {item.credential_version} was rotated; secret material is not displayed.",actor_id)
    return credential_status(item)


def credential_status(item):
    if not item: return {"configured":False,"credential_type":None,"last_four":None,"created_at":None,"rotated_at":None,"version":0,"key_available":credential_key_available()}
    suffix=None
    if credential_key_available():
        try: suffix=last_four(decrypt_secret(item.encrypted_payload))
        except IntegrationSecurityError: suffix=None
    return {"configured":bool(item.configured and not item.disabled_at),"credential_type":item.credential_type,"last_four":suffix,"created_at":item.created_at,"rotated_at":item.rotated_at,"version":item.credential_version,"key_version":item.encryption_key_version,"key_available":credential_key_available()}


def remove_credential(db, connector, actor_id):
    item=db.query(ConnectorCredential).filter_by(connector_id=connector.id).first()
    if item: item.configured=False; item.disabled_at=utcnow(); item.encrypted_payload=encrypt_secret({"removed":True,"nonce":secrets.token_urlsafe(16)})
    connector.enabled=False; connector.lifecycle_status="disabled"; connector.health_status="disabled"; connector.optimistic_lock_version+=1
    add_activity(db,"credential_removed",f"Connector credential removed and {connector.name} disabled.","integration_connector",connector.id);db.commit()


TRANSITIONS={"move-to-testing":{"draft":"testing","disabled":"testing"},"activate":{"testing":"active","disabled":"active","degraded":"active"},"disable":{"active":"disabled","degraded":"disabled"},"archive":{"draft":"archived","testing":"archived","disabled":"archived"}}


def transition(db, connector, action, actor_id, lock):
    if lock is None or int(lock)!=connector.optimistic_lock_version: raise IntegrationSecurityError("CONNECTOR_OPTIMISTIC_LOCK_CONFLICT","Connector version conflict")
    target=TRANSITIONS.get(action,{}).get(connector.lifecycle_status)
    if not target: raise IntegrationSecurityError("CONNECTOR_DELIVERY_CONFLICT","Connector lifecycle transition is not allowed")
    validation=validate_configuration(db,connector)
    if action=="move-to-testing" and not validation["valid"]: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","Configuration must validate before testing")
    if action=="activate" and not validation["activation_eligible"]: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","A successful test and required credential are required before activation")
    connector.lifecycle_status=target;connector.enabled=target=="active";connector.health_status="healthy" if target=="active" else ("disabled" if target in {"disabled","archived"} else connector.health_status);connector.optimistic_lock_version+=1
    if target=="active": connector.activated_by_user_id=actor_id
    if target=="archived": connector.archived_at=utcnow()
    add_activity(db,f"connector_{target}",f"Connector {connector.name} moved to {target}.","integration_connector",connector.id);db.commit();db.refresh(connector)
    if target=="active":emit_notification(db,"connector_activated",connector,"integration_connector",connector.id,f"Connector {connector.name} was activated.",actor_id)
    return connector


def test_connector(db, connector, actor_id, send=False, resolver=None, transport=None):
    previous=connector.health_status;started=utcnow(); validation=validate_configuration(db,connector,resolver=resolver); status="passed" if validation["valid"] else "failed"; summary="Configuration and bounded safety controls passed." if validation["valid"] else "Configuration failed validation."
    if connector.connector_type=="local_test_sink" and validation["valid"]: summary="TEST SINK validated; no external request was performed."
    check=ConnectorHealthCheck(connector_id=connector.id,check_type="capability" if send else "configuration",status=status,started_at=started,completed_at=utcnow(),duration_ms=0,summary=summary,error_code=None if status=="passed" else validation["errors"][0]["code"]);db.add(check)
    connector.last_tested_at=utcnow();connector.last_test_status=status;connector.last_health_check_at=utcnow();connector.health_status="healthy" if status=="passed" else "unhealthy"
    add_activity(db,"connector_tested",f"Connector {connector.name} test {status}; secrets were not exposed.","integration_connector",connector.id);db.commit();db.refresh(check)
    if status=="failed":emit_notification(db,"connector_unhealthy",connector,"integration_connector",connector.id,f"Connector {connector.name} failed a bounded health test.",actor_id)
    elif previous in {"unhealthy","degraded"}:emit_notification(db,"connector_recovered",connector,"integration_connector",connector.id,f"Connector {connector.name} recovered after a successful test.",actor_id)
    return {**row(check),"validation":validation,"external_request_performed":False}


def canonical_event(event_type, source_module, entity_type, entity_id, title, summary, payload=None, severity=None, actor_id=None, correlation_id=None, profile="minimal", event_id=None):
    if event_type not in EVENT_TYPES: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","Unsupported integration event type")
    event_id=event_id or str(uuid.uuid4()); redacted=redact(payload or {}); now=datetime.now(timezone.utc).isoformat()
    data={"event_id":event_id,"schema_version":"1.0","event_type":event_type,"occurred_at":now,"emitted_at":now,"source_module":source_module[:80],"source_entity_type":entity_type[:80],"source_entity_id":str(entity_id)[:100],"correlation_id":correlation_id,"severity":severity,"confidence":None,"title":str(title)[:240],"summary":str(summary)[:1000],"tags":[],"actor_type":"user" if actor_id else "system","actor_id":actor_id,"payload_profile":profile,"redacted_payload":redacted}
    content=canonical_json(data);data["content_sha256"]=sha256(content);data["idempotency_key"]=sha256(f"{event_type}:{source_module}:{entity_type}:{entity_id}:{data['content_sha256']}");return data


def enqueue_outbox(db, event, available_at=None):
    encoded=_json(event); item=IntegrationOutboxEvent(event_uuid=event["event_id"],event_type=event["event_type"],schema_version=event["schema_version"],source_module=event["source_module"],source_entity_type=event["source_entity_type"],source_entity_id=event["source_entity_id"],correlation_id=event.get("correlation_id"),idempotency_key=event["idempotency_key"],canonical_event_json=encoded,content_sha256=sha256(encoded),available_at=available_at or utcnow());db.add(item);db.flush();return item


def queue_delivery(db, connector, payload, event_type, operation, idempotency_key, actor_id=None, subscription_id=None, outbox_id=None, soar_execution_id=None):
    if connector.lifecycle_status!="active" or not connector.enabled: raise IntegrationSecurityError("CONNECTOR_NOT_ACTIVE","Connector is not active")
    if connector.circuit_state=="open" and (not connector.circuit_retry_at or connector.circuit_retry_at>utcnow()): raise IntegrationSecurityError("CONNECTOR_CIRCUIT_OPEN","Connector circuit is open")
    existing=db.query(ConnectorDelivery).filter_by(idempotency_key=idempotency_key).first()
    if existing:return existing
    safe=redact(payload);encoded=_json(safe,min(MAX_JSON,262144));item=ConnectorDelivery(delivery_uuid=str(uuid.uuid4()),connector_id=connector.id,subscription_id=subscription_id,outbox_event_id=outbox_id,soar_execution_id=soar_execution_id,event_type=event_type,external_operation=operation,idempotency_key=idempotency_key,payload_json=encoded,payload_sha256=sha256(encoded),payload_profile=connector.payload_profile,maximum_attempts=min(connector.retry_limit or 1,7),created_by_user_id=actor_id);db.add(item);db.flush();add_activity(db,"delivery_queued",f"Redacted delivery queued for connector {connector.name}.","integration_delivery",item.id);return item


def _retry_after(headers):
    try:return min(max(int((headers or {}).get("retry-after",0)),0),3600) or None
    except (TypeError,ValueError):return None


def _dead_letter(db, delivery, code, summary):
    delivery.status="dead_letter";delivery.completed_at=utcnow();delivery.error_code=code;delivery.error_summary=summary[:1000]
    if not db.query(ConnectorDeadLetter).filter_by(delivery_id=delivery.id).first(): db.add(ConnectorDeadLetter(delivery_id=delivery.id,connector_id=delivery.connector_id,reason_code=code,reason_summary=summary[:1000],payload_summary_json=_json(redact(json.loads(delivery.payload_json))),final_attempt_number=delivery.attempt_count))
    add_activity(db,"delivery_dead_lettered",f"Connector delivery moved to dead letter: {code}.","integration_delivery",delivery.id)


def _record_soar_delivery_outcome(db, delivery):
    """Append one safe, idempotent delivery outcome to the linked SOAR timeline."""
    if not delivery.soar_execution_id or delivery.status not in {"succeeded", "dead_letter", "waiting_retry"}:
        return
    from app.modules.soar.models import SoarExecution, SoarExecutionEvent

    execution = db.get(SoarExecution, delivery.soar_execution_id)
    if not execution:
        return
    event_type = f"connector_delivery_{delivery.status}"
    stable_summary = f"Connector delivery {delivery.delivery_uuid[:12]} reached {delivery.status}."
    duplicate = db.query(SoarExecutionEvent).filter_by(
        execution_id=execution.id,
        event_type=event_type,
        summary=stable_summary,
    ).first()
    if duplicate:
        return
    db.add(SoarExecutionEvent(
        execution_id=execution.id,
        event_type=event_type,
        actor_user_id=delivery.created_by_user_id,
        summary=stable_summary,
        metadata_json=_json({
            "delivery_id": delivery.id,
            "connector_id": delivery.connector_id,
            "status": delivery.status,
            "error_code": delivery.error_code,
        }),
    ))
    db.commit()


def _case_sync_context(db, delivery, payload):
    """Resolve a previously linked ticket and fail closed on newer local case data."""
    if delivery.external_operation != "update_ticket" or not payload.get("case_id") or not payload.get("external_reference"):
        return None, None
    from app.modules.unified_correlation.models import IncidentCase, IncidentTimelineEvent

    case = db.get(IncidentCase, int(payload["case_id"]))
    reference = db.query(ConnectorExternalReference).filter_by(
        connector_id=delivery.connector_id,
        external_reference_id=str(payload["external_reference"])[:200],
        linked_entity_type="incident_case",
        linked_entity_id=str(payload["case_id"]),
    ).first()
    if not case or not reference:
        raise IntegrationSecurityError("CONNECTOR_SYNC_CONFLICT", "Linked case ticket reference is unavailable")
    if reference.last_synced_at and case.updated_at and case.updated_at > reference.last_synced_at:
        summary = f"External ticket update for {reference.external_reference_id[:40]} paused because the local case is newer."
        exists = db.query(IncidentTimelineEvent).filter_by(case_id=case.id,event_type="external_sync_conflict",summary=summary).first()
        if not exists:
            db.add(IncidentTimelineEvent(case_id=case.id,event_type="external_sync_conflict",summary=summary,actor_label="ThreatScope Integration Hub"))
        add_activity(db,"external_sync_conflict",summary,"incident_case",case.id)
        raise IntegrationSecurityError("CONNECTOR_SYNC_CONFLICT", "Local case data is newer; external update was not sent")
    return case, reference


def _case_timeline_once(db, case_id, event_type, summary):
    from app.modules.unified_correlation.models import IncidentTimelineEvent

    exists = db.query(IncidentTimelineEvent).filter_by(case_id=case_id,event_type=event_type,summary=summary).first()
    if not exists:
        db.add(IncidentTimelineEvent(case_id=case_id,event_type=event_type,summary=summary,actor_label="ThreatScope Integration Hub"))


def _audit_delivery_operation(db, delivery, action, outcome="success", reason_code=None):
    actor=db.get(UserAccount,delivery.created_by_user_id) if delivery.created_by_user_id else None
    append_event(db,event_type="integration_operation",action=action,request_id=delivery.delivery_uuid,outcome=outcome,actor=actor,resource_type="integration_delivery",resource_id=delivery.id,status_code=200 if outcome=="success" else 409,reason_code=reason_code,metadata={"connector_id":delivery.connector_id,"delivery_status":delivery.status,"error_code":delivery.error_code})


def deliver(db, delivery, resolver=None, transport=None, smtp_factory=None):
    connector=db.get(ConnectorInstance,delivery.connector_id)
    if not connector or connector.lifecycle_status!="active" or not connector.enabled: delivery.status="waiting_retry";delivery.error_code="CONNECTOR_DISABLED";delivery.error_summary="Connector is disabled";db.commit();_record_soar_delivery_outcome(db,delivery);return delivery
    if delivery.status in TERMINAL:return delivery
    if connector.circuit_state=="open" and connector.circuit_retry_at and connector.circuit_retry_at>utcnow(): delivery.status="waiting_retry";delivery.next_attempt_at=connector.circuit_retry_at;db.commit();return delivery
    if connector.circuit_state=="half_open":delivery.status="waiting_retry";delivery.next_attempt_at=connector.circuit_retry_at or utcnow()+timedelta(seconds=30);db.commit();return delivery
    if connector.circuit_state=="open":connector.circuit_state="half_open";db.commit();emit_notification(db,"circuit_half_open",connector,"integration_connector",connector.id,f"Connector {connector.name} entered a single-probe half-open state.",delivery.created_by_user_id)
    prior_health=connector.health_status;prior_circuit=connector.circuit_state;attempt_no=delivery.attempt_count+1;started=utcnow();attempt=ConnectorDeliveryAttempt(delivery_id=delivery.id,attempt_number=attempt_no,status="started",started_at=started,request_size_bytes=len(delivery.payload_json.encode()));db.add(attempt);delivery.status="delivering";delivery.started_at=delivery.started_at or started;delivery.attempt_count=attempt_no;db.flush()
    try:
        config=json.loads(connector.configuration_json);payload=json.loads(delivery.payload_json)
        sync_case,sync_reference=_case_sync_context(db,delivery,payload)
        if connector.connector_type=="local_test_sink": response=adapters.AdapterResponse(200,b'{"status":"stored_redacted_test_delivery"}',0)
        elif get_runtime_config().profile is RuntimeProfile.PRODUCTION and not get_runtime_config().connector_egress_enabled:
            raise IntegrationSecurityError("CONNECTOR_EGRESS_DISABLED", "Outbound connector delivery is disabled by production policy")
        elif connector.connector_type=="smtp_email":
            cred=decrypt_secret(db.query(ConnectorCredential).filter_by(connector_id=connector.id,configured=True).one().encrypted_payload);response=adapters.send_smtp(config,cred,payload,smtp_factory)
        else:
            credential=db.query(ConnectorCredential).filter_by(connector_id=connector.id,configured=True).first()
            if not credential: raise IntegrationSecurityError("CONNECTOR_CREDENTIAL_REQUIRED","Connector credential is required")
            cred=decrypt_secret(credential.encrypted_payload);url,method,body,headers,_=adapters.build_http_request(connector.connector_type,config,cred,payload,delivery.delivery_uuid,delivery.idempotency_key)
            policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=connector.id).one();destination=validate_destination(url,_policy_dict(policy),resolver=resolver) if resolver else validate_destination(url,_policy_dict(policy));attempt.destination_host=destination.hostname;attempt.resolved_address_summary=sha256("|".join(destination.addresses))[:16]
            response=(transport or adapters.bounded_https_send)(destination,method,body,headers,connector.timeout_seconds,policy.maximum_response_bytes)
            if connector.connector_type=="splunk_hec" and config.get("acknowledgements_enabled") and 200<=response.status_code<300:
                try:ack_id=json.loads(response.body).get("ackId")
                except (ValueError,UnicodeError):ack_id=None
                if ack_id is None:raise IntegrationSecurityError("CONNECTOR_DELIVERY_TERMINAL","Splunk acknowledgement identifier is missing")
                ack_url=config["url"].rstrip("/")+"/services/collector/ack";ack_destination=validate_destination(ack_url,_policy_dict(policy),resolver=resolver) if resolver else validate_destination(ack_url,_policy_dict(policy));ack_body=canonical_json({"acks":[ack_id]}).encode();response=(transport or adapters.bounded_https_send)(ack_destination,"POST",ack_body,headers,connector.timeout_seconds,policy.maximum_response_bytes)
                try:acknowledged=bool(json.loads(response.body).get("acks",{}).get(str(ack_id))) if 200<=response.status_code<300 else False
                except (ValueError,UnicodeError):acknowledged=False
                if not acknowledged:raise IntegrationSecurityError("CONNECTOR_TIMEOUT","Splunk acknowledgement was not confirmed by the bounded check")
        attempt.response_status_code=response.status_code;attempt.response_size_bytes=len(response.body);attempt.duration_ms=response.duration_ms;delivery.response_status_code=response.status_code;delivery.response_summary=(response.body.decode("utf-8","replace")[:300] if response.body else "No response body")
        if 200<=response.status_code<300:
            attempt.status="succeeded";delivery.status="succeeded";delivery.completed_at=utcnow();connector.consecutive_failures=0;connector.circuit_state="closed";connector.health_status="healthy";connector.last_success_at=utcnow();delivery.error_code=None;delivery.error_summary=None
            if response.external_reference:
                linked_type="incident_case" if payload.get("case_id") else str(payload.get("linked_entity_type") or "integration_delivery")[:80];linked_id=str(payload.get("case_id") or payload.get("linked_entity_id") or delivery.id)[:100]
                reference=db.query(ConnectorExternalReference).filter_by(connector_id=connector.id,external_reference_id=str(response.external_reference)[:200]).first()
                safe_url=None
                if response.external_reference_url:
                    candidate=urlsplit(str(response.external_reference_url));configured=urlsplit(_configured_url(config) or "")
                    if candidate.scheme=="https" and candidate.hostname and candidate.hostname.casefold()==(configured.hostname or "").casefold():safe_url=str(response.external_reference_url)[:2000]
                if not reference:
                    reference=ConnectorExternalReference(connector_id=connector.id,external_system_type=connector.connector_type,external_object_type="ticket",external_reference_id=str(response.external_reference)[:200],safe_external_url=safe_url,linked_entity_type=linked_type,linked_entity_id=linked_id,last_synced_at=utcnow());db.add(reference);db.flush()
                delivery.external_reference=reference.external_reference_id;delivery.external_reference_url=reference.safe_external_url
                add_activity(db,"external_ticket_created",f"External ticket reference {reference.external_reference_id[:40]} linked safely to {linked_type} {linked_id}.",linked_type,int(linked_id) if linked_id.isdigit() else None)
                if linked_type=="incident_case" and linked_id.isdigit():_case_timeline_once(db,int(linked_id),"external_ticket_synchronized",f"External ticket {reference.external_reference_id[:40]} linked safely through {connector.connector_type}.")
            if sync_case and sync_reference:
                sync_reference.last_synced_at=utcnow();_case_timeline_once(db,sync_case.id,"external_ticket_synchronized",f"External ticket {sync_reference.external_reference_id[:40]} received an approved bounded update.")
            add_activity(db,"delivery_succeeded",f"Connector delivery {delivery.delivery_uuid[:12]} succeeded.","integration_delivery",delivery.id)
        elif response.status_code in RETRYABLE_HTTP: raise IntegrationSecurityError("CONNECTOR_RATE_LIMITED" if response.status_code==429 else "CONNECTOR_TIMEOUT",f"Temporary external response {response.status_code}")
        else: raise IntegrationSecurityError("CONNECTOR_AUTHENTICATION_FAILED" if response.status_code==401 else "CONNECTOR_AUTHORIZATION_FAILED" if response.status_code==403 else "CONNECTOR_DELIVERY_TERMINAL",f"Terminal external response {response.status_code}")
    except IntegrationSecurityError as exc:
        attempt.error_code=exc.code;attempt.error_summary=str(exc)[:500];connector.last_failure_at=utcnow();retryable=exc.code in {"CONNECTOR_TIMEOUT","CONNECTOR_RATE_LIMITED"};connector.consecutive_failures+=1 if retryable else 0
        if retryable and attempt_no<delivery.maximum_attempts:
            delay=_retry_after(response.headers) if exc.code=="CONNECTOR_RATE_LIMITED" and "response" in locals() else None;delay=delay or RETRY_SCHEDULE[min(attempt_no,len(RETRY_SCHEDULE)-1)];attempt.retry_after_seconds=delay;attempt.status="failed_retryable";delivery.status="waiting_retry";delivery.next_attempt_at=utcnow()+timedelta(seconds=delay);delivery.error_code=exc.code;delivery.error_summary=str(exc)[:1000]
        else:
            attempt.status="failed_terminal";_dead_letter(db,delivery,exc.code,str(exc))
        if connector.consecutive_failures>=5: connector.circuit_state="open";connector.circuit_opened_at=utcnow();connector.circuit_retry_at=utcnow()+timedelta(minutes=15);connector.health_status="unhealthy"
    finally:
        attempt.completed_at=utcnow();db.commit()
    if delivery.status=="dead_letter":
        _audit_delivery_operation(db,delivery,"dead_letter_creation",reason_code=delivery.error_code)
        emit_notification(db,"delivery_terminal_failure",connector,"integration_delivery",delivery.id,f"Delivery {delivery.delivery_uuid[:12]} failed terminally with safe code {delivery.error_code}.",delivery.created_by_user_id)
        emit_notification(db,"delivery_dead_lettered",connector,"integration_delivery",delivery.id,f"Delivery {delivery.delivery_uuid[:12]} moved to dead letter with safe code {delivery.error_code}.",delivery.created_by_user_id)
    if delivery.status=="succeeded" and (delivery.external_reference or delivery.external_operation=="update_ticket"):
        _audit_delivery_operation(db,delivery,"external_ticket_update" if delivery.external_operation=="update_ticket" else "external_ticket_creation")
        if delivery.external_reference:emit_notification(db,"external_ticket_created",connector,"integration_delivery",delivery.id,f"External ticket {delivery.external_reference[:40]} was created and linked safely.",delivery.created_by_user_id)
    replay_source=db.query(ConnectorDeadLetter).filter_by(replayed_delivery_id=delivery.id).first()
    if replay_source and delivery.status in {"succeeded","dead_letter"}:
        replay_source.replay_status="succeeded" if delivery.status=="succeeded" else "failed";db.commit();_audit_delivery_operation(db,delivery,"dead_letter_replay_result","success" if delivery.status=="succeeded" else "failure",delivery.error_code)
        if delivery.status=="dead_letter":emit_notification(db,"dead_letter_replay_failed",connector,"integration_dead_letter",replay_source.id,"Dead-letter replay failed once with safe aggregate metadata; payload details are withheld.",delivery.created_by_user_id)
    if connector.circuit_state=="open" and prior_circuit!="open":emit_notification(db,"circuit_opened",connector,"integration_connector",connector.id,f"Connector {connector.name} circuit opened after bounded retryable failures.",delivery.created_by_user_id)
    if delivery.status=="succeeded" and prior_health in {"unhealthy","degraded"}:emit_notification(db,"connector_recovered",connector,"integration_connector",connector.id,f"Connector {connector.name} recovered after successful delivery.",delivery.created_by_user_id)
    _record_soar_delivery_outcome(db,delivery)
    return delivery


def process_due(db, actor_id=None, batch_size=100, resolver=None, transport=None):
    limit=min(max(int(batch_size),1),100);now=utcnow();summary={"outbox_processed":0,"deliveries_processed":0,"retries_processed":0,"nonce_records_removed":0,"failures":0}
    events=db.query(IntegrationOutboxEvent).filter_by(status="pending").filter(IntegrationOutboxEvent.available_at<=now).order_by(IntegrationOutboxEvent.id).limit(limit).all()
    for event in events:
        try:
            canonical=json.loads(event.canonical_event_json);subscriptions=db.query(ConnectorSubscription).filter_by(event_type=event.event_type,enabled=True).order_by(ConnectorSubscription.id).all();created=0
            for sub in subscriptions:
                connector=db.get(ConnectorInstance,sub.connector_id)
                if not connector or not connector.enabled:continue
                filters=json.loads(sub.filter_json or "{}");severity=canonical.get("severity");minimum=filters.get("minimum_severity") or sub.minimum_severity
                if minimum and {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(severity,-1)<{"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(minimum,0):continue
                payload=canonical
                if sub.mapping_id:
                    mapping=db.get(ConnectorFieldMapping,sub.mapping_id);payload=apply_mapping(canonical,json.loads(mapping.mapping_json))
                queue_delivery(db,connector,payload,event.event_type,"notify",sha256(f"{event.idempotency_key}:{sub.id}"),subscription_id=sub.id,outbox_id=event.id);created+=1
            event.status="delivered" if created else "partially_delivered";event.processed_at=utcnow();db.commit();summary["outbox_processed"]+=1
        except Exception as exc:
            db.rollback();event=db.get(IntegrationOutboxEvent,event.id);event.status="failed";event.error_summary=str(exc)[:500];db.commit();summary["failures"]+=1
    due=db.query(ConnectorDelivery).filter(ConnectorDelivery.status.in_(["queued","waiting_retry"])).filter((ConnectorDelivery.next_attempt_at==None)|(ConnectorDelivery.next_attempt_at<=now)).order_by(ConnectorDelivery.id).limit(limit).all()  # noqa: E711
    for item in due:
        connector=db.get(ConnectorInstance,item.connector_id)
        if item.soar_execution_id:emit_notification(db,"soar_connector_delivery",connector,"integration_delivery",item.id,f"SOAR requested connector delivery {item.delivery_uuid[:12]} is ready for bounded processing.",item.created_by_user_id)
        was_retry=item.status=="waiting_retry";deliver(db,item,resolver=resolver,transport=transport);summary["deliveries_processed"]+=1;summary["retries_processed"]+=int(was_retry)
    expiring=db.query(ConnectorCredential).filter(ConnectorCredential.configured.is_(True),ConnectorCredential.expires_at.is_not(None),ConnectorCredential.expires_at<=now+timedelta(days=7),ConnectorCredential.expires_at>now).all()
    for credential in expiring:
        connector=db.get(ConnectorInstance,credential.connector_id);emit_notification(db,"credential_nearing_expiry",connector,"integration_connector",connector.id,f"Credential version {credential.credential_version} is nearing expiry; no secret is displayed.")
    expired=db.query(ConnectorReplayNonce).filter(ConnectorReplayNonce.expires_at<now).limit(limit).all();summary["nonce_records_removed"]=len(expired)
    for item in expired:db.delete(item)
    db.commit();return summary


def replay_dead_letter(db, dead, actor_id, reason):
    if not reason.strip(): raise IntegrationSecurityError("CONNECTOR_REPLAY_NOT_ALLOWED","Replay reason is required")
    if dead.replayed_delivery_id:
        existing=db.get(ConnectorDelivery,dead.replayed_delivery_id)
        if existing:return existing
    original=db.get(ConnectorDelivery,dead.delivery_id);connector=db.get(ConnectorInstance,dead.connector_id)
    if not connector or not connector.enabled or connector.lifecycle_status!="active":
        if connector:emit_notification(db,"dead_letter_replay_failed",connector,"integration_dead_letter",dead.id,"Dead-letter replay failed safe revalidation; payload details are withheld.",actor_id)
        raise IntegrationSecurityError("CONNECTOR_REPLAY_NOT_ALLOWED","Connector must be active, tested, credentialed, and valid")
    if not validate_configuration(db,connector)["activation_eligible"]:
        if connector:emit_notification(db,"dead_letter_replay_failed",connector,"integration_dead_letter",dead.id,"Dead-letter replay failed safe revalidation; payload details are withheld.",actor_id)
        raise IntegrationSecurityError("CONNECTOR_REPLAY_NOT_ALLOWED","Connector must be active, tested, credentialed, and valid")
    replay=queue_delivery(db,connector,json.loads(original.payload_json),original.event_type,original.external_operation,sha256(f"replay:{original.idempotency_key}:{uuid.uuid4()}"),actor_id)
    dead.replay_status="replayed";dead.replayed_delivery_id=replay.id;dead.replay_requested_at=utcnow();dead.replay_requested_by_user_id=actor_id;add_activity(db,"dead_letter_replayed",f"Dead letter {dead.id} replayed as a new delivery.","integration_dead_letter",dead.id);db.commit();return replay


def ingest_inbound(db, endpoint, body: bytes, headers: dict, source_ip=None):
    from .security import source_ip_summary, verify_hmac
    if not endpoint.enabled: raise IntegrationSecurityError("CONNECTOR_DISABLED","Inbound endpoint is disabled")
    content_type=str(headers.get("content-type","")).split(";",1)[0].strip().casefold()
    if content_type!="application/json": raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","JSON content type is required")
    if len(body)>min(endpoint.maximum_body_bytes,524288): raise IntegrationSecurityError("CONNECTOR_PAYLOAD_TOO_LARGE","Inbound body exceeds the configured limit")
    timestamp=str(headers.get("x-threatscope-timestamp", ""));external_id=str(headers.get("x-threatscope-event-id", ""))[:160];signature=str(headers.get("x-threatscope-signature", ""));schema=str(headers.get("x-threatscope-schema-version", ""))
    try: instant=datetime.fromtimestamp(int(timestamp),timezone.utc);delta=abs((datetime.now(timezone.utc)-instant).total_seconds())
    except (ValueError,TypeError,OverflowError) as exc: raise IntegrationSecurityError("CONNECTOR_TIMESTAMP_INVALID","Inbound authentication failed") from exc
    if delta>min(endpoint.timestamp_tolerance_seconds,900): raise IntegrationSecurityError("CONNECTOR_TIMESTAMP_INVALID","Inbound authentication failed")
    if not external_id or not signature or schema!=endpoint.schema_version: raise IntegrationSecurityError("CONNECTOR_SIGNATURE_INVALID","Inbound authentication failed")
    connector=db.get(ConnectorInstance,endpoint.connector_id);credential=db.query(ConnectorCredential).filter_by(connector_id=connector.id,configured=True).first()
    if not credential: raise IntegrationSecurityError("CONNECTOR_SIGNATURE_INVALID","Inbound authentication failed")
    credential_payload=decrypt_secret(credential.encrypted_payload);secret=credential_payload.get("signing_secret","");valid_signature=verify_hmac(str(secret),timestamp,body,signature)
    if not valid_signature and credential_payload.get("_previous_signing_secret") and credential_payload.get("_previous_valid_until"):
        try:overlap_until=datetime.fromisoformat(str(credential_payload["_previous_valid_until"]))
        except ValueError:overlap_until=utcnow()-timedelta(seconds=1)
        if overlap_until>=utcnow():valid_signature=verify_hmac(str(credential_payload["_previous_signing_secret"]),timestamp,body,signature)
    if not valid_signature: raise IntegrationSecurityError("CONNECTOR_SIGNATURE_INVALID","Inbound authentication failed")
    nonce_hash=sha256(f"{endpoint.id}:{external_id}");existing=db.query(ConnectorReplayNonce).filter_by(endpoint_id=endpoint.id,nonce_hash=nonce_hash).first()
    if existing: raise IntegrationSecurityError("CONNECTOR_REPLAY_DETECTED","Inbound authentication failed")
    try: payload=json.loads(body)
    except (UnicodeError,json.JSONDecodeError) as exc: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","Inbound JSON is invalid") from exc
    if not isinstance(payload,dict): raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","Inbound payload must be an object")
    allowed=set(json.loads(endpoint.allowed_event_types_json or "[]"));event_type=str(payload.get("event_type", ""))
    if allowed and event_type not in allowed: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","Inbound event type is not allowlisted")
    redacted=redact(payload);normalized=redacted
    if endpoint.mapping_id:
        mapping=db.get(ConnectorFieldMapping,endpoint.mapping_id);normalized=apply_mapping(redacted,json.loads(mapping.mapping_json))
    nonce=ConnectorReplayNonce(endpoint_id=endpoint.id,nonce_hash=nonce_hash,timestamp_bucket=instant.strftime("%Y%m%d%H%M"),expires_at=utcnow()+timedelta(seconds=min(endpoint.replay_window_seconds,3600)));db.add(nonce)
    event=ConnectorInboundEvent(inbound_event_uuid=str(uuid.uuid4()),endpoint_id=endpoint.id,external_event_id=external_id,schema_version=schema,source_ip_summary=source_ip_summary(source_ip),content_type=content_type,body_size_bytes=len(body),signature_status="valid",replay_status="accepted",content_sha256=sha256(body),raw_payload_redacted_json=_json(redacted),normalized_event_json=_json(normalized),status="validated" if endpoint.trusted_source else "quarantined")
    db.add(event)
    try:db.commit()
    except IntegrityError as exc:db.rollback();raise IntegrationSecurityError("CONNECTOR_REPLAY_DETECTED","Inbound authentication failed") from exc
    db.refresh(event)
    severity=str(redacted.get("severity","")).casefold()
    if event.status=="quarantined" and severity in {"high","critical"}:emit_notification(db,"quarantined_high_severity",connector,"integration_inbound_event",event.id,f"A {severity} inbound event was quarantined for explicit review.")
    return event


def promote_inbound(db,event,target_type,actor_id):
    if event.status=="promoted": raise IntegrationSecurityError("CONNECTOR_DELIVERY_CONFLICT","Inbound event was already promoted")
    if event.status not in {"quarantined","validated"}: raise IntegrationSecurityError("CONNECTOR_PROMOTION_DENIED","Inbound event is not eligible for promotion")
    if target_type not in {"soc_alert","threat_intelligence","case_evidence_proposal","vulnerability_evidence_proposal","analyst_review_task"}: raise IntegrationSecurityError("CONNECTOR_PROMOTION_DENIED","Promotion target is unsupported")
    event.status="promoted";event.promoted_entity_type=target_type;event.promoted_entity_id=f"proposal-{event.id}";event.promoted_by_user_id=actor_id;add_activity(db,"inbound_event_promoted",f"Quarantined inbound event {event.inbound_event_uuid[:12]} promoted to a bounded {target_type} proposal.","integration_inbound_event",event.id);db.commit();return event


def _taxii_pull(db,connector,actor_id,resolver=None,transport=None):
    if connector.connector_type!="taxii_21_collection_pull": raise IntegrationSecurityError("CONNECTOR_TYPE_UNKNOWN","Connector is not TAXII 2.1")
    validation=validate_configuration(db,connector,resolver=resolver)
    if not validation["valid"]: raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","TAXII connector configuration is invalid")
    config=json.loads(connector.configuration_json);credential=db.query(ConnectorCredential).filter_by(connector_id=connector.id,configured=True).first();cred=decrypt_secret(credential.encrypted_payload) if credential else {}
    cursor=db.query(ConnectorSyncCursor).filter_by(connector_id=connector.id).first();added_after=cursor.cursor_value_encrypted_or_hashed if cursor else None
    url=config["api_root_url"].rstrip("/")+"/collections/"+str(config["collection_id"])+"/objects/"+(f"?added_after={added_after}" if added_after else "")
    policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=connector.id).one();destination=validate_destination(url,_policy_dict(policy),resolver=resolver) if resolver else validate_destination(url,_policy_dict(policy));headers={"Accept":"application/taxii+json;version=2.1"}
    if cred.get("token"):headers["Authorization"]="Bearer "+str(cred["token"])
    response=(transport or adapters.bounded_https_send)(destination,"GET",b"",headers,connector.timeout_seconds,policy.maximum_response_bytes)
    if not 200<=response.status_code<300: raise IntegrationSecurityError("CONNECTOR_TIMEOUT",f"TAXII pull returned {response.status_code}")
    try:envelope=json.loads(response.body);objects=envelope.get("objects",[])
    except (ValueError,UnicodeError) as exc:raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","TAXII response is invalid") from exc
    if not isinstance(objects,list) or len(objects)>5000:raise IntegrationSecurityError("CONNECTOR_PAYLOAD_TOO_LARGE","TAXII response object count exceeds the safe maximum")
    run=stix_preview(db,{"type":"bundle","id":"bundle--"+str(uuid.uuid4()),"objects":objects},actor_id,f"TAXII {connector.name}")
    new_cursor=str(response.headers.get("x-taxii-date-added-last") if response.headers else "")[:100] or datetime.now(timezone.utc).isoformat()
    if cursor:cursor.cursor_value_encrypted_or_hashed=new_cursor;cursor.last_successful_sync_at=utcnow();cursor.last_attempt_at=utcnow();cursor.items_processed+=len(objects)
    else:db.add(ConnectorSyncCursor(connector_id=connector.id,cursor_type="taxii_added_after",cursor_value_encrypted_or_hashed=new_cursor,last_successful_sync_at=utcnow(),last_attempt_at=utcnow(),items_processed=len(objects)))
    db.commit();return {"import_run":row(run),"objects_received":len(objects),"cursor_advanced":True,"pages":1,"bounded":True}


def taxii_pull(db,connector,actor_id,resolver=None,transport=None):
    try:return _taxii_pull(db,connector,actor_id,resolver=resolver,transport=transport)
    except Exception:
        db.rollback();emit_notification(db,"taxii_sync_failed",connector,"integration_connector",connector.id,f"TAXII synchronization failed safely for connector {connector.name}; response details are withheld.",actor_id);raise


REPORT_SECTIONS=("Report metadata","Executive summary","Connector inventory","Connector type distribution","Lifecycle distribution","Health distribution","Circuit-breaker status","Credential configuration summary","Credential rotation summary","Network-policy summary","Private-endpoint summary","Subscription inventory","Event-type distribution","Outbox totals","Delivery totals","Delivery success rate","Delivery failures","Retry activity","Dead-letter activity","Replay activity","Response-code distribution","Delivery latency","Payload-profile distribution","Data-egress summary","Inbound endpoint inventory","Inbound event totals","Signature failures","Replay attempts blocked","Quarantined inbound events","Promoted inbound events","STIX import summary","TAXII synchronization summary","Jira references","ServiceNow references","Splunk delivery summary","Slack/Teams/email notification summary","SOAR connector-delivery summary","Security-control summary","RBAC summary","Methodology","Limitations","Secret-handling disclaimer","External-system disclaimer","No-containment disclaimer")


def generate_report(db,title,report_type,filters,user_id):
    metrics=overview(db,aggregate_only=False);parts=["<!doctype html><html><head><meta charset='utf-8'><title>"+escape(title)+"</title></head><body>"]
    for name in REPORT_SECTIONS:parts.append(f"<section><h2>{escape(name)}</h2><p>{escape(canonical_json(metrics)[:2000] if name in {'Executive summary','Connector inventory','Delivery totals'} else 'ThreatScope deterministic, permission-controlled integration-hub review. No credentials, raw external responses, scripts, remote assets, or containment actions are included.')}</p></section>")
    parts.append("</body></html>");html_content="".join(parts);item=ConnectorReport(report_uuid=str(uuid.uuid4()),title=title[:200],report_type=report_type[:60],filters_json=_json(filters or {}),summary_json=_json(metrics),html_content=html_content,generated_by_user_id=user_id);db.add(item);db.flush();add_activity(db,"integration_report_generated",f"Integration report {item.title} generated without secrets.","integration_report",item.id);db.commit();db.refresh(item);return item


def overview(db,aggregate_only=False):
    connectors=db.query(ConnectorInstance);deliveries=db.query(ConnectorDelivery);inbound=db.query(ConnectorInboundEvent);total_deliveries=deliveries.count();success=deliveries.filter(ConnectorDelivery.status.in_(["succeeded","succeeded_with_warnings"])).count()
    data={"total_connectors":connectors.count(),"active_connectors":connectors.filter_by(lifecycle_status="active").count(),"degraded_connectors":connectors.filter_by(lifecycle_status="degraded").count(),"unhealthy_connectors":connectors.filter_by(health_status="unhealthy").count(),"open_circuits":connectors.filter_by(circuit_state="open").count(),"queued_deliveries":deliveries.filter_by(status="queued").count(),"due_retries":deliveries.filter_by(status="waiting_retry").count(),"successful_deliveries":success,"failed_deliveries":deliveries.filter(ConnectorDelivery.status.in_(["failed","dead_letter"])).count(),"dead_letters":db.query(ConnectorDeadLetter).count(),"delivery_success_rate":round(success*100/total_deliveries,2) if total_deliveries else None,"inbound_events":inbound.count(),"quarantined_events":inbound.filter_by(status="quarantined").count(),"rejected_signatures":inbound.filter_by(signature_status="invalid").count(),"replay_attempts_blocked":inbound.filter_by(replay_status="rejected").count(),"stix_objects_imported":sum(x.accepted_count for x in db.query(StixImportRun).all()),"external_tickets_created":db.query(ConnectorExternalReference).count(),"credential_key_available":credential_key_available(),"no_containment":True}
    return data if aggregate_only else {**data,"connector_types":len(CONNECTOR_CATALOG),"supported_event_types":len(EVENT_TYPES)}


STIX_TYPES={"indicator","malware","threat-actor","intrusion-set","campaign","attack-pattern","identity","relationship","marking-definition","observed-data"}


def stix_preview(db,bundle,user_id,source_name="STIX 2.1 upload"):
    encoded=_json(bundle,5242880)
    if bundle.get("type")!="bundle" or not isinstance(bundle.get("objects"),list):raise IntegrationSecurityError("CONNECTOR_CONFIGURATION_INVALID","A STIX 2.1 bundle is required")
    objects=bundle["objects"]
    if len(objects)>5000:raise IntegrationSecurityError("CONNECTOR_PAYLOAD_TOO_LARGE","STIX bundle exceeds 5,000 objects")
    accepted=[];quarantined=[];ids=set()
    for obj in objects:
        kind=obj.get("type");identifier=obj.get("id","")
        valid_id=isinstance(identifier,str) and identifier.startswith(f"{kind}--") and len(identifier)<=200
        if kind in STIX_TYPES and valid_id and identifier not in ids:accepted.append({"id":identifier,"type":kind,"name":str(obj.get("name") or "")[:200],"pattern":str(obj.get("pattern") or "")[:1000]})
        else:quarantined.append({"id":str(identifier)[:200],"type":str(kind)[:80],"reason":"unsupported_or_invalid"})
        ids.add(identifier)
    preview={"bundle_id":str(bundle.get("id") or "")[:200],"accepted":accepted,"quarantined":quarantined,"external_references_fetched":False}
    run=StixImportRun(import_uuid=str(uuid.uuid4()),status="preview",source_name=source_name[:160],content_sha256=sha256(encoded),object_count=len(objects),accepted_count=len(accepted),quarantined_count=len(quarantined),preview_json=_json(preview,5242880),created_by_user_id=user_id);db.add(run);db.commit();db.refresh(run);return run


def stix_promote(db,run,user_id):
    if run.status=="promoted":return run
    preview=json.loads(run.preview_json);accepted=0
    from app.modules.threat_intelligence.models import ThreatIntelSource
    from app.modules.threat_intelligence.service import create_or_merge_indicator
    source=db.query(ThreatIntelSource).filter_by(name=run.source_name).first()
    if not source:source=ThreatIntelSource(name=run.source_name,description="STIX 2.1 import through the quarantined integration hub.",source_type="stix",reliability=60,default_confidence=60,default_tlp="amber",created_by_user_id=user_id);db.add(source);db.flush()
    for obj in preview["accepted"]:
        if obj["type"]!="indicator" or not obj.get("pattern"):continue
        pattern=obj["pattern"]
        import re
        match=re.fullmatch(r"\[(ipv4-addr|ipv6-addr|domain-name|url|file):(?:value|hashes\.'SHA-256')\s*=\s*'([^']{1,2048})'\]",pattern)
        if not match:continue
        kind={"ipv4-addr":"ipv4","ipv6-addr":"ipv6","domain-name":"domain","url":"url","file":"sha256"}[match.group(1)]
        try:create_or_merge_indicator(db,{"type":kind,"value":match.group(2),"source_id":source.id,"title":obj.get("name") or "STIX indicator","confidence":60,"severity":"medium","tlp":"amber"},user_id,externally_supplied=True);accepted+=1
        except HTTPException:continue
    run.status="promoted";run.accepted_count=accepted;run.promoted_at=utcnow();source.last_import_at=utcnow();add_activity(db,"stix_import_promoted",f"STIX import {run.import_uuid[:12]} promoted {accepted} safe indicators.","integration_stix_import",run.id);db.commit();return run
