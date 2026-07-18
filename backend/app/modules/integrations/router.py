import json
import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.modules.access_control.dependencies import get_current_user, require_permission
from app.modules.access_control.audit_service import append_event
from app.modules.access_control.models import UserAccount

from .catalog import CONNECTOR_CATALOG
from .mapping import apply_mapping, validate_mapping
from .models import *  # noqa: F403
from .schemas import *  # noqa: F403
from .security import IntegrationSecurityError, canonical_json, sha256
from . import service, rate_limit


router=APIRouter();public_router=APIRouter()


def _get(db,model,item_id,label="Record"):
    item=db.get(model,item_id)
    if not item:raise HTTPException(404,{"code":"CONNECTOR_NOT_FOUND","message":f"{label} not found"})
    return item


@router.get("/overview")
def overview(db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.overview(db,aggregate_only=not actor.is_system_admin)


@router.get("/catalog")
def catalog():return {"items":[x.to_dict() for x in CONNECTOR_CATALOG.values()],"immutable":True,"server_owned":True}


@router.get("/connectors")
def connectors(page:int=1,page_size:int=50,status:str|None=None,connector_type:str|None=None,db:Session=Depends(get_db)):
    q=db.query(ConnectorInstance).order_by(ConnectorInstance.id.desc())
    if status:q=q.filter_by(lifecycle_status=status)
    if connector_type:q=q.filter_by(connector_type=connector_type)
    return service.page(q,page,page_size)


@router.post("/connectors",status_code=201)
def create_connector(payload:ConnectorCreate,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    values=payload.model_dump(exclude_none=True)
    if values.get("timeout_seconds") is None:values.pop("timeout_seconds",None)
    if values.get("retry_limit") is None:values.pop("retry_limit",None)
    return service.row(service.create_connector(db,values,actor.id))


@router.get("/connectors/{connector_id}")
def connector(connector_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorInstance,connector_id,"Connector"))


@router.patch("/connectors/{connector_id}")
def patch_connector(connector_id:int,payload:ConnectorUpdate,db:Session=Depends(get_db)):return service.row(service.update_connector(db,_get(db,ConnectorInstance,connector_id,"Connector"),payload.model_dump(exclude_none=True)))


@router.post("/connectors/{connector_id}/validate")
def validate_connector(connector_id:int,db:Session=Depends(get_db)):return service.validate_configuration(db,_get(db,ConnectorInstance,connector_id,"Connector"))


@router.post("/connectors/{connector_id}/move-to-testing")
def move_to_testing(connector_id:int,payload:LockAction,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.transition(db,_get(db,ConnectorInstance,connector_id,"Connector"),"move-to-testing",actor.id,payload.optimistic_lock_version))


@router.post("/connectors/{connector_id}/activate")
def activate(connector_id:int,payload:LockAction,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.transition(db,_get(db,ConnectorInstance,connector_id,"Connector"),"activate",actor.id,payload.optimistic_lock_version))


@router.post("/connectors/{connector_id}/disable")
def disable(connector_id:int,payload:LockAction,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.transition(db,_get(db,ConnectorInstance,connector_id,"Connector"),"disable",actor.id,payload.optimistic_lock_version))


@router.post("/connectors/{connector_id}/archive")
def archive(connector_id:int,payload:LockAction,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.transition(db,_get(db,ConnectorInstance,connector_id,"Connector"),"archive",actor.id,payload.optimistic_lock_version))


@router.post("/connectors/{connector_id}/test")
def test(connector_id:int,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.test_connector(db,_get(db,ConnectorInstance,connector_id,"Connector"),actor.id)


@router.post("/connectors/{connector_id}/send-test")
def send_test(connector_id:int,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.test_connector(db,_get(db,ConnectorInstance,connector_id,"Connector"),actor.id,send=True)


@router.post("/connectors/{connector_id}/reset-circuit")
def reset_circuit(connector_id:int,payload:ReasonAction,db:Session=Depends(get_db)):
    item=_get(db,ConnectorInstance,connector_id,"Connector");item.circuit_state="closed";item.circuit_opened_at=None;item.circuit_retry_at=None;item.consecutive_failures=0;db.commit();service.emit_notification(db,"circuit_reset",item,"integration_connector",item.id,f"Connector {item.name} circuit was reset with an explicit bounded reason.");return service.row(item)


@router.get("/connectors/{connector_id}/credential-status")
def get_credential_status(connector_id:int,db:Session=Depends(get_db)):_get(db,ConnectorInstance,connector_id,"Connector");return service.credential_status(db.query(ConnectorCredential).filter_by(connector_id=connector_id).first())


@router.put("/connectors/{connector_id}/credentials")
def put_credentials(connector_id:int,payload:CredentialWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.set_credential(db,_get(db,ConnectorInstance,connector_id,"Connector"),payload.credential_type,payload.secret,actor.id)


@router.post("/connectors/{connector_id}/credentials/rotate")
def rotate_credentials(connector_id:int,payload:CredentialWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.set_credential(db,_get(db,ConnectorInstance,connector_id,"Connector"),payload.credential_type,payload.secret,actor.id,rotate=True)


@router.delete("/connectors/{connector_id}/credentials")
def delete_credentials(connector_id:int,confirmation:str=Body(embed=True),db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    if confirmation!="REMOVE AND DISABLE":raise HTTPException(422,"Explicit removal confirmation is required")
    service.remove_credential(db,_get(db,ConnectorInstance,connector_id,"Connector"),actor.id);return {"removed":True,"connector_disabled":True}


@router.get("/connectors/{connector_id}/network-policy")
def get_network_policy(connector_id:int,db:Session=Depends(get_db)):return service.row(db.query(ConnectorNetworkPolicy).filter_by(connector_id=connector_id).one())


@router.patch("/connectors/{connector_id}/network-policy")
def patch_network_policy(connector_id:int,payload:NetworkPolicyUpdate,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    connector=_get(db,ConnectorInstance,connector_id,"Connector");values=payload.model_dump();private=values["network_scope"]=="approved_private"
    if private and (not actor.is_system_admin or not values.get("reason") or values.get("confirmation")!="APPROVE PRIVATE EGRESS"):raise HTTPException(403,{"code":"CONNECTOR_PERMISSION_DENIED","message":"Administrator approval, reason, and confirmation are required"})
    if any("*" in x for x in values["allowed_hosts"]):raise HTTPException(422,{"code":"CONNECTOR_NETWORK_POLICY_DENIED","message":"Wildcard hosts are prohibited"})
    policy=db.query(ConnectorNetworkPolicy).filter_by(connector_id=connector_id).one();policy.network_scope=values["network_scope"];policy.allowed_hosts_json=canonical_json(values["allowed_hosts"]);policy.allowed_ports_json=canonical_json(values["allowed_ports"]);policy.allowed_cidrs_json=canonical_json(values["allowed_cidrs"]);policy.redirect_policy=values["redirect_policy"];policy.maximum_response_bytes=values["maximum_response_bytes"];policy.maximum_request_bytes=values["maximum_request_bytes"];policy.reason=values.get("reason");policy.approved_by_user_id=actor.id if private else None;connector.last_test_status=None;connector.health_status="unknown";db.commit()
    if private:service.emit_notification(db,"private_network_policy_changed",connector,"integration_connector",connector.id,f"Approved private network policy changed for connector {connector.name}.",actor.id)
    return service.row(policy)


@router.get("/subscriptions")
def subscriptions(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorSubscription).order_by(ConnectorSubscription.id.desc()),page,page_size)


@router.post("/subscriptions",status_code=201)
def create_subscription(payload:SubscriptionWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    connector=_get(db,ConnectorInstance,payload.connector_id,"Connector")
    if not connector.enabled:raise HTTPException(409,{"code":"CONNECTOR_DISABLED","message":"Disabled connectors cannot receive subscriptions"})
    if payload.event_type not in CONNECTOR_CATALOG[connector.connector_type].supported_event_types:raise HTTPException(422,{"code":"CONNECTOR_CONFIGURATION_INVALID","message":"Event type is unsupported"})
    item=ConnectorSubscription(subscription_uuid=str(uuid.uuid4()),connector_id=payload.connector_id,name=payload.name,event_type=payload.event_type,source_module=payload.source_module,filter_json=canonical_json(payload.filter),mapping_id=payload.mapping_id,enabled=payload.enabled,delivery_mode=payload.delivery_mode,digest_window_minutes=payload.digest_window_minutes,minimum_severity=payload.minimum_severity,created_by_user_id=actor.id);db.add(item);db.commit();db.refresh(item);return service.row(item)


@router.get("/subscriptions/{item_id}")
def subscription(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorSubscription,item_id,"Subscription"))


@router.patch("/subscriptions/{item_id}")
def patch_subscription(item_id:int,payload:SubscriptionWrite,db:Session=Depends(get_db)):
    item=_get(db,ConnectorSubscription,item_id,"Subscription")
    for k,v in payload.model_dump().items():setattr(item,"filter_json" if k=="filter" else k,canonical_json(v) if k=="filter" else v)
    db.commit();return service.row(item)


@router.delete("/subscriptions/{item_id}")
def delete_subscription(item_id:int,db:Session=Depends(get_db)):item=_get(db,ConnectorSubscription,item_id,"Subscription");item.enabled=False;db.commit();return {"disabled":True,"hard_deleted":False}


@router.get("/mappings")
def mappings(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorFieldMapping).order_by(ConnectorFieldMapping.id.desc()),page,page_size)


@router.post("/mappings",status_code=201)
def create_mapping(payload:MappingWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    validation=validate_mapping(payload.mapping);encoded=canonical_json(payload.mapping);item=ConnectorFieldMapping(mapping_uuid=str(uuid.uuid4()),name=payload.name,direction=payload.direction,source_schema=payload.source_schema,target_schema=payload.target_schema,mapping_json=encoded,validation_status="valid" if validation["valid"] else "invalid",validation_summary_json=canonical_json(validation),content_sha256=sha256(encoded),created_by_user_id=actor.id);db.add(item);db.commit();db.refresh(item);return service.row(item)


@router.get("/mappings/{item_id}")
def mapping(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorFieldMapping,item_id,"Mapping"))


@router.patch("/mappings/{item_id}")
def patch_mapping(item_id:int,payload:MappingWrite,db:Session=Depends(get_db)):
    item=_get(db,ConnectorFieldMapping,item_id,"Mapping");validation=validate_mapping(payload.mapping);item.name=payload.name;item.direction=payload.direction;item.source_schema=payload.source_schema;item.target_schema=payload.target_schema;item.mapping_json=canonical_json(payload.mapping);item.content_sha256=sha256(item.mapping_json);item.validation_status="valid" if validation["valid"] else "invalid";item.validation_summary_json=canonical_json(validation);db.commit();return service.row(item)


@router.post("/mappings/{item_id}/validate")
def validate_mapping_route(item_id:int,db:Session=Depends(get_db)):return validate_mapping(json.loads(_get(db,ConnectorFieldMapping,item_id,"Mapping").mapping_json))


@router.post("/mappings/{item_id}/preview")
def preview_mapping(item_id:int,source:dict=Body(...),db:Session=Depends(get_db)):return {"output":apply_mapping(source,json.loads(_get(db,ConnectorFieldMapping,item_id,"Mapping").mapping_json)),"network_access":False,"code_execution":False}


@router.delete("/mappings/{item_id}")
def delete_mapping(item_id:int,db:Session=Depends(get_db)):
    item=_get(db,ConnectorFieldMapping,item_id,"Mapping")
    if item.system_owned:raise HTTPException(409,"System mapping is immutable")
    if db.query(ConnectorSubscription).filter_by(mapping_id=item.id).first() or db.query(ConnectorInboundEndpoint).filter_by(mapping_id=item.id).first():raise HTTPException(409,"Mapping is in use")
    db.delete(item);db.commit();return {"deleted":True}


@router.get("/outbox")
def outbox(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(IntegrationOutboxEvent).order_by(IntegrationOutboxEvent.id.desc()),page,page_size)


@router.get("/outbox/{item_id}")
def outbox_item(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,IntegrationOutboxEvent,item_id,"Outbox event"))


@router.get("/deliveries")
def deliveries(page:int=1,page_size:int=50,status:str|None=None,db:Session=Depends(get_db)):
    q=db.query(ConnectorDelivery).order_by(ConnectorDelivery.id.desc());q=q.filter_by(status=status) if status else q;return service.page(q,page,page_size)


@router.post("/deliveries",status_code=201)
def create_delivery(payload:DeliveryWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=service.queue_delivery(db,_get(db,ConnectorInstance,payload.connector_id,"Connector"),payload.payload,payload.event_type,payload.external_operation,payload.idempotency_key,actor.id,soar_execution_id=payload.soar_execution_id);db.commit();db.refresh(item);return service.row(item)


@router.get("/deliveries/{item_id}")
def delivery(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorDelivery,item_id,"Delivery"))


@router.get("/deliveries/{item_id}/attempts")
def attempts(item_id:int,db:Session=Depends(get_db)):_get(db,ConnectorDelivery,item_id,"Delivery");return [service.row(x) for x in db.query(ConnectorDeliveryAttempt).filter_by(delivery_id=item_id).order_by(ConnectorDeliveryAttempt.attempt_number).all()]


@router.post("/deliveries/{item_id}/retry")
def retry_delivery(item_id:int,payload:ReasonAction,db:Session=Depends(get_db)):
    item=_get(db,ConnectorDelivery,item_id,"Delivery")
    if item.status not in {"failed","waiting_retry"}:raise HTTPException(409,{"code":"CONNECTOR_RETRY_NOT_ALLOWED","message":"Delivery is not retryable"})
    item.status="queued";item.next_attempt_at=None;db.commit();return service.row(item)


@router.post("/deliveries/{item_id}/cancel")
def cancel_delivery(item_id:int,payload:ReasonAction,db:Session=Depends(get_db)):
    item=_get(db,ConnectorDelivery,item_id,"Delivery")
    if item.status not in {"queued","waiting_retry"}:raise HTTPException(409,{"code":"CONNECTOR_DELIVERY_TERMINAL","message":"Only queued deliveries can be cancelled"})
    item.status="cancelled";item.completed_at=service.utcnow();item.error_summary=payload.reason;db.commit();return service.row(item)


@router.get("/dead-letters")
def dead_letters(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorDeadLetter).order_by(ConnectorDeadLetter.id.desc()),page,page_size)


@router.get("/dead-letters/{item_id}")
def dead_letter(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorDeadLetter,item_id,"Dead letter"))


@router.post("/dead-letters/{item_id}/replay")
def replay(item_id:int,payload:ReasonAction,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.replay_dead_letter(db,_get(db,ConnectorDeadLetter,item_id,"Dead letter"),actor.id,payload.reason))


@router.post("/dead-letters/{item_id}/cancel")
def cancel_dead_letter(item_id:int,payload:ReasonAction,db:Session=Depends(get_db)):
    item=_get(db,ConnectorDeadLetter,item_id,"Dead letter");item.replay_status="cancelled";db.commit();return service.row(item)


@router.get("/inbound-endpoints")
def inbound_endpoints(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorInboundEndpoint).order_by(ConnectorInboundEndpoint.id.desc()),page,page_size)


@router.post("/inbound-endpoints",status_code=201)
def create_inbound_endpoint(payload:EndpointWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    connector=_get(db,ConnectorInstance,payload.connector_id,"Connector")
    if connector.connector_type!="generic_hmac_webhook_inbound":raise HTTPException(422,"Connector is not inbound HMAC")
    if payload.trusted_source and not actor.is_system_admin:raise HTTPException(403,"Administrator approval is required for trusted sources")
    item=ConnectorInboundEndpoint(endpoint_uuid=str(uuid.uuid4()),connector_id=connector.id,name=payload.name,schema_version=payload.schema_version,trusted_source=payload.trusted_source,maximum_body_bytes=payload.maximum_body_bytes,timestamp_tolerance_seconds=payload.timestamp_tolerance_seconds,replay_window_seconds=payload.replay_window_seconds,allowed_event_types_json=canonical_json(payload.allowed_event_types),mapping_id=payload.mapping_id,created_by_user_id=actor.id);db.add(item);db.flush();service.set_credential(db,connector,"hmac_signing",{"signing_secret":payload.secret},actor.id);db.refresh(item);return service.row(item)


@router.get("/inbound-endpoints/{item_id}")
def inbound_endpoint(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorInboundEndpoint,item_id,"Inbound endpoint"))


@router.patch("/inbound-endpoints/{item_id}")
def patch_inbound_endpoint(item_id:int,enabled:bool|None=None,trusted_source:bool|None=None,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    item=_get(db,ConnectorInboundEndpoint,item_id,"Inbound endpoint")
    if trusted_source is not None:
        if not actor.is_system_admin:raise HTTPException(403,"Administrator approval is required")
        item.trusted_source=trusted_source
    if enabled is not None:item.enabled=enabled
    db.commit();return service.row(item)


@router.post("/inbound-endpoints/{item_id}/rotate-secret")
def rotate_inbound_secret(item_id:int,payload:CredentialWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    endpoint=_get(db,ConnectorInboundEndpoint,item_id,"Inbound endpoint");return service.set_credential(db,_get(db,ConnectorInstance,endpoint.connector_id,"Connector"),"hmac_signing",payload.secret,actor.id,rotate=True)


@router.post("/inbound-endpoints/{item_id}/disable")
def disable_endpoint(item_id:int,db:Session=Depends(get_db)):
    item=_get(db,ConnectorInboundEndpoint,item_id,"Inbound endpoint");item.enabled=False;item.disabled_at=service.utcnow();db.commit();return service.row(item)


@public_router.post("/inbound/{endpoint_uuid}",status_code=202)
async def inbound(endpoint_uuid:str,request:Request,db:Session=Depends(get_db)):
    source=request.client.host if request.client else None
    endpoint=db.query(ConnectorInboundEndpoint).filter_by(endpoint_uuid=endpoint_uuid).first()
    if not endpoint:
        try: rate_limit.consume(db,"global",None,rate_limit.source_key(source))
        except rate_limit.RateLimitExceeded as exc: raise HTTPException(429,"Inbound request rate exceeded",headers={"Retry-After":str(exc.retry_after)}) from exc
        raise HTTPException(401,"Inbound authentication failed")
    try: source_hash=rate_limit.enforce_request(db,endpoint.id,source)
    except rate_limit.RateLimitExceeded as exc: raise HTTPException(429,"Inbound request rate exceeded",headers={"Retry-After":str(exc.retry_after)}) from exc
    body=await request.body()
    try:item=service.ingest_inbound(db,endpoint,body,{k.casefold():v for k,v in request.headers.items()},source)
    except IntegrationSecurityError as error:
        kind="replay" if error.code=="CONNECTOR_REPLAY_DETECTED" else ("signature" if error.code in {"CONNECTOR_SIGNATURE_INVALID","CONNECTOR_TIMESTAMP_INVALID"} else "invalid")
        try: rate_limit.record_failure(db,endpoint.id,source_hash,kind)
        except rate_limit.RateLimitExceeded as exc:
            connector=db.get(ConnectorInstance,endpoint.connector_id);event_key="replay_attack_threshold" if kind=="replay" else "signature_failure_threshold"
            service.emit_notification(db,event_key,connector,"integration_inbound_endpoint",endpoint.id,"Inbound authentication failure threshold reached; payload and source details are withheld.")
            append_event(db,event_type="integration_security_threshold",action="replay_detection_threshold" if kind=="replay" else "invalid_signature_threshold",request_id=getattr(request.state,"request_id","unknown"),outcome="denied",resource_type="integration_inbound_endpoint",resource_id=endpoint.id,route_template="/api/integrations/inbound/{endpoint_uuid}",request_method="POST",status_code=429,reason_code="inbound_rate_threshold",metadata={"failure_class":kind,"aggregate_only":True})
            raise HTTPException(429,"Inbound request rate exceeded",headers={"Retry-After":str(exc.retry_after)}) from exc
        raise HTTPException(401,"Inbound authentication failed") from error
    return {"accepted":True,"event_id":item.inbound_event_uuid,"status":item.status}


@router.get("/inbound-events")
def inbound_events(page:int=1,page_size:int=50,status:str|None=None,db:Session=Depends(get_db)):
    q=db.query(ConnectorInboundEvent).order_by(ConnectorInboundEvent.id.desc());q=q.filter_by(status=status) if status else q;return service.page(q,page,page_size)


@router.get("/inbound-events/{item_id}")
def inbound_event(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorInboundEvent,item_id,"Inbound event"))


@router.post("/inbound-events/{item_id}/promote")
def promote(item_id:int,payload:Promotion,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.promote_inbound(db,_get(db,ConnectorInboundEvent,item_id,"Inbound event"),payload.target_type,actor.id))


@router.post("/inbound-events/{item_id}/reject")
def reject(item_id:int,payload:ReasonAction,db:Session=Depends(get_db)):
    item=_get(db,ConnectorInboundEvent,item_id,"Inbound event");item.status="rejected";item.rejection_code="ANALYST_REJECTED";item.rejection_summary=payload.reason;db.commit();return service.row(item)


@router.post("/stix/import/preview")
def stix_preview(bundle:dict=Body(...),source_name:str=Query("STIX 2.1 upload"),db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.stix_preview(db,bundle,actor.id,source_name))


@router.post("/stix/import/promote")
def stix_promote(import_run_id:int=Body(embed=True),db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.stix_promote(db,_get(db,StixImportRun,import_run_id,"STIX import"),actor.id))


@router.get("/stix/import-runs")
def stix_runs(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(StixImportRun).order_by(StixImportRun.id.desc()),page,page_size)


@router.get("/stix/import-runs/{item_id}")
def stix_run(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,StixImportRun,item_id,"STIX import"))


@router.post("/connectors/{connector_id}/taxii/pull")
def taxii_pull(connector_id:int,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.taxii_pull(db,_get(db,ConnectorInstance,connector_id,"Connector"),actor.id)


@router.get("/connectors/{connector_id}/taxii/sync-status")
def taxii_status(connector_id:int,db:Session=Depends(get_db)):
    item=db.query(ConnectorSyncCursor).filter_by(connector_id=connector_id).first();return service.row(item) if item else {"configured":False,"items_processed":0}


@router.get("/health-checks")
def health_checks(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorHealthCheck).order_by(ConnectorHealthCheck.id.desc()),page,page_size)


@router.get("/connectors/{connector_id}/health-checks")
def connector_health_checks(connector_id:int,page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorHealthCheck).filter_by(connector_id=connector_id).order_by(ConnectorHealthCheck.id.desc()),page,page_size)


@router.post("/health-checks/run")
def run_health_checks(batch_size:int=Body(25,embed=True),db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    items=db.query(ConnectorInstance).filter(ConnectorInstance.lifecycle_status.in_(["testing","active","degraded"])).order_by(ConnectorInstance.id).limit(min(batch_size,25)).all();return {"checks":[service.test_connector(db,x,actor.id) for x in items],"bounded":True}


@router.get("/external-references")
def external_references(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorExternalReference).order_by(ConnectorExternalReference.id.desc()),page,page_size)


@router.get("/external-references/{item_id}")
def external_reference(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorExternalReference,item_id,"External reference"))


@router.post("/process-due")
def process_due(batch_size:int=Body(100,embed=True),db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):
    result=service.process_due(db,actor.id,batch_size);result["expired_rate_counters_removed"]=rate_limit.cleanup(db);return result


@router.get("/reports")
def reports(page:int=1,page_size:int=50,db:Session=Depends(get_db)):return service.page(db.query(ConnectorReport).order_by(ConnectorReport.id.desc()),page,page_size)


@router.post("/reports",status_code=201)
def create_report(payload:ReportWrite,db:Session=Depends(get_db),actor:UserAccount=Depends(get_current_user)):return service.row(service.generate_report(db,payload.title,payload.report_type,payload.filters,actor.id))


@router.get("/reports/{item_id}")
def report(item_id:int,db:Session=Depends(get_db)):return service.row(_get(db,ConnectorReport,item_id,"Integration report"))


@router.get("/reports/{item_id}/download",response_class=HTMLResponse)
def download_report(item_id:int,db:Session=Depends(get_db)):
    item=_get(db,ConnectorReport,item_id,"Integration report");return HTMLResponse(item.html_content,headers={"Content-Disposition":f'attachment; filename="integration-report-{item.id}.html"',"X-Content-Type-Options":"nosniff"})
