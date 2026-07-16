import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.modules.access_control.dependencies import require_permission
from app.modules.access_control.audit_service import append_event

from . import correlation_service, report_service, schemas, service
from .import_service import MAX_UPLOAD_BYTES, process_import
from .models import (IndicatorMatch, IndicatorRelationship, IndicatorSighting, ThreatCampaign, ThreatCampaignIndicator,
                     ThreatCorrelationRun, ThreatIndicator, ThreatIntelImport, ThreatIntelReport, ThreatIntelSource,
                     ThreatWatchlist, ThreatWatchlistEntry)


router = APIRouter()
_rate_lock = threading.Lock()
_rate_events: dict[tuple[int, str], deque[datetime]] = defaultdict(deque)


def rate_limit(user_id: int, action: str, limit: int, minutes: int = 5):
    current = datetime.now(timezone.utc)
    cutoff = current - timedelta(minutes=minutes)
    with _rate_lock:
        events = _rate_events[(user_id, action)]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= limit:
            raise HTTPException(429, f"{action.replace('_', ' ').title()} is temporarily rate limited")
        events.append(current)


def page(query, page: int, page_size: int, order_by):
    total = query.count()
    return {"items": [service.dump(item) for item in query.order_by(order_by).offset((page - 1) * page_size).limit(page_size).all()], "total": total, "page": page, "page_size": page_size}


def get_or_404(db: Session, model, item_id: int, label: str):
    item = db.get(model, item_id)
    if not item:
        raise HTTPException(404, f"{label} not found")
    return item


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    current = service.now()
    active = db.query(ThreatIndicator).filter(ThreatIndicator.active.is_(True), ThreatIndicator.revoked.is_(False), or_(ThreatIndicator.valid_until.is_(None), ThreatIndicator.valid_until >= current))
    return {
        "total_active_indicators": active.count(),
        "indicators_by_type": dict(db.query(ThreatIndicator.indicator_type, func.count()).group_by(ThreatIndicator.indicator_type).all()),
        "severity_distribution": dict(db.query(ThreatIndicator.severity, func.count()).group_by(ThreatIndicator.severity).all()),
        "confidence_distribution": {"0-24": db.query(ThreatIndicator).filter(ThreatIndicator.confidence < 25).count(), "25-49": db.query(ThreatIndicator).filter(ThreatIndicator.confidence.between(25, 49)).count(), "50-74": db.query(ThreatIndicator).filter(ThreatIndicator.confidence.between(50, 74)).count(), "75-100": db.query(ThreatIndicator).filter(ThreatIndicator.confidence >= 75).count()},
        "active_watchlists": db.query(ThreatWatchlist).filter_by(enabled=True).count(),
        "new_matches": db.query(IndicatorMatch).filter_by(status="new").count(),
        "high_risk_matches": db.query(IndicatorMatch).filter(IndicatorMatch.risk_score >= 60, IndicatorMatch.status.notin_(["false_positive", "accepted_risk"])).count(),
        "module_distribution": dict(db.query(IndicatorSighting.module, func.count()).group_by(IndicatorSighting.module).all()),
        "recent_imports": [service.dump(x) for x in db.query(ThreatIntelImport).order_by(ThreatIntelImport.started_at.desc()).limit(5)],
        "recent_sightings": [service.dump(x) for x in db.query(IndicatorSighting).order_by(IndicatorSighting.last_observed_at.desc()).limit(5)],
        "recent_escalations": [service.dump(x) for x in db.query(IndicatorMatch).filter(IndicatorMatch.status == "escalated").order_by(IndicatorMatch.reviewed_at.desc()).limit(5)],
    }


@router.get("/sources")
def sources(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), enabled: bool | None = None, q: str | None = Query(None, max_length=160), db: Session = Depends(get_db)):
    query = db.query(ThreatIntelSource)
    if enabled is not None: query = query.filter_by(enabled=enabled)
    if q: query = query.filter(or_(ThreatIntelSource.name.ilike(f"%{q}%"), ThreatIntelSource.description.ilike(f"%{q}%")))
    return page(query, page_number, page_size, ThreatIntelSource.name.asc())


@router.post("/sources")
def create_source(payload: schemas.SourceCreate, request: Request, db: Session = Depends(get_db)):
    user = request.state.current_user
    item = ThreatIntelSource(**payload.model_dump(), created_by_user_id=user.id)
    db.add(item)
    try: db.commit()
    except IntegrityError as exc:
        db.rollback(); raise HTTPException(409, "A source with this name already exists") from exc
    db.refresh(item)
    service.post_commit_event(db, request, user, "source_created", "threat_intel_source", item.id, f"Threat-intelligence source {item.name} created.")
    return service.dump(item)


@router.get("/sources/{source_id}")
def get_source(source_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIntelSource, source_id, "Source")
    return service.dump(item) | {"indicator_count": db.query(ThreatIndicator).filter_by(source_id=item.id).count(), "import_count": db.query(ThreatIntelImport).filter_by(source_id=item.id).count()}


@router.patch("/sources/{source_id}")
def update_source(source_id: int, payload: schemas.SourceUpdate, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIntelSource, source_id, "Source")
    if item.system_owned and payload.name and payload.name != item.name: raise HTTPException(403, "System source names are protected")
    for key, value in payload.model_dump(exclude_unset=True).items(): setattr(item, key, value)
    db.commit(); db.refresh(item)
    service.post_commit_event(db, request, request.state.current_user, "source_updated", "threat_intel_source", item.id, f"Threat-intelligence source {item.name} updated.")
    return service.dump(item)


@router.get("/indicators")
def indicators(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), q: str | None = Query(None, max_length=200), indicator_type: str | None = None, severity: str | None = None, tlp: str | None = None, source_id: int | None = None, active: bool | None = None, revoked: bool | None = None, expired: bool | None = None, min_confidence: int | None = Query(None, ge=0, le=100), max_confidence: int | None = Query(None, ge=0, le=100), watchlist_id: int | None = None, sort: str = Query("updated_at", pattern="^(updated_at|created_at|confidence|severity|indicator_type)$"), direction: str = Query("desc", pattern="^(asc|desc)$"), db: Session = Depends(get_db)):
    query = db.query(ThreatIndicator)
    if q: query = query.filter(or_(ThreatIndicator.normalized_value.ilike(f"%{q}%"), ThreatIndicator.title.ilike(f"%{q}%"), ThreatIndicator.tags_json.ilike(f"%{q}%")))
    for field, value in (("indicator_type", indicator_type), ("severity", severity), ("tlp", tlp), ("source_id", source_id), ("active", active), ("revoked", revoked)):
        if value is not None: query = query.filter(getattr(ThreatIndicator, field) == value)
    if min_confidence is not None: query = query.filter(ThreatIndicator.confidence >= min_confidence)
    if max_confidence is not None: query = query.filter(ThreatIndicator.confidence <= max_confidence)
    if expired is not None: query = query.filter(ThreatIndicator.valid_until < service.now()) if expired else query.filter(or_(ThreatIndicator.valid_until.is_(None), ThreatIndicator.valid_until >= service.now()))
    if watchlist_id: query = query.join(ThreatWatchlistEntry, ThreatWatchlistEntry.indicator_id == ThreatIndicator.id).filter(ThreatWatchlistEntry.watchlist_id == watchlist_id)
    ordering = getattr(getattr(ThreatIndicator, sort), direction)()
    return page(query, page_number, page_size, ordering)


@router.post("/indicators")
def create_indicator(payload: schemas.IndicatorCreate, request: Request, db: Session = Depends(get_db)):
    user = request.state.current_user; rate_limit(user.id, "indicator_creation", 60)
    item, duplicate = service.create_or_merge_indicator(db, payload.model_dump(), user.id)
    db.commit(); db.refresh(item)
    if not duplicate:
        service.post_commit_event(db, request, user, "indicator_created", "threat_indicator", item.id, f"{item.indicator_type} indicator created.")
    return {"indicator": service.dump(item), "duplicate": duplicate, "message": "Existing normalized indicator returned; lifecycle was not reactivated." if duplicate else "Indicator created."}


@router.get("/indicators/{indicator_id}")
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIndicator, indicator_id, "Indicator")
    watchlists = db.query(ThreatWatchlist).join(ThreatWatchlistEntry).filter(ThreatWatchlistEntry.indicator_id == item.id).all()
    campaigns = db.query(ThreatCampaign).join(ThreatCampaignIndicator).filter(ThreatCampaignIndicator.indicator_id == item.id).all()
    relationships = db.query(IndicatorRelationship).filter(or_(IndicatorRelationship.source_indicator_id == item.id, IndicatorRelationship.target_indicator_id == item.id)).all()
    return service.dump(item) | {"source": service.dump(item.source) if item.source else None, "sightings": [service.dump(x) for x in db.query(IndicatorSighting).filter_by(indicator_id=item.id).order_by(IndicatorSighting.last_observed_at.desc()).limit(100)], "matches": [service.dump(x) for x in db.query(IndicatorMatch).filter_by(indicator_id=item.id).order_by(IndicatorMatch.risk_score.desc()).limit(100)], "watchlists": [service.dump(x) for x in watchlists], "campaigns": [service.dump(x) for x in campaigns], "relationships": [service.dump(x) for x in relationships]}


@router.patch("/indicators/{indicator_id}")
def update_indicator(indicator_id: int, payload: schemas.IndicatorUpdate, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIndicator, indicator_id, "Indicator")
    data = payload.model_dump(exclude_unset=True)
    first = data.pop("first_seen", item.first_seen_at); last = data.pop("last_seen", item.last_seen_at)
    service.validate_lifecycle(first, last, data.get("valid_until", item.valid_until), item.valid_from)
    item.first_seen_at, item.last_seen_at = first, last
    if "tags" in data: item.tags_json = json.dumps(service.clean_tags(data.pop("tags")), sort_keys=True)
    for key, value in data.items(): setattr(item, key, value)
    db.commit(); db.refresh(item)
    service.post_commit_event(db, request, request.state.current_user, "indicator_updated", "threat_indicator", item.id, f"Indicator {item.id} updated.")
    return service.dump(item)


def lifecycle_change(indicator_id: int, revoked: bool, request: Request, db: Session):
    item = get_or_404(db, ThreatIndicator, indicator_id, "Indicator")
    item.revoked = revoked; item.active = not revoked
    db.commit(); db.refresh(item)
    action = "indicator_revoked" if revoked else "indicator_restored"
    service.post_commit_event(db, request, request.state.current_user, action, "threat_indicator", item.id, f"Indicator {item.id} {'revoked' if revoked else 'restored by explicit analyst action'}.")
    return service.dump(item)


@router.post("/indicators/{indicator_id}/revoke")
def revoke(indicator_id: int, request: Request, db: Session = Depends(get_db)): return lifecycle_change(indicator_id, True, request, db)


@router.post("/indicators/{indicator_id}/restore")
def restore(indicator_id: int, request: Request, db: Session = Depends(get_db)): return lifecycle_change(indicator_id, False, request, db)


@router.get("/imports")
def imports(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), source_id: int | None = None, status: str | None = None, db: Session = Depends(get_db)):
    query = db.query(ThreatIntelImport)
    if source_id: query = query.filter_by(source_id=source_id)
    if status: query = query.filter_by(status=status)
    return page(query, page_number, page_size, ThreatIntelImport.started_at.desc())


@router.post("/imports")
async def import_indicators(request: Request, source_id: int = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = request.state.current_user; rate_limit(user.id, "indicator_import", 20)
    source = get_or_404(db, ThreatIntelSource, source_id, "Source")
    if not source.enabled: raise HTTPException(409, "Source is disabled")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    append_event(db, event_type="threat_intelligence", action="import_started", request_id=getattr(request.state, "request_id", "unknown"), outcome="success", actor=user, resource_type="threat_intel_source", resource_id=source.id, route_template=request.url.path, request_method=request.method, status_code=202, metadata={"content_size": len(content), "source_id": source.id})
    db.commit()
    try:
        manifest = process_import(db, source=source, user_id=user.id, filename=file.filename, content=content)
    except HTTPException as exc:
        failed_id = exc.detail.get("import_id") if isinstance(exc.detail, dict) else source.id
        service.post_commit_event(db, request, user, "import_failed", "threat_intel_import", int(failed_id), "Threat-intelligence import failed safely; no uploaded source bytes were retained.")
        raise
    service.post_commit_event(db, request, user, "import_completed", "threat_intel_import", manifest.id, f"Import {manifest.id} completed with {manifest.accepted_records} accepted and {manifest.rejected_records} rejected records.", notify=("Threat-intelligence import completed with warnings", f"Import {manifest.id} completed with {manifest.warning_count + manifest.rejected_records} warnings or rejected records.", "warning") if manifest.warning_count or manifest.rejected_records else None)
    return service.dump(manifest)


@router.get("/imports/{import_id}")
def get_import(import_id: int, db: Session = Depends(get_db)): return service.dump(get_or_404(db, ThreatIntelImport, import_id, "Import"))


@router.get("/watchlists")
def watchlists(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), db: Session = Depends(get_db)):
    result = page(db.query(ThreatWatchlist), page_number, page_size, ThreatWatchlist.name.asc())
    for item in result["items"]:
        item["indicator_count"] = db.query(ThreatWatchlistEntry).filter_by(watchlist_id=item["id"]).count()
        item["recent_match_count"] = db.query(IndicatorMatch).join(ThreatWatchlistEntry, ThreatWatchlistEntry.indicator_id == IndicatorMatch.indicator_id).filter(ThreatWatchlistEntry.watchlist_id == item["id"], IndicatorMatch.created_at >= service.now() - timedelta(days=30)).count()
    return result


@router.post("/watchlists")
def create_watchlist(payload: schemas.WatchlistCreate, request: Request, db: Session = Depends(get_db)):
    item = ThreatWatchlist(**payload.model_dump(), created_by_user_id=request.state.current_user.id); db.add(item)
    try: db.commit()
    except IntegrityError as exc: db.rollback(); raise HTTPException(409, "A watchlist with this name already exists") from exc
    db.refresh(item); service.post_commit_event(db, request, request.state.current_user, "watchlist_created", "threat_watchlist", item.id, f"Watchlist {item.name} created."); return service.dump(item)


@router.get("/watchlists/{watchlist_id}")
def get_watchlist(watchlist_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatWatchlist, watchlist_id, "Watchlist")
    entries = db.query(ThreatWatchlistEntry).filter_by(watchlist_id=item.id).order_by(ThreatWatchlistEntry.added_at.desc()).all()
    return service.dump(item) | {"entries": [service.dump(entry) | {"indicator": service.dump(entry.indicator)} for entry in entries], "indicator_count": len(entries), "recent_matches": [service.dump(x) for x in db.query(IndicatorMatch).join(ThreatWatchlistEntry, ThreatWatchlistEntry.indicator_id == IndicatorMatch.indicator_id).filter(ThreatWatchlistEntry.watchlist_id == item.id).order_by(IndicatorMatch.created_at.desc()).limit(20)]}


@router.patch("/watchlists/{watchlist_id}")
def update_watchlist(watchlist_id: int, payload: schemas.WatchlistUpdate, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatWatchlist, watchlist_id, "Watchlist"); data = payload.model_dump(exclude_unset=True)
    if item.system_owned and any(key in data for key in {"name", "description"}): raise HTTPException(403, "System watchlist identity is protected")
    for key, value in data.items(): setattr(item, key, value)
    db.commit(); service.post_commit_event(db, request, request.state.current_user, "watchlist_updated", "threat_watchlist", item.id, f"Watchlist {item.name} updated."); return service.dump(item)


@router.post("/watchlists/{watchlist_id}/entries")
def add_watchlist_entry(watchlist_id: int, payload: schemas.WatchlistEntryCreate, request: Request, db: Session = Depends(get_db)):
    get_or_404(db, ThreatWatchlist, watchlist_id, "Watchlist"); get_or_404(db, ThreatIndicator, payload.indicator_id, "Indicator")
    if db.query(ThreatWatchlistEntry).filter_by(watchlist_id=watchlist_id, indicator_id=payload.indicator_id).first(): raise HTTPException(409, "Indicator is already on this watchlist")
    item = ThreatWatchlistEntry(watchlist_id=watchlist_id, indicator_id=payload.indicator_id, note=service.bounded(payload.note, 1000), added_by_user_id=request.state.current_user.id); db.add(item); db.commit(); db.refresh(item)
    service.post_commit_event(db, request, request.state.current_user, "watchlist_entry_added", "threat_watchlist", watchlist_id, f"Indicator {payload.indicator_id} added to watchlist {watchlist_id}."); return service.dump(item)


@router.delete("/watchlists/{watchlist_id}/entries/{indicator_id}")
def remove_watchlist_entry(watchlist_id: int, indicator_id: int, request: Request, db: Session = Depends(get_db)):
    item = db.query(ThreatWatchlistEntry).filter_by(watchlist_id=watchlist_id, indicator_id=indicator_id).first()
    if not item: raise HTTPException(404, "Watchlist entry not found")
    db.delete(item); db.commit(); service.post_commit_event(db, request, request.state.current_user, "watchlist_entry_removed", "threat_watchlist", watchlist_id, f"Indicator {indicator_id} removed from watchlist {watchlist_id}; indicator retained."); return {"ok": True}


def sync_campaign_indicators(db: Session, campaign: ThreatCampaign, ids: list[int], user_id: int):
    unique_ids = list(dict.fromkeys(ids))
    if unique_ids and db.query(ThreatIndicator).filter(ThreatIndicator.id.in_(unique_ids)).count() != len(unique_ids): raise HTTPException(422, "One or more indicators do not exist")
    current = {item.indicator_id: item for item in campaign.indicators}
    for indicator_id, link in current.items():
        if indicator_id not in unique_ids: db.delete(link)
    for indicator_id in unique_ids:
        if indicator_id not in current: db.add(ThreatCampaignIndicator(campaign_id=campaign.id, indicator_id=indicator_id, added_by_user_id=user_id))


@router.get("/campaigns")
def campaigns(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), active: bool | None = None, q: str | None = Query(None, max_length=160), db: Session = Depends(get_db)):
    query = db.query(ThreatCampaign)
    if active is not None: query = query.filter_by(active=active)
    if q: query = query.filter(or_(ThreatCampaign.name.ilike(f"%{q}%"), ThreatCampaign.description.ilike(f"%{q}%")))
    result = page(query, page_number, page_size, ThreatCampaign.updated_at.desc())
    for item in result["items"]: item["indicator_count"] = db.query(ThreatCampaignIndicator).filter_by(campaign_id=item["id"]).count()
    return result


@router.post("/campaigns")
def create_campaign(payload: schemas.CampaignCreate, request: Request, db: Session = Depends(get_db)):
    data = payload.model_dump(); ids = data.pop("indicator_ids"); data["tags_json"] = json.dumps(service.clean_tags(data.pop("tags")), sort_keys=True)
    service.validate_lifecycle(data.get("first_seen_at"), data.get("last_seen_at"), None)
    item = ThreatCampaign(**data, created_by_user_id=request.state.current_user.id); db.add(item); db.flush(); sync_campaign_indicators(db, item, ids, request.state.current_user.id)
    try: db.commit()
    except IntegrityError as exc: db.rollback(); raise HTTPException(409, "A campaign with this name already exists") from exc
    db.refresh(item); service.post_commit_event(db, request, request.state.current_user, "campaign_created", "threat_campaign", item.id, f"Campaign {item.name} created."); return service.dump(item)


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatCampaign, campaign_id, "Campaign")
    return service.dump(item) | {"indicators": [service.dump(link.indicator) for link in item.indicators]}


@router.patch("/campaigns/{campaign_id}")
def update_campaign(campaign_id: int, payload: schemas.CampaignUpdate, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatCampaign, campaign_id, "Campaign"); data = payload.model_dump(exclude_unset=True); ids = data.pop("indicator_ids", None)
    if "tags" in data: data["tags_json"] = json.dumps(service.clean_tags(data.pop("tags")), sort_keys=True)
    for key, value in data.items(): setattr(item, key, value)
    service.validate_lifecycle(item.first_seen_at, item.last_seen_at, None)
    if ids is not None: sync_campaign_indicators(db, item, ids, request.state.current_user.id)
    db.commit(); service.post_commit_event(db, request, request.state.current_user, "campaign_updated", "threat_campaign", item.id, f"Campaign {item.name} updated."); return service.dump(item)


@router.get("/relationships")
def relationships(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(50, ge=1, le=100), indicator_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(IndicatorRelationship)
    if indicator_id: query = query.filter(or_(IndicatorRelationship.source_indicator_id == indicator_id, IndicatorRelationship.target_indicator_id == indicator_id))
    return page(query, page_number, page_size, IndicatorRelationship.created_at.desc())


@router.post("/relationships")
def create_relationship(payload: schemas.RelationshipCreate, request: Request, db: Session = Depends(get_db)):
    if payload.source_indicator_id == payload.target_indicator_id: raise HTTPException(422, "An indicator cannot relate to itself")
    get_or_404(db, ThreatIndicator, payload.source_indicator_id, "Source indicator"); get_or_404(db, ThreatIndicator, payload.target_indicator_id, "Target indicator")
    allowed = {"related_to", "resolves_to", "redirects_to", "communicates_with", "downloads", "drops", "impersonates", "associated_with", "duplicate_of", "custom"}
    label = payload.relationship_type.strip().lower()
    if label not in allowed: raise HTTPException(422, "Unsupported relationship type; use custom with a bounded description")
    data = payload.model_dump(); data["relationship_type"] = label
    item = IndicatorRelationship(**data, created_by_user_id=request.state.current_user.id); db.add(item)
    try: db.commit()
    except IntegrityError as exc: db.rollback(); raise HTTPException(409, "This relationship already exists") from exc
    db.refresh(item); service.post_commit_event(db, request, request.state.current_user, "relationship_created", "indicator_relationship", item.id, f"Indicator relationship {item.id} created."); return service.dump(item)


@router.delete("/relationships/{relationship_id}")
def delete_relationship(relationship_id: int, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, IndicatorRelationship, relationship_id, "Relationship"); db.delete(item); db.commit(); service.post_commit_event(db, request, request.state.current_user, "relationship_deleted", "indicator_relationship", relationship_id, f"Indicator relationship {relationship_id} deleted."); return {"ok": True}


@router.post("/correlation/run")
def run_correlation(payload: schemas.CorrelationRequest, request: Request, db: Session = Depends(get_db)):
    user = request.state.current_user; rate_limit(user.id, "correlation_run", 10)
    run_record, high_ids = correlation_service.run(db, user.id, payload.maximum_records)
    for match_id in high_ids[:100]:
        match = db.get(IndicatorMatch, match_id)
        if match and match.risk_score >= 60:
            title = "High-risk threat-intelligence match"; message = f"Match {match.id} scored {match.risk_score:.1f} against stored {match.sighting.module} data."
            if not db.query(models.Notification).filter_by(title=title, entity_type="indicator_match", entity_id=match.id).first(): db.add(models.Notification(title=title, message=message, type="danger", entity_type="indicator_match", entity_id=match.id))
    db.commit()
    service.post_commit_event(db, request, user, "correlation_executed", "threat_correlation_run", run_record.id, f"Correlation run {run_record.id} examined {run_record.records_examined} stored observations.")
    return service.dump(run_record)


@router.get("/correlation/runs")
def correlation_runs(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), db: Session = Depends(get_db)): return page(db.query(ThreatCorrelationRun), page_number, page_size, ThreatCorrelationRun.started_at.desc())


@router.get("/sightings")
def sightings(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), module: str | None = None, indicator_id: int | None = None, reviewed: bool | None = None, db: Session = Depends(get_db)):
    query = db.query(IndicatorSighting)
    if module: query = query.filter_by(module=module)
    if indicator_id: query = query.filter_by(indicator_id=indicator_id)
    if reviewed is not None: query = query.filter_by(reviewed=reviewed)
    return page(query, page_number, page_size, IndicatorSighting.last_observed_at.desc())


@router.get("/matches")
def matches(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), status: str | None = None, min_risk: float | None = Query(None, ge=0, le=100), module: str | None = None, indicator_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(IndicatorMatch)
    if status: query = query.filter_by(status=status)
    if min_risk is not None: query = query.filter(IndicatorMatch.risk_score >= min_risk)
    if module: query = query.join(IndicatorSighting).filter(IndicatorSighting.module == module)
    if indicator_id: query = query.filter_by(indicator_id=indicator_id)
    return page(query, page_number, page_size, IndicatorMatch.created_at.desc())


@router.get("/matches/{match_id}")
def get_match(match_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, IndicatorMatch, match_id, "Match")
    return service.dump(item) | {"indicator": service.dump(item.indicator), "sighting": service.dump(item.sighting), "case": service.dump(db.get(models.IncidentCase, item.case_id)) if item.case_id else None}


@router.post("/matches/{match_id}/review")
def review_match(match_id: int, payload: schemas.MatchReview, request: Request, db: Session = Depends(get_db)):
    item = get_or_404(db, IndicatorMatch, match_id, "Match")
    if payload.status == "escalated" and not (payload.case_id or item.case_id): raise HTTPException(422, "Escalated disposition requires an incident case")
    if payload.case_id: get_or_404(db, models.IncidentCase, payload.case_id, "Incident case")
    item.status = payload.status; item.analyst_note = service.bounded(payload.analyst_note, 4000); item.reviewed_by_user_id = request.state.current_user.id; item.reviewed_at = service.now(); item.sighting.reviewed = True
    if payload.status == "false_positive":
        item.risk_score = 0
        factors = json.loads(item.risk_factors_json or "[]"); factors.append({"factor": "analyst_disposition", "points": 0, "explanation": "This match is dispositioned as a false positive."}); item.risk_factors_json = json.dumps(factors, sort_keys=True)
    if payload.case_id: item.case_id = payload.case_id
    db.commit(); service.post_commit_event(db, request, request.state.current_user, "match_reviewed", "indicator_match", item.id, f"Match {item.id} disposition set to {item.status}."); return service.dump(item)


@router.post("/matches/{match_id}/escalate", dependencies=[Depends(require_permission("cases:create"))])
def escalate_match(match_id: int, payload: schemas.MatchEscalate, request: Request, db: Session = Depends(get_db)):
    if payload.confirmed is not True: raise HTTPException(422, "Explicit analyst confirmation is required")
    item = get_or_404(db, IndicatorMatch, match_id, "Match")
    if item.case_id: raise HTTPException(409, "Match is already linked to a case")
    if payload.case_id:
        case = get_or_404(db, models.IncidentCase, payload.case_id, "Incident case")
    else:
        key = f"TI-{service.now().strftime('%Y%m%d%H%M%S')}-{item.id}"
        case = models.IncidentCase(case_key=key, title=service.bounded(payload.case_title or f"Threat-intelligence match {item.id}", 240, required=True), summary=f"Explicitly escalated offline IOC match {item.id} from {item.sighting.module}.", case_type="incident", severity="critical" if item.risk_score >= 80 else "high" if item.risk_score >= 60 else "medium", priority="P1" if item.risk_score >= 80 else "P2" if item.risk_score >= 60 else "P3", confidence="high" if item.indicator.confidence >= 75 else "medium", risk_score=item.risk_score, status="new", source_module_count=1, evidence_count=0, tags_json=json.dumps(["threat-intelligence", item.indicator.indicator_type]))
        db.add(case); db.flush()
    fingerprint = __import__("hashlib").sha256(f"threat-intel:{item.id}:{case.id}".encode()).hexdigest()
    if not db.query(models.IncidentEvidence).filter_by(evidence_fingerprint=fingerprint).first():
        db.add(models.IncidentEvidence(case_id=case.id, source_module="threat_intelligence", source_record_type="indicator_match", source_record_id=item.id, source_internal_route=f"/threat-intelligence/matches/{item.id}", title_snapshot=f"Threat-intelligence match {item.id}", evidence_snapshot=f"Defanged indicator {item.indicator.indicator_type}: {service.dump(item.indicator)['display_value']}; source module {item.sighting.module}; risk {item.risk_score:.1f}.", severity=case.severity, confidence=case.confidence, evidence_fingerprint=fingerprint)); case.evidence_count += 1
    item.case_id = case.id; item.status = "escalated"; item.reviewed_by_user_id = request.state.current_user.id; item.reviewed_at = service.now(); item.analyst_note = service.bounded(payload.analyst_note, 4000)
    db.commit(); db.refresh(case)
    service.post_commit_event(db, request, request.state.current_user, "match_escalated", "indicator_match", item.id, f"Match {item.id} explicitly linked to incident case {case.case_key}.", notify=("Threat-intelligence match linked to a case", f"Match {item.id} was linked to {case.case_key}.", "warning"))
    return {"match": service.dump(item), "case": service.dump(case)}


@router.get("/reports")
def reports(page_number: int = Query(1, alias="page", ge=1), page_size: int = Query(25, ge=1, le=100), db: Session = Depends(get_db)): return page(db.query(ThreatIntelReport), page_number, page_size, ThreatIntelReport.created_at.desc())


@router.post("/reports")
def create_report(payload: schemas.ReportCreate, request: Request, db: Session = Depends(get_db)):
    user = request.state.current_user; rate_limit(user.id, "report_generation", 20)
    report = report_service.generate(db, title=payload.title, report_type=payload.report_type, defanged=payload.defanged, user_id=user.id)
    service.post_commit_event(db, request, user, "report_generated", "threat_intel_report", report.id, f"Threat-intelligence report {report.id} generated.")
    return service.dump(report)


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIntelReport, report_id, "Report")
    return service.dump(item) | {"html_content": item.html_content}


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    item = get_or_404(db, ThreatIntelReport, report_id, "Report")
    return Response(item.html_content, media_type="text/html", headers={"Content-Disposition": f"attachment; filename=threat-intelligence-report-{item.id}.html"})
