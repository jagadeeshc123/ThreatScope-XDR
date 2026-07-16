import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app import models

from .models import IndicatorMatch, IndicatorSighting, ThreatCorrelationRun, ThreatIndicator, ThreatWatchlist, ThreatWatchlistEntry
from .normalization import IndicatorValidationError, normalize_indicator
from .service import SEVERITY_WEIGHT, comparable, now


@dataclass(frozen=True)
class Observation:
    kind: str
    value: str
    module: str
    entity_type: str
    entity_id: int
    observed_at: datetime
    context: str
    confidence: int = 70
    match_type: str = "exact"


def _confidence(value) -> int:
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    return {"low": 35, "medium": 65, "high": 85}.get(str(value).lower(), 60)


def _map_kind(value: str) -> str | None:
    mapping = {
        "ip": "ipv4", "ip_address": "ipv4", "source_ip": "ipv4", "destination_ip": "ipv4",
        "domain_name": "domain", "host": "hostname", "sender": "email", "sender_email": "email",
        "reply_to": "email", "email_address": "email", "uri": "url", "link": "url",
        "hash": "sha256", "file_hash": "sha256", "filename": "file_name",
    }
    kind = str(value or "").lower().replace("-", "_")
    if kind in {"ipv4", "ipv6", "cidr", "domain", "hostname", "url", "email", "sha256", "sha1", "md5", "file_name", "user_agent", "vulnerability_id", "custom"}:
        return kind
    return mapping.get(kind)


def _time(value) -> datetime:
    return value or now()


def _expand_url(value: str, module: str, entity_type: str, entity_id: int, observed_at: datetime, context: str, confidence: int):
    yield Observation("url", value, module, entity_type, entity_id, observed_at, context, confidence, "exact")
    try:
        host = urlsplit(value).hostname
        if host:
            kind = "ipv6" if ":" in host else "ipv4" if all(part.isdigit() for part in host.split(".")) and len(host.split(".")) == 4 else "domain"
            yield Observation(kind, host, module, entity_type, entity_id, observed_at, context, confidence, "host_only")
    except ValueError:
        return


def observations(db: Session, maximum: int) -> list[Observation]:
    result: list[Observation] = []

    def add(kind, value, module, entity_type, entity_id, observed_at, context, confidence=70):
        if value in (None, "") or len(result) >= maximum:
            return
        kind = _map_kind(kind)
        if not kind:
            return
        item = Observation(kind, str(value), module, entity_type, int(entity_id), _time(observed_at), str(context)[:1000], _confidence(confidence))
        result.extend(list(_expand_url(item.value, module, entity_type, item.entity_id, item.observed_at, item.context, item.confidence)) if kind == "url" else [item])

    for event in db.query(models.SocEvent).order_by(models.SocEvent.id).limit(maximum).all():
        add("source_ip", event.source_ip, "soc", "event", event.id, event.event_time, event.message or event.event_type, 75)
        add("destination_ip", event.destination_ip, "soc", "event", event.id, event.event_time, event.message or event.event_type, 70)
        add("user_agent", event.user_agent, "soc", "event", event.id, event.event_time, event.message or event.event_type, 60)
    for alert in db.query(models.SocAlert).order_by(models.SocAlert.id).limit(maximum).all():
        add("source_ip", alert.source_ip, "soc", "alert", alert.id, alert.last_seen, alert.evidence_summary, alert.confidence)
    for item in db.query(models.PhishingIndicator).order_by(models.PhishingIndicator.id).limit(maximum).all():
        add(item.indicator_type, item.normalized_value, "phishing", "indicator", item.id, item.created_at, item.context, item.confidence)
    for item in db.query(models.PhishingAnalysis).order_by(models.PhishingAnalysis.id).limit(maximum).all():
        add("email", item.sender_address_redacted, "phishing", "analysis", item.id, item.created_at, "Stored sender address", item.confidence)
        add("email", item.reply_to_redacted, "phishing", "analysis", item.id, item.created_at, "Stored reply-to address", item.confidence)
    for item in db.query(models.DocumentIndicator).order_by(models.DocumentIndicator.id).limit(maximum).all():
        add(item.indicator_type, item.normalized_value, "document", "indicator", item.id, item.created_at, item.context, item.confidence)
    for item in db.query(models.DocumentEmbeddedArtifact).order_by(models.DocumentEmbeddedArtifact.id).limit(maximum).all():
        add("sha256", item.sha256, "document", "embedded_artifact", item.id, item.created_at, item.evidence_summary, 75)
        add("file_name", item.filename_sanitized, "document", "embedded_artifact", item.id, item.created_at, item.evidence_summary, 60)
    for item in db.query(models.DocumentAnalysis).order_by(models.DocumentAnalysis.id).limit(maximum).all():
        add("sha256", item.file_hash, "document", "analysis", item.id, item.created_at, "Stored document SHA-256", item.confidence)
    for item in db.query(models.Target).order_by(models.Target.id).limit(maximum).all():
        add("domain", item.domain, "web_exposure", "target", item.id, item.created_at, item.name, 80)
        add("url", item.base_url, "web_exposure", "target", item.id, item.created_at, item.name, 80)
    for item in db.query(models.ApiAssessment).order_by(models.ApiAssessment.id).limit(maximum).all():
        add("url", item.base_url, "api_security", "assessment", item.id, item.created_at, item.name, 80)
    for item in db.query(models.ApiEndpoint).join(models.ApiAssessment).order_by(models.ApiEndpoint.id).limit(maximum).all():
        if item.assessment.base_url:
            base = item.assessment.base_url.rstrip("/")
            path = item.path if item.path.startswith("/") else f"/{item.path}"
            add("url", f"{base}{path}", "api_security", "endpoint", item.id, item.created_at, item.summary or f"{item.method} {item.path}", 75)
    for item in db.query(models.UnifiedEntity).order_by(models.UnifiedEntity.id).limit(maximum).all():
        add(item.entity_type, item.normalized_value, "unified_correlation", "entity", item.id, item.last_seen_at, "Stored unified entity", item.confidence)
    for item in db.query(models.IncidentEvidence).order_by(models.IncidentEvidence.id).limit(maximum).all():
        if item.entity_id:
            entity = db.get(models.UnifiedEntity, item.entity_id)
            if entity:
                add(entity.entity_type, entity.normalized_value, "incident_cases", "evidence", item.id, item.added_at, item.evidence_snapshot, item.confidence)
    # Keep execution bounded even when URL host expansion added a second observation.
    return result[:maximum]


def _watchlist_info(db: Session, indicator_id: int) -> tuple[bool, bool]:
    names = {row[0] for row in db.query(ThreatWatchlist.name).join(ThreatWatchlistEntry, ThreatWatchlistEntry.watchlist_id == ThreatWatchlist.id).filter(ThreatWatchlist.enabled.is_(True), ThreatWatchlistEntry.indicator_id == indicator_id).all()}
    return bool(names), "Confirmed Malicious" in names


def risk_score(db: Session, indicator: ThreatIndicator, sighting: IndicatorSighting, match_type: str) -> tuple[float, list[dict]]:
    if indicator.revoked or indicator.false_positive or not indicator.active:
        return 0.0, [{"factor": "lifecycle", "points": 0, "explanation": "Inactive, revoked, or false-positive indicators are suppressed."}]
    source_reliability = indicator.source.reliability if indicator.source else 50
    total_occurrences = sum(row[0] or 0 for row in db.query(IndicatorSighting.occurrence_count).filter_by(indicator_id=indicator.id).all())
    modules = db.query(IndicatorSighting.module).filter_by(indicator_id=indicator.id).distinct().count()
    watchlisted, confirmed = _watchlist_info(db, indicator.id)
    observed = comparable(sighting.last_observed_at)
    age = now() - observed
    recency = 8 if age <= timedelta(days=7) else 5 if age <= timedelta(days=30) else 2
    factors = [
        {"factor": "indicator_severity", "points": round(SEVERITY_WEIGHT[indicator.severity] * .35, 2)},
        {"factor": "indicator_confidence", "points": round(indicator.confidence * .25, 2)},
        {"factor": "source_reliability", "points": round(source_reliability * .10, 2)},
        {"factor": "occurrence_count", "points": min(10, total_occurrences)},
        {"factor": "affected_modules", "points": min(10, modules * 2)},
        {"factor": "recency", "points": recency},
        {"factor": "watchlist", "points": 8 if watchlisted else 0},
        {"factor": "confirmed_malicious", "points": 5 if confirmed else 0},
        {"factor": "match_strength", "points": 5 if match_type == "exact" else 2},
    ]
    score = sum(float(item["points"]) for item in factors)
    if indicator.valid_until and comparable(indicator.valid_until) < now():
        score *= .6
        factors.append({"factor": "expired", "multiplier": .6, "explanation": "Expired indicators receive reduced weight."})
    return round(max(0, min(100, score)), 2), factors


def run(db: Session, user_id: int, maximum: int = 1000) -> tuple[ThreatCorrelationRun, list[int]]:
    run_record = ThreatCorrelationRun(requested_by_user_id=user_id)
    db.add(run_record)
    db.commit()
    db.refresh(run_record)
    new_high_risk: list[int] = []
    try:
        observed = observations(db, maximum)
        indicators = db.query(ThreatIndicator).filter(ThreatIndicator.active.is_(True), ThreatIndicator.revoked.is_(False), ThreatIndicator.false_positive.is_(False)).all()
        exact: dict[tuple[str, str], list[ThreatIndicator]] = {}
        networks: list[tuple[ipaddress._BaseNetwork, ThreatIndicator]] = []
        for indicator in indicators:
            exact.setdefault((indicator.indicator_type, indicator.normalized_value), []).append(indicator)
            if indicator.indicator_type == "cidr":
                networks.append((ipaddress.ip_network(indicator.normalized_value), indicator))
        run_record.records_examined = len(observed)
        touched: set[int] = set()
        for obs in observed:
            try:
                normalized = normalize_indicator(obs.kind, obs.value)
            except IndicatorValidationError:
                continue
            candidates = list(exact.get((normalized.indicator_type, normalized.normalized), []))
            if obs.kind in {"domain", "hostname"}:
                other = "hostname" if obs.kind == "domain" else "domain"
                candidates.extend(exact.get((other, normalized.normalized), []))
            match_type = obs.match_type
            if obs.kind in {"ipv4", "ipv6"}:
                address = ipaddress.ip_address(normalized.normalized)
                cidr_matches = [indicator for network, indicator in networks if address in network]
                if cidr_matches:
                    candidates.extend(cidr_matches)
            for indicator in {item.id: item for item in candidates}.values():
                current_type = "cidr_membership" if indicator.indicator_type == "cidr" else match_type
                observed_hash = hashlib.sha256(f"{obs.kind}\0{normalized.normalized}".encode()).hexdigest()
                sighting = db.query(IndicatorSighting).filter_by(indicator_id=indicator.id, module=obs.module, entity_type=obs.entity_type, entity_id=obs.entity_id, observed_value_hash=observed_hash).first()
                if sighting:
                    sighting.last_observed_at = max(comparable(sighting.last_observed_at), comparable(obs.observed_at))
                    sighting.observed_at = sighting.last_observed_at
                    sighting.context_summary = obs.context
                    run_record.sightings_updated += 1
                else:
                    sighting = IndicatorSighting(indicator_id=indicator.id, module=obs.module, entity_type=obs.entity_type, entity_id=obs.entity_id, observed_value_hash=observed_hash, observed_at=obs.observed_at, context_summary=obs.context, confidence=obs.confidence, first_observed_at=obs.observed_at, last_observed_at=obs.observed_at)
                    db.add(sighting)
                    db.flush()
                    run_record.sightings_created += 1
                match = db.query(IndicatorMatch).filter_by(sighting_id=sighting.id).first()
                score, factors = risk_score(db, indicator, sighting, current_type)
                if not match:
                    match = IndicatorMatch(indicator_id=indicator.id, sighting_id=sighting.id, match_type=current_type, match_strength=100 if current_type == "exact" else 85 if current_type == "cidr_membership" else 75, risk_score=score, risk_factors_json=json.dumps(factors, sort_keys=True))
                    db.add(match)
                    db.flush()
                    run_record.matches_created += 1
                    if score >= 60:
                        new_high_risk.append(match.id)
                else:
                    match.risk_score = score
                    match.risk_factors_json = json.dumps(factors, sort_keys=True)
                touched.add(indicator.id)
        # Re-score all touched matches after module/occurrence aggregation is complete.
        for indicator_id in touched:
            indicator = db.get(ThreatIndicator, indicator_id)
            for match in db.query(IndicatorMatch).filter_by(indicator_id=indicator_id).all():
                match.risk_score, factors = risk_score(db, indicator, match.sighting, match.match_type)
                if match.status == "false_positive":
                    match.risk_score = 0
                    factors.append({"factor": "analyst_disposition", "points": 0, "explanation": "This match is dispositioned as a false positive."})
                match.risk_factors_json = json.dumps(factors, sort_keys=True)
        run_record.high_risk_matches = db.query(IndicatorMatch).filter(IndicatorMatch.id.in_(new_high_risk), IndicatorMatch.risk_score >= 60).count() if new_high_risk else 0
        run_record.status = "completed"
        run_record.completed_at = now()
        db.commit()
        db.refresh(run_record)
        return run_record, new_high_risk
    except Exception as exc:
        db.rollback()
        run_record = db.get(ThreatCorrelationRun, run_record.id)
        run_record.status = "failed"
        run_record.error_summary_json = json.dumps([str(exc)[:500]])
        run_record.completed_at = now()
        db.commit()
        raise
