import html
import json
from collections import Counter

from sqlalchemy.orm import Session

from .models import IndicatorMatch, IndicatorSighting, ThreatCampaign, ThreatIndicator, ThreatIntelReport, ThreatIntelSource, ThreatWatchlist
from .normalization import defang
from .service import now


SECTIONS = [
    "Report metadata", "Executive summary", "Source summary", "Indicator totals", "Indicator-type breakdown",
    "Severity breakdown", "Confidence breakdown", "TLP distribution", "Watchlist summary", "Campaign summary",
    "Cross-module sightings", "High-risk matches", "Confirmed matches", "False positives", "Expired/revoked indicators",
    "Escalated incident cases", "Correlation methodology", "Risk-scoring explanation", "Limitations", "Static/offline-analysis disclaimer",
]


def _list(items):
    return "<ul>" + "".join(f"<li>{html.escape(str(key))}: {html.escape(str(value))}</li>" for key, value in items) + "</ul>"


def generate(db: Session, *, title: str, report_type: str, defanged: bool, user_id: int) -> ThreatIntelReport:
    indicators = db.query(ThreatIndicator).order_by(ThreatIndicator.id).all()
    matches = db.query(IndicatorMatch).order_by(IndicatorMatch.risk_score.desc(), IndicatorMatch.id).all()
    sightings = db.query(IndicatorSighting).order_by(IndicatorSighting.id).all()
    types = Counter(item.indicator_type for item in indicators)
    severities = Counter(item.severity for item in indicators)
    confidences = Counter("0-24" if item.confidence < 25 else "25-49" if item.confidence < 50 else "50-74" if item.confidence < 75 else "75-100" for item in indicators)
    tlps = Counter(item.tlp for item in indicators)
    modules = Counter(item.module for item in sightings)
    safe_values = [defang(item.normalized_value, item.indicator_type) if defanged else item.normalized_value for item in indicators[:200]]
    content = {
        "Report metadata": f"<p>Generated: {html.escape(now().isoformat())}. Type: {html.escape(report_type)}. Values: {'defanged' if defanged else 'raw'}.</p>",
        "Executive summary": f"<p>This deterministic local report covers {len(indicators)} indicators, {len(sightings)} sightings, and {len(matches)} matches.</p>",
        "Source summary": _list((item.name, f"{item.source_type}; reliability {item.reliability}") for item in db.query(ThreatIntelSource).order_by(ThreatIntelSource.name)),
        "Indicator totals": f"<p>Active: {sum(1 for x in indicators if x.active and not x.revoked)}. Total: {len(indicators)}.</p>" + _list((f"IOC {index + 1}", value) for index, value in enumerate(safe_values)),
        "Indicator-type breakdown": _list(sorted(types.items())),
        "Severity breakdown": _list(sorted(severities.items())),
        "Confidence breakdown": _list(sorted(confidences.items())),
        "TLP distribution": _list(sorted(tlps.items())),
        "Watchlist summary": _list((item.name, len(item.entries)) for item in db.query(ThreatWatchlist).order_by(ThreatWatchlist.name)),
        "Campaign summary": _list((item.name, len(item.indicators)) for item in db.query(ThreatCampaign).order_by(ThreatCampaign.name)),
        "Cross-module sightings": _list(sorted(modules.items())),
        "High-risk matches": _list((f"Match {item.id}", f"risk {item.risk_score:.1f}; {item.status}") for item in matches if item.risk_score >= 60),
        "Confirmed matches": _list((f"Match {item.id}", f"risk {item.risk_score:.1f}") for item in matches if item.status == "confirmed"),
        "False positives": _list((f"Match {item.id}", "analyst disposition") for item in matches if item.status == "false_positive"),
        "Expired/revoked indicators": f"<p>{sum(1 for x in indicators if x.revoked or not x.active)} inactive or revoked indicators. Expiration is retained as lifecycle data.</p>",
        "Escalated incident cases": _list((f"Match {item.id}", f"case {item.case_id}") for item in matches if item.case_id),
        "Correlation methodology": "<p>Exact normalized matching is used by default. URL host matches and explicit CIDR membership are labeled separately. Only already-stored ThreatScope XDR data is inspected.</p>",
        "Risk-scoring explanation": "<p>The deterministic 0-100 score weights severity (35%), confidence (25%), source reliability (10%), occurrences, affected modules, recency, watchlist/confirmed status, and match strength. Expired indicators receive a 0.6 multiplier; inactive, revoked, and false-positive indicators score zero.</p>",
        "Limitations": "<p>The STIX importer supports a bounded subset. No external reputation, causal inference, fuzzy hash/IP matching, feed download, DNS resolution, or automated blocking is performed.</p>",
        "Static/offline-analysis disclaimer": "<p>This is a static, offline analysis of locally stored data. Indicators are inert text and are not hyperlinks. No target was contacted during report generation.</p>",
    }
    css = "body{font:14px system-ui;max-width:1100px;margin:2rem auto;color:#17202a}h1,h2{color:#15344b}section{border-top:1px solid #ccd6dd;padding:1rem 0}li{overflow-wrap:anywhere}"
    document = "<!doctype html><html><head><meta charset='utf-8'><title>" + html.escape(title) + "</title><style>" + css + "</style></head><body><h1>" + html.escape(title) + "</h1>"
    document += "".join(f"<section><h2>{index}. {html.escape(name)}</h2>{content[name]}</section>" for index, name in enumerate(SECTIONS, 1))
    document += "</body></html>"
    report = ThreatIntelReport(title=title, report_type=report_type, html_content=document, summary_json=json.dumps({"indicator_count": len(indicators), "sighting_count": len(sightings), "match_count": len(matches), "sections": SECTIONS}, sort_keys=True), defanged=defanged, created_by_user_id=user_id)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report

