import json
import uuid
from datetime import datetime, timedelta
from statistics import fmean, median, pstdev

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import IMPLEMENTATION_VERSION
from .features import clean_values, deterministic_hash, interquartile_range, median_absolute_deviation, percentile, seasonal_bucket, stable_round, utc, window_series
from .models import AnalyticsBaseline


MIN_PEER_GROUP_SIZE = 5
MAX_BASELINE_WINDOWS = 1000


def _summary(values: list[float]) -> dict:
    if not values:
        return {key: None for key in ("mean", "median", "minimum", "maximum", "standard_deviation", "mad", "iqr")}
    return {
        "mean": stable_round(fmean(values)), "median": stable_round(median(values)),
        "minimum": stable_round(min(values)), "maximum": stable_round(max(values)),
        "standard_deviation": stable_round(pstdev(values)) if len(values) > 1 else 0.0,
        "mad": median_absolute_deviation(values), "iqr": interquartile_range(values),
        "percentiles": {str(q): percentile(values, q) for q in (5, 25, 50, 75, 95)},
    }


def build_statistics(values, *, minimum_samples: int, timestamps: list[datetime] | None = None, seasonality: str = "none", winsorize: bool = False, peer_group_size: int | None = None) -> dict:
    if not 1 <= int(minimum_samples) <= MAX_BASELINE_WINDOWS:
        raise ValueError("Minimum sample requirement is outside the server bound")
    raw_values = list(values)
    clean, missing = clean_values(raw_values, non_negative=True)
    original = _summary(clean)
    used = list(clean)
    winsorized_count = 0
    if winsorize and used:
        low, high = percentile(used, 5), percentile(used, 95)
        used = [max(low, min(high, item)) for item in used]  # type: ignore[arg-type]
        winsorized_count = sum(1 for left, right in zip(clean, used) if left != right)
    status, reason = "ready", None
    if peer_group_size is not None and peer_group_size < MIN_PEER_GROUP_SIZE:
        status, reason = "insufficient_data", f"Peer group contains {peer_group_size}; at least {MIN_PEER_GROUP_SIZE} aggregate members are required."
    elif len(used) < minimum_samples:
        status, reason = "insufficient_data", f"Only {len(used)} historical windows are available; {minimum_samples} are required."
    summary = _summary(used)
    seasonal: dict[str, dict] = {}
    fallback_buckets: list[str] = []
    if seasonality != "none":
        if timestamps is None or len(timestamps) != len(raw_values):
            raise ValueError("Seasonal baselines require one timestamp per input value")
        buckets: dict[str, list[float]] = {}
        for timestamp, value in zip(timestamps, raw_values):
            if value is None:
                continue
            buckets.setdefault(seasonal_bucket(timestamp, seasonality), []).append(float(value))
        seasonal_minimum = max(3, min(minimum_samples, 10))
        for key in sorted(buckets):
            if len(buckets[key]) < seasonal_minimum:
                fallback_buckets.append(key)
                seasonal[key] = {"status": "fallback", "sample_count": len(buckets[key]), "fallback": "non_seasonal_baseline"}
            else:
                seasonal[key] = {"status": "ready", "sample_count": len(buckets[key]), **_summary(buckets[key])}
    payload = {
        **summary, "observation_count": len(used), "missing_value_count": missing,
        "status": status, "insufficiency_reason": reason, "seasonality": seasonality,
        "seasonal_summaries": seasonal, "seasonal_fallback_buckets": fallback_buckets,
        "winsorized": winsorize, "winsorized_count": winsorized_count, "original_summary": original,
        "implementation_version": IMPLEMENTATION_VERSION,
    }
    payload["data_hash"] = deterministic_hash({"values": [stable_round(item) for item in used], "missing": missing, "seasonality": seasonality, "timestamps": [utc(item).isoformat() for item in timestamps] if timestamps else []})
    return payload


def build_baseline(
    db: Session, *, detector_version, feature_key: str, cutoff: datetime, lookback_seconds: int,
    observation_window_seconds: int, minimum_samples: int, source_scope: str = "platform",
    source_entity_identifier: str = "", peer_group_identifier: str = "", scope: dict | None = None,
    seasonality: str = "none", winsorize: bool = False, peer_group_size: int | None = None,
) -> AnalyticsBaseline:
    cutoff = utc(cutoff)
    if lookback_seconds < observation_window_seconds or lookback_seconds > 366 * 86400:
        raise ValueError("Baseline lookback is outside the server bound")
    start = cutoff - timedelta(seconds=lookback_seconds)
    samples = window_series(db, feature_key, start, cutoff, observation_window_seconds, scope)
    values = [item["value"] for item in samples]
    timestamps = [datetime.fromisoformat(item["window_end"].removesuffix("Z")) for item in samples]
    stats = build_statistics(values, minimum_samples=minimum_samples, timestamps=timestamps, seasonality=seasonality, winsorize=winsorize, peer_group_size=peer_group_size)
    existing = db.query(AnalyticsBaseline).filter_by(
        detector_version_id=detector_version.id, feature_key=feature_key, source_scope=source_scope[:120],
        source_entity_identifier=source_entity_identifier[:200], peer_group_identifier=peer_group_identifier[:120],
        source_data_cutoff=cutoff, data_hash=stats["data_hash"],
    ).first()
    if existing:
        return existing
    item = AnalyticsBaseline(
        baseline_uuid=str(uuid.uuid4()), detector_version_id=detector_version.id, feature_key=feature_key,
        source_scope=source_scope[:120], source_entity_identifier=source_entity_identifier[:200], peer_group_identifier=peer_group_identifier[:120],
        baseline_window_start=start, baseline_window_end=cutoff, observation_count=stats["observation_count"],
        missing_value_count=stats["missing_value_count"], median_value=stats["median"], mean_value=stats["mean"],
        minimum_value=stats["minimum"], maximum_value=stats["maximum"], standard_deviation=stats["standard_deviation"],
        mad_value=stats["mad"], iqr_value=stats["iqr"], percentiles_json=json.dumps(stats["percentiles"], sort_keys=True, allow_nan=False),
        seasonal_summaries_json=json.dumps(stats["seasonal_summaries"], sort_keys=True, allow_nan=False),
        original_summary_json=json.dumps(stats["original_summary"], sort_keys=True, allow_nan=False), winsorized=stats["winsorized"],
        source_data_cutoff=cutoff, data_hash=stats["data_hash"], baseline_status=stats["status"],
        insufficiency_reason=stats["insufficiency_reason"], implementation_version=IMPLEMENTATION_VERSION,
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(AnalyticsBaseline).filter_by(
            detector_version_id=detector_version.id, feature_key=feature_key, source_scope=source_scope[:120],
            source_entity_identifier=source_entity_identifier[:200], peer_group_identifier=peer_group_identifier[:120],
            source_data_cutoff=cutoff, data_hash=stats["data_hash"],
        ).first()
        if existing:
            return existing
        raise
    return item
