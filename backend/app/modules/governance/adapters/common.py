from datetime import datetime, timezone


def stamp(record):
    for name in ("updated_at", "created_at", "detected_at", "generated_at", "analyzed_at", "started_at"):
        value = getattr(record, name, None)
        if value:
            return value
    return datetime.now(timezone.utc)


def row(module, record_type, record, category, title, evidence, severity="medium", confidence="medium", route=None):
    return {"source_module": module, "source_record_type": record_type, "source_record_id": record.id, "category": category, "title": title or f"{record_type} #{record.id}", "evidence": evidence or "Bounded local source observation.", "severity": severity or "medium", "confidence": confidence or "medium", "route": route, "observed_at": stamp(record)}
