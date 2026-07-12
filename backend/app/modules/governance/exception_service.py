from datetime import datetime, timezone


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def is_active(item, at=None):
    at = at or datetime.now(timezone.utc)
    return item.status == "approved" and item.expires_at is not None and utc(item.expires_at) > at
