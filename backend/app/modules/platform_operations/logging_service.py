import json
import logging
from datetime import datetime, timezone

from .redaction import redact


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event_name": getattr(record, "event_name", "application_log"),
            "request_id": getattr(record, "request_id", None),
            "actor_user_id": getattr(record, "actor_user_id", None),
            "route_template": getattr(record, "route_template", None),
            "method": getattr(record, "method", None),
            "status_code": getattr(record, "status_code", None),
            "duration_ms": getattr(record, "duration_ms", None),
            "job_key": getattr(record, "job_key", None),
            "metadata": redact(getattr(record, "safe_metadata", {})),
            "message": redact(record.getMessage(), "message"),
        }
        return json.dumps(payload, sort_keys=True, default=str)


def configure_logging():
    logger = logging.getLogger("threatscope.operations")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


logger = configure_logging()
