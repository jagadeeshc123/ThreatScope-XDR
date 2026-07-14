import re
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware


REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        started = time.perf_counter()
        inbound = request.headers.get("X-Request-ID", "")
        request_id = inbound if REQUEST_ID_RE.fullmatch(inbound) else secrets.token_hex(16)
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'self'"
        )
        if request.url.path.startswith(("/api/auth", "/api/admin", "/api/security-audit")):
            response.headers["Cache-Control"] = "no-store"
        try:
            from app.modules.platform_operations.logging_service import logger
            actor = getattr(request.state, "current_user", None)
            logger.info("Request completed", extra={"event_name": "http_request", "request_id": request_id,
                "actor_user_id": getattr(actor, "id", None), "route_template": request.url.path,
                "method": request.method, "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2), "safe_metadata": {}})
        except Exception:
            pass
        return response
