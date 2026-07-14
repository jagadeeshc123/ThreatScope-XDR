import re
import secrets

from starlette.middleware.base import BaseHTTPMiddleware


REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
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
        return response

