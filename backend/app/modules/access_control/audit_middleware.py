import re
import secrets
import time

import ipaddress
from fastapi.responses import JSONResponse

from starlette.middleware.base import BaseHTTPMiddleware


REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        from app.modules.production.config import get_runtime_config
        from app.modules.production.headers import response_security_headers

        config = get_runtime_config()
        started = time.perf_counter()
        inbound = request.headers.get("X-Request-ID", "")
        request_id = inbound if REQUEST_ID_RE.fullmatch(inbound) else secrets.token_hex(16)
        request.state.request_id = request_id
        content_length = request.headers.get("content-length", "")
        if content_length:
            try:
                upload_route = any(token in request.url.path for token in ("/upload", "/import", "/stix", "/documents", "/document-threats"))
                maximum = config.max_upload_bytes if upload_route else config.max_request_bytes
                too_large = int(content_length) > maximum
            except ValueError:
                too_large = True
            if too_large:
                return JSONResponse(status_code=413, content={"detail": "Request body exceeds the configured limit", "request_id": request_id}, headers={"X-Request-ID": request_id, "Cache-Control": "no-store"})
        if len(request.url.path) > 2048 or len(request.query_params) > 100 or len(request.headers) > 100:
            return JSONResponse(status_code=400, content={"detail": "Request metadata exceeds the configured limit", "request_id": request_id}, headers={"X-Request-ID": request_id, "Cache-Control": "no-store"})
        trusted_proxy = False
        try:
            address = ipaddress.ip_address(request.client.host if request.client else "")
            trusted_proxy = any(address in ipaddress.ip_network(item, strict=False) for item in config.trusted_proxy_networks)
        except ValueError:
            trusted_proxy = False
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().casefold()
        request.state.external_scheme = forwarded_proto if trusted_proxy and forwarded_proto in {"http", "https"} else request.url.scheme
        request.state.trusted_proxy = trusted_proxy
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        for name, value in response_security_headers(config, https=request.state.external_scheme == "https", path=request.url.path).items():
            response.headers[name] = value
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
