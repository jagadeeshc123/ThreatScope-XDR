from __future__ import annotations

from .config import RuntimeConfig


PRODUCTION_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'"
)


def response_security_headers(config: RuntimeConfig, *, https: bool, path: str) -> dict[str, str]:
    headers = {
        "Content-Security-Policy": PRODUCTION_CSP if config.production else (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'self'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "X-Frame-Options": "DENY" if config.production else "SAMEORIGIN",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    if config.production and https:
        headers["Strict-Transport-Security"] = "max-age=31536000"
    if path.startswith(("/api/auth", "/api/admin", "/api/security-audit", "/api/operations", "/api/reports")):
        headers["Cache-Control"] = "no-store"
    elif path.startswith("/api/"):
        headers["Cache-Control"] = "private, no-store"
    return headers
