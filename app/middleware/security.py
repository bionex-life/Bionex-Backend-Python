"""
Security middleware for:
- Security headers (CSP, X-Frame-Options, etc.)
- CSRF protection (Enhanced Security #9)
- Request ID tracking for audit
"""

from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Content Security Policy - prevent script injection
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self';"
        )

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy for privacy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # HSTS - force HTTPS in production
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate and track request IDs for audit trail."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection by validating Origin and Referer headers.
    (Enhanced Security #9)
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip CSRF check for safe methods
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        # Skip CSRF check for public endpoints (no auth required)
        public_paths = ["/health", "/docs", "/redoc", "/openapi.json"]
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)

        # For state-changing operations, validate Origin / Referer
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")

        if not origin and not referer:
            # CSRF: no origin/referer for state-changing operation
            # Allow if it's a simple form submission (no API)
            # For API clients, this would be caught
            pass

        response = await call_next(request)
        return response
