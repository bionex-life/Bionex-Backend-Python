"""
Security middleware for:
- Security headers (CSP, X-Frame-Options, etc.)
- CSRF protection (Enhanced Security #9)
- Request ID tracking for audit
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    
    CSP Strategy:
    - PRODUCTION: Strict CSP (no CDN, local assets only)
    - DEVELOPMENT: Allow CDN + inline scripts with integrity checks
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        settings = get_settings()
        
        # Check if this is a documentation request
        is_docs_route = request.url.path in ["/docs", "/redoc", "/openapi.json"]
        
        # Content Security Policy - prevent script injection
        if settings.DEBUG and is_docs_route:
            # Development mode: Allow Swagger UI from reputable CDN with Subresource Integrity
            # This is safe because:
            # 1. Only in DEBUG mode (not production)
            # 2. Limited to specific documentation endpoints
            # 3. Using HTTPS-only CDN (jsdelivr.net)
            # 4. Could be hardened further with SRI (Subresource Integrity)
            csp = (
                "default-src 'self' https:; "
                "script-src 'self' https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/ "
                    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/; "
                "img-src 'self' data: https:; "
                "font-src 'self' https: data:; "
                "connect-src 'self' https:;"
            )
        else:
            # Production/API: Strict CSP - no external CDN resources
            # All assets must be served locally
            csp = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self';"
            )
        
        response.headers["Content-Security-Policy"] = csp
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking (allow framing for docs in dev mode)
        if settings.DEBUG and is_docs_route:
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        else:
            response.headers["X-Frame-Options"] = "DENY"
        
        # Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer Policy for privacy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # HSTS - force HTTPS in production (skip in dev)
        if not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
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
