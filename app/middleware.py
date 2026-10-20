"""
middleware.py — Bearer token authentication middleware for <NAME>.

Exempts /health and /admin/ prefixes from auth.
All other paths require a valid Bearer token from callers.json.
Sets _current_caller ContextVar on success.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.auth import resolve_caller


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces Bearer token authentication on all routes
    except /health and paths under /admin/.
    """

    EXEMPT_PREFIXES = ("/health", "/admin/")
    # Exact method/path pairs only; these handlers enforce capability/session/CSRF.
    INTAKE_PATHS = frozenset({("GET", "/intake/")} | {
        ("POST", "/intake/" + action)
        for action in ("session", "submit", "confirm", "status")
    })

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if (request.method, path) in self.INTAKE_PATHS:
            return await call_next(request)

        # Allow exempt paths through without authentication
        for prefix in self.EXEMPT_PREFIXES:
            if path == prefix or path.startswith(prefix):
                return await call_next(request)

        # Extract Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or malformed Authorization header"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[len("Bearer "):]
        caller = resolve_caller(token)

        if caller is None:
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid Bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        # _current_caller ContextVar is set inside resolve_caller
        return await call_next(request)
