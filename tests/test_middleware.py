"""
tests/test_middleware.py — unit tests for BearerAuthMiddleware.

Tests cover:
  - /health is exempt from authentication
  - /admin/* paths are exempt from authentication
  - MCP paths require a Bearer token
  - Invalid/unknown tokens are rejected with 401
  - Valid tokens are accepted and allow the request through
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware import BearerAuthMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _echo_handler(request: Request) -> JSONResponse:
    """Simple handler that returns 200 for any authenticated request."""
    return JSONResponse({"ok": True})


def _make_app(callers: dict[str, str]) -> TestClient:
    """
    Build a minimal Starlette app with BearerAuthMiddleware.
    `callers` maps bot_name -> token for the mock.
    """
    app = Starlette(
        routes=[
            Route("/health", _echo_handler, methods=["GET"]),
            Route("/admin/add_caller", _echo_handler, methods=["POST"]),
            Route("/mcp/sse", _echo_handler, methods=["GET"]),
            Route("/mcp/messages", _echo_handler, methods=["POST"]),
        ]
    )
    app.add_middleware(BearerAuthMiddleware)
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_TOKEN = "valid-bearer-token-abc"
VALID_CALLER = "test-bot"

_MOCK_TOKENS = {VALID_CALLER: VALID_TOKEN}


@pytest.fixture()
def client():
    app = _make_app(_MOCK_TOKENS)
    with patch("app.auth.merged_tokens", return_value=_MOCK_TOKENS), \
         patch("app.auth.resolve_caller", side_effect=_mock_resolve_caller):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


def _mock_resolve_caller(token: str):
    """Mimic auth.resolve_caller behaviour without file I/O."""
    import app.auth as auth_mod
    for name, tok in _MOCK_TOKENS.items():
        if tok == token:
            auth_mod._current_caller.set(name)
            return name
    return None


# ---------------------------------------------------------------------------
# test_health_exempt
# ---------------------------------------------------------------------------

def test_health_exempt(client):
    """GET /health should return 200 without any Authorization header."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ---------------------------------------------------------------------------
# test_admin_exempt
# ---------------------------------------------------------------------------

def test_admin_exempt(client):
    """POST /admin/add_caller should return 200 without Bearer token."""
    resp = client.post("/admin/add_caller")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# test_mcp_requires_bearer
# ---------------------------------------------------------------------------

def test_mcp_requires_bearer(client):
    """Requests to /mcp/* without Authorization header should return 401."""
    resp = client.get("/mcp/sse")
    assert resp.status_code == 401
    body = resp.json()
    assert "error" in body


def test_mcp_requires_bearer_not_basic(client):
    """Non-Bearer auth schemes should also be rejected."""
    resp = client.get("/mcp/sse", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# test_mcp_rejects_invalid_token
# ---------------------------------------------------------------------------

def test_mcp_rejects_invalid_token(client):
    """An unrecognised Bearer token should return 401."""
    resp = client.get("/mcp/sse", headers={"Authorization": "Bearer wrong-token-xyz"})
    assert resp.status_code == 401
    body = resp.json()
    assert "error" in body
    assert "Invalid" in body["error"] or "invalid" in body["error"]


# ---------------------------------------------------------------------------
# test_mcp_accepts_valid_token
# ---------------------------------------------------------------------------

def test_mcp_accepts_valid_token(client):
    """A valid Bearer token should let the request through (200)."""
    resp = client.get(
        "/mcp/sse",
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_mcp_post_accepts_valid_token(client):
    """POST to /mcp/messages with valid token should succeed."""
    resp = client.post(
        "/mcp/messages",
        headers={"Authorization": f"Bearer {VALID_TOKEN}"},
        json={"method": "tools/list"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# test_www_authenticate_header
# ---------------------------------------------------------------------------

def test_www_authenticate_header_on_missing_token(client):
    """401 response should include WWW-Authenticate: Bearer header."""
    resp = client.get("/mcp/sse")
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"


def test_www_authenticate_header_on_invalid_token(client):
    """401 response for invalid token should include WWW-Authenticate: Bearer header."""
    resp = client.get("/mcp/sse", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
