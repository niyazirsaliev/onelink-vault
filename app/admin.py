"""
admin.py — Admin endpoint for onelink-vault.

POST /admin/add_caller
  Header: X-Admin-Key: <ADMIN_KEY>
  Body JSON: {
      "bot_name": str,
      "token": str,
      "write_ok": bool (default false),
      "bw_clientid": str|null,
      "bw_clientsecret": str|null,
      "bw_password": str|null
  }

Returns JSON: {
    "ok": true,
    "bot_name": str,
    "write_ok": bool,
    "has_bw_creds": bool,
    "callers": [str, ...]   -- list of all registered caller names
}
"""

from __future__ import annotations

import json
from typing import Optional

from starlette.requests import Request
from starlette.responses import JSONResponse

import app.auth as auth
from app.config import ADMIN_KEY


async def add_caller_endpoint(request: Request) -> JSONResponse:
    """Handle POST /admin/add_caller."""

    # --- Gate: X-Admin-Key ---
    provided_key = request.headers.get("X-Admin-Key", "")
    if not ADMIN_KEY or provided_key != ADMIN_KEY:
        return JSONResponse(
            status_code=403,
            content={"error": "Invalid or missing X-Admin-Key"},
        )

    # --- Parse body ---
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "Request body must be valid JSON"},
        )

    bot_name: Optional[str] = body.get("bot_name")
    token: Optional[str] = body.get("token")

    if not bot_name or not token:
        return JSONResponse(
            status_code=400,
            content={"error": "'bot_name' and 'token' are required"},
        )

    write_ok: bool = bool(body.get("write_ok", False))
    bw_clientid: Optional[str] = body.get("bw_clientid") or None
    bw_clientsecret: Optional[str] = body.get("bw_clientsecret") or None
    bw_password: Optional[str] = body.get("bw_password") or None

    # --- Persist ---
    auth.add_caller(
        bot_name=bot_name,
        token=token,
        write_ok=write_ok,
        bw_clientid=bw_clientid,
        bw_clientsecret=bw_clientsecret,
        bw_password=bw_password,
    )

    has_bw_creds = auth.caller_bw_creds(bot_name) is not None
    all_callers = list(auth.merged_tokens().keys())

    return JSONResponse(
        status_code=200,
        content={
            "ok": True,
            "bot_name": bot_name,
            "write_ok": write_ok,
            "has_bw_creds": has_bw_creds,
            "callers": all_callers,
        },
    )
