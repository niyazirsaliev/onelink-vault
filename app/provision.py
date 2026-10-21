"""Generic caller lifecycle and credential delivery endpoints.

Account creation is intentionally left to Bitwarden or Vaultwarden's own UI.
"""
from __future__ import annotations
import json
import secrets
from starlette.requests import Request
from starlette.responses import JSONResponse
import app.auth as auth
from app.config import ADMIN_KEY

async def rotate_endpoint(request: Request) -> JSONResponse:
    """POST /admin/rotate {"bot_name"}: new bearer for an existing caller; its VW account, data and write flag stay."""
    if not ADMIN_KEY or not secrets.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=403)
    try:
        name = str((await request.json()).get("bot_name", "")).strip().lower()
    except Exception:
        return JSONResponse({"error": "Request body must be valid JSON"}, status_code=400)
    token = secrets.token_urlsafe(32)
    with auth._cache_lock:
        callers = auth._load_callers_locked()
        entry = callers.get(name)
        if not isinstance(entry, dict) or not entry.get("bw_clientid"):
            return JSONResponse({"error": "no such provisioned caller"}, status_code=404)
        callers[name] = {**entry, "token": token}
        auth._save_callers_locked(dict(callers))
    return JSONResponse({"ok": True, "bot_name": name, "token": token})


async def remove_caller_endpoint(request: Request) -> JSONResponse:
    """POST /admin/remove_caller {"bot_name"}: the bot loses onelink-vault access; its VW account and data stay."""
    if not ADMIN_KEY or not secrets.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=403)
    name = str((await request.json()).get("bot_name", ""))
    with auth._cache_lock:
        callers = auth._load_callers_locked()
        found = callers.pop(name, None) is not None
        if found:
            auth._save_callers_locked(dict(callers))
    return JSONResponse({"ok": True, "removed": found})


async def callers_endpoint(request: Request) -> JSONResponse:
    """GET /admin/callers: names + write flag only (no tokens, no creds)."""
    if not ADMIN_KEY or not secrets.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=403)
    return JSONResponse([{"name": n, "write_ok": auth.caller_has_write(n)} for n in sorted(auth.merged_tokens())])


async def deliver_endpoint(request: Request) -> JSONResponse:
    """POST /admin/deliver {"bot_name","name","password","username?","url?","notes?"}: deliver a credential directly into the bot's own folder (owner-visible), replacing an older item of the same name."""
    if not ADMIN_KEY or not secrets.compare_digest(request.headers.get("X-Admin-Key", ""), ADMIN_KEY):
        return JSONResponse({"error": "Invalid or missing X-Admin-Key"}, status_code=403)
    try:
        b = await request.json()
    except Exception:
        return JSONResponse({"error": "Request body must be valid JSON"}, status_code=400)
    bot, name = str(b.get("bot_name", "")), str(b.get("name", "")).strip()
    creds = auth.caller_bw_creds(bot)
    if not creds or not name or not b.get("password"):
        return JSONResponse({"error": "bot_name (with a vault) + name + password"}, status_code=400)
    from app import bw_client
    from app.tools import create_item, update_field
    try:
        col = create_item._pick_collection(await bw_client.list_collections(bot, creds), bot, None)
        if not col:
            return JSONResponse({'error':'Own collection unavailable; no credentials changed'}, status_code=409)
        old = [c for c in await bw_client.list_ciphers(bot, creds, search=name)
               if c.get('name') == name and col['id'] in (c.get('collectionIds') or [])]
        if len(old) > 1:
            return JSONResponse({'error':'Multiple own credential items; resolve duplicate before delivery'}, status_code=409)
        if old:
            await update_field.run(item_id=old[0]["id"], field="password", value=b["password"], caller=bot, creds=creds)
            return JSONResponse({"ok": True, "id": old[0]["id"], "updated": True})
        iid = await create_item.run(name=name, username=b.get("username"), password=b["password"], url=b.get("url"),
                                    notes=b.get("notes"), caller=bot, creds=creds, collection_id=col['id'], organization_id=col['organizationId'])
    except Exception as e:
        return JSONResponse({"error": f"deliver failed: {e}"[:300]}, status_code=502)
    return JSONResponse({"ok": True, "id": iid})
