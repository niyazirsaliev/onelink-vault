"""
main.py — onelink-vault FastMCP application entry point.

Exposes MCP tools under the 'vault' namespace:
  vault.sync           — synchronize the caller's Bitwarden cache (read)
  vault.get_password   — retrieve password for a named item
  vault.get_item       — retrieve full item details
  vault.list           — list items with optional filters
  vault.create_item    — create a new login item (write)
  vault.give           — one-way secret handoff into another bot's own folder (write)
  vault.update_field   — update a field on an existing item (write)
  vault.rotate_password — rotate an item's password (write)

All tools enforce:
  1. Caller authentication via BearerAuthMiddleware
  2. bw credential presence (503 if caller has no bw creds)
  3. write_ok flag for mutating operations (403 if not permitted)
  4. Audit logging of every call (item names only — never passwords/secrets)

Cross-vault superusers
----------------------
Every tool accepts an optional `target_caller`. It is HONORED ONLY when the
authenticated caller (derived from the bearer token via the middleware/ContextVar,
never from any request/body field) is a member of CROSS_VAULT_READ_CALLERS. For
those callers, the vault op runs against target_caller's own Vaultwarden
namespace. For any other caller, supplying target_caller is REJECTED — they
remain strictly isolated to their own vault. Omitting target_caller is
byte-identical to prior behavior.

Read vs. write cross-vault tiers: CROSS_VAULT_READ_CALLERS may cross-vault
vault.get_password / vault.get_item / vault.list. Cross-vault
vault.create_item / vault.update_field / vault.rotate_password additionally
require membership in CROSS_VAULT_WRITE_CALLERS (a subset of the read tier) —
read-only cross-vault callers get PermissionError on a cross-vault write
attempt, same as a non-superuser caller would. This is independent of, and
in addition to, each caller's own-vault write_ok flag, which continues to
gate that caller's OWN vault unchanged (a read-only cross-vault caller with
write_ok=true still has normal write access to its own namespace).

Gating fails CLOSED: anything other than a token-proven read-tier caller
cannot cross vaults at all, and anything other than a token-proven write-tier
caller cannot cross-vault-write. Every cross-vault access is audited
(actor, target_caller, tool, item ref, action, status, timestamp) — metadata
only, never secret values.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

import app.auth as auth
import app.audit as audit
import app.admin as admin_routes
import app.provision as provision_routes
from app.middleware import BearerAuthMiddleware
from app.tools import (
    create_item as _create_item_tool,
    get_item as _get_item_tool,
    get_password as _get_password_tool,
    list as _list_tool,
    rotate_password as _rotate_password_tool,
    update_field as _update_field_tool,
)

# ---------------------------------------------------------------------------
# FastMCP instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="onelink-vault",
    instructions=(
        "onelink-vault provides scoped access to a Bitwarden cloud or Vaultwarden "
        "vault via the bw CLI. "
        "Use vault.sync to explicitly refresh the local Bitwarden cache; all vault "
        "reads also synchronize first and fail closed if synchronization fails. "
        "Use vault.get_password to retrieve credentials by item name. "
        "Use vault.get_item for full item details including username, notes, and custom fields. "
        "Use vault.list to search and browse available items. "
        "Write operations (vault.create_item, vault.update_field, vault.rotate_password) "
        "require write_ok permission and valid bw credentials for the caller."
    ),
)


# ---------------------------------------------------------------------------
# Cross-vault delegation is disabled unless explicitly configured by the operator.
# These environment settings are never taken from request input.
CROSS_VAULT_READ_CALLERS = frozenset(filter(None, (x.strip() for x in os.environ.get("CROSS_VAULT_READ_CALLERS", "").split(","))))
CROSS_VAULT_WRITE_CALLERS = frozenset(filter(None, (x.strip() for x in os.environ.get("CROSS_VAULT_WRITE_CALLERS", "").split(","))))
if not CROSS_VAULT_WRITE_CALLERS <= CROSS_VAULT_READ_CALLERS:
    raise ValueError("Cross-vault write callers must also have cross-vault read permission")

# Back-compat alias (kept in case anything else imports the old name).
SUPERUSER_CALLERS = CROSS_VAULT_READ_CALLERS


def _authed_caller() -> str:
    """
    Return the authenticated caller name for the current request.

    Identity is taken ONLY from the _current_caller ContextVar, which is set
    exclusively by BearerAuthMiddleware after validating the bearer token against
    callers.json. There is no code path by which a tool argument or request body
    can influence this value — identity is always token-derived.
    """
    caller = auth._current_caller.get()
    if not caller:
        raise PermissionError("Unauthenticated request")
    return caller


def _resolve_target(target_caller: Optional[str]) -> tuple[str, str, dict, Optional[str]]:
    """Resolve actor and effective vault using operator-configured delegation.

    Returns (actor, effective_caller, credentials, cross_vault_target).
    An omitted/self target stays in the actor's account. Any other target
    requires the authenticated actor in CROSS_VAULT_READ_CALLERS; writes
    additionally require CROSS_VAULT_WRITE_CALLERS and write_ok.
    """
    actor = _authed_caller()

    # Own-vault path (no target, or target is the actor itself).
    if not target_caller or target_caller == actor:
        creds = auth.caller_bw_creds(actor)
        if not creds:
            raise ValueError("onelink-vault requires bw credentials for this caller")
        return actor, actor, creds, None

    # From here, target_caller refers to a DIFFERENT namespace => cross-vault.
    # HARD GATE: only a token-proven cross-vault-read caller may cross vaults at
    # all (read or write — the write tools apply a further, stricter check).
    # Everyone else: deny.
    if actor not in CROSS_VAULT_READ_CALLERS:
        raise PermissionError(
            "target_caller is restricted to cross-vault callers "
            f"{sorted(CROSS_VAULT_READ_CALLERS)}; caller '{actor}' may only access its own vault"
        )

    # Authenticated superuser: load the TARGET's own creds and route bw to its namespace.
    creds = auth.caller_bw_creds(target_caller)
    if creds is None:
        if target_caller not in auth.merged_tokens():
            raise ValueError(f"Unknown target_caller '{target_caller}'")
        raise ValueError(
            f"target_caller '{target_caller}' has no bw credentials configured"
        )
    return actor, target_caller, creds, target_caller


def _check_write_permission(actor: str, xvault_target: Optional[str]) -> None:
    """
    Enforce write permission for a mutating tool call.

    xvault_target is None for an own-vault call (write_ok alone governs, as
    before) and non-None for a cross-vault call, which additionally requires
    actor to be in CROSS_VAULT_WRITE_CALLERS — a read-only cross-vault caller
    (e.g. reader_a-hermes) is rejected here even though _resolve_target already
    let it through to reach a target namespace for read tools.
    """
    if xvault_target is not None and actor not in CROSS_VAULT_WRITE_CALLERS:
        raise PermissionError(
            f"Caller '{actor}' has read-only cross-vault access; cross-vault "
            f"write to '{xvault_target}' requires membership in "
            f"{sorted(CROSS_VAULT_WRITE_CALLERS)}"
        )
    if not auth.caller_has_write(actor):
        raise PermissionError(f"Caller '{actor}' does not have write_ok permission")


def _audit_target(actor: str, target_caller: Optional[str]) -> Optional[str]:
    """
    The target namespace to record in the audit trail: the requested target when
    it differs from the actor (a cross-vault attempt — logged whether it succeeds
    or is denied), else None. Computed from token identity, never trusted input.
    """
    if target_caller and target_caller != actor:
        return target_caller
    return None


# ---------------------------------------------------------------------------
# Audit wrapper
# ---------------------------------------------------------------------------

async def _wrap(
    tool_name: str,
    inputs: dict,
    fn,
    *,
    actor: Optional[str] = None,
    target_caller: Optional[str] = None,
    action: Optional[str] = None,
):
    """
    Call fn(), record timing, and write an audit log row.
    Propagates exceptions after logging.

    actor         — authenticated caller (token-derived); recorded as the audit actor.
    target_caller — cross-vault target namespace (None for own-vault); recorded so
                    every cross-vault access (success OR denial) is auditable.
    action        — "read" | "write".
    """
    caller = actor or auth._current_caller.get() or "unknown"
    start = time.monotonic()
    error_msg: Optional[str] = None
    status = "ok"
    result = None

    try:
        result = await fn()
    except PermissionError as exc:
        status = "denied"
        error_msg = str(exc)
        raise
    except Exception as exc:
        status = "error"
        error_msg = str(exc)
        raise
    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        audit.log_call(
            caller=caller,
            tool=tool_name,
            inputs=inputs,
            status=status,
            duration_ms=duration_ms,
            error=error_msg,
            target_caller=target_caller,
            action=action,
        )

    return result


# ---------------------------------------------------------------------------
# Tool: vault.get_password
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.sync")
async def vault_sync(target_caller: Optional[str] = None) -> dict:
    """Synchronize a vault cache without returning item or secret data.

    `target_caller` follows the same read-only cross-vault gate as list/get.
    The result contains status metadata only.
    """
    actor = _authed_caller()

    async def _fn():
        _, eff_caller, creds, _ = _resolve_target(target_caller)
        from app import bw_client
        return await bw_client.sync_vault(eff_caller, creds, force=True)

    return await _wrap(
        "vault.sync", {}, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="read",
    )


# ---------------------------------------------------------------------------
# Tool: vault.get_password
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.get_password")
async def vault_get_password(
    name: str,
    collection: Optional[str] = None,
    target_caller: Optional[str] = None,
) -> str:
    """
    Retrieve the password for a vault item by name.

    Args:
        name: The display name of the vault item to look up.
        collection: Optional collection name to narrow the search when multiple
                    items share the same name.
        target_caller: (delegated callers only) read from another caller's vault. Ignored/own
                    vault if equal to the caller; rejected for non-delegated callers.

    Returns:
        The password string for the matched item.
    """
    actor = _authed_caller()
    inputs = {"name": name}

    async def _fn():
        _, eff_caller, creds, _ = _resolve_target(target_caller)
        return await _get_password_tool.run(
            name=name,
            collection=collection,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.get_password", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="read",
    )


# ---------------------------------------------------------------------------
# Tool: vault.get_item
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.get_item")
async def vault_get_item(
    name: Optional[str] = None,
    item_id: Optional[str] = None,
    target_caller: Optional[str] = None,
) -> dict:
    """
    Retrieve full details for a vault item.

    Args:
        name:    Item display name (use if item_id is unknown).
        item_id: Item UUID for precise lookup.
        target_caller: (delegated callers only) read from another caller's vault. Ignored/own
                 vault if equal to the caller; rejected for non-delegated callers.

    Returns:
        Dict with keys: id, name, type, login (username, password, uris),
        notes, fields, custom_fields.
    """
    actor = _authed_caller()
    inputs = {"name": name, "item_id": item_id}

    async def _fn():
        _, eff_caller, creds, _ = _resolve_target(target_caller)
        return await _get_item_tool.run(
            name=name,
            item_id=item_id,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.get_item", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="read",
    )


# ---------------------------------------------------------------------------
# Tool: vault.list
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.list")
async def vault_list(
    search: Optional[str] = None,
    collection: Optional[str] = None,
    target_caller: Optional[str] = None,
) -> list:
    """
    List vault items, optionally filtered by search term and/or collection.

    Args:
        search:     Text search term matched against item names.
        collection: Collection name to filter results.
        target_caller: (delegated callers only) list another caller's vault. Ignored/own vault
                    if equal to the caller; rejected for non-delegated callers.

    Returns:
        List of dicts, each with keys: id, name, collection, type.
    """
    actor = _authed_caller()
    inputs = {}  # no item-identifying field to log here

    async def _fn():
        _, eff_caller, creds, _ = _resolve_target(target_caller)
        return await _list_tool.run(
            search=search,
            collection=collection,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.list", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="read",
    )


# ---------------------------------------------------------------------------
# Tool: vault.create_item  (write)
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.create_item")
async def vault_create_item(
    name: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    collection_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    custom_fields: Optional[list] = None,
    target_caller: Optional[str] = None,
    collection: Optional[str] = None,
) -> str:
    """
    Create a new login item in the vault. Requires write_ok permission.

    Args:
        name:          Display name for the new item (required).
        username:      Login username.
        password:      Login password.
        url:           Website or service URL.
        notes:         Free-text notes.
        collection_id: Collection UUID to place the item in.
        organization_id: Organization UUID owning that collection. Required
                       together with collection_id — without it Vaultwarden
                       stores the item in the caller's personal vault and the
                       collection is silently ignored.
        custom_fields: List of {name, value, type} dicts for custom fields.
        collection:    Omit to save in your own folder (owner-visible). Use "shared"
                       to hand a secret to other bots (every bot can read it).
        target_caller: (delegated callers only) create in another caller's vault. Ignored/own
                       vault if equal to the caller; rejected for non-delegated callers.

    Returns:
        The UUID of the newly created item.
    """
    actor = _authed_caller()
    inputs = {"name": name}

    async def _fn():
        actor2, eff_caller, creds, xvault_target = _resolve_target(target_caller)
        _check_write_permission(actor2, xvault_target)
        return await _create_item_tool.run(
            name=name,
            username=username,
            password=password,
            url=url,
            notes=notes,
            collection_id=collection_id,
            organization_id=organization_id,
            custom_fields=custom_fields,
            collection=collection,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.create_item", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="write",
    )


# ---------------------------------------------------------------------------
# Tool: vault.give  (one-way handoff to another bot)
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.give")
async def vault_give(
    to: str,
    name: str,
    password: Optional[str] = None,
    username: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
) -> str:
    """
    Hand a secret to another bot, one way. The item lands in the receiver's own
    folder (owner-visible) as "<name> (from <you>)". You cannot read, change or
    delete it afterwards; the receiver reads it with vault.list / vault.get_item.
    Requires write_ok. Use this instead of the shared folder for bot-to-bot keys.

    Args:
        to:       receiver bot's vault caller name (e.g. "agent_c").
        name:     what the secret is (e.g. "Stripe API key").
        password: the secret value.
        username, url, notes: optional context for the receiver.

    Returns:
        The new item's UUID in the receiver's vault.
    """
    actor = _authed_caller()

    async def _fn():
        if not auth.caller_has_write(actor):
            raise PermissionError(f"Caller '{actor}' does not have write_ok permission")
        if not to or to == actor:
            raise ValueError("'to' must name another bot")
        creds = auth.caller_bw_creds(to)
        if not creds:
            raise ValueError(f"unknown receiver '{to}'")
        # Create-only, never update: a giver can't overwrite the receiver's items
        return await _create_item_tool.run(
            name=f"{name} (from {actor})", username=username, password=password,
            url=url, notes=notes, caller=to, creds=creds,
        )

    return await _wrap("vault.give", {"name": name}, _fn, actor=actor, target_caller=to, action="give")


# ---------------------------------------------------------------------------
# Tool: vault.update_field  (write)
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.update_field")
async def vault_update_field(
    item_id: str,
    field: str,
    value: str,
    target_caller: Optional[str] = None,
) -> dict:
    """
    Update a specific field on an existing vault item. Requires write_ok permission.

    Supported built-in fields: password, username, notes, url.
    Any other field name is treated as a custom field (created if it does not exist).

    Args:
        item_id: The UUID of the vault item to update.
        field:   Field name to update (password, username, notes, url, or custom name).
        value:   New value for the field.
        target_caller: (delegated callers only) update in another caller's vault. Ignored/own
                 vault if equal to the caller; rejected for non-delegated callers.

    Returns:
        {"ok": True} on success.
    """
    actor = _authed_caller()
    inputs = {"item_id": item_id}

    async def _fn():
        actor2, eff_caller, creds, xvault_target = _resolve_target(target_caller)
        _check_write_permission(actor2, xvault_target)
        return await _update_field_tool.run(
            item_id=item_id,
            field=field,
            value=value,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.update_field", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="write",
    )


# ---------------------------------------------------------------------------
# Tool: vault.rotate_password  (write)
# ---------------------------------------------------------------------------

@mcp.tool(name="vault.rotate_password")
async def vault_rotate_password(
    item_id: str,
    length: int = 32,
    target_caller: Optional[str] = None,
) -> str:
    """
    Generate a new cryptographically-strong password and update the vault item.
    Requires write_ok permission.

    Args:
        item_id: The UUID of the vault item to update.
        length:  Desired password length in characters (16–128, default 32).
        target_caller: (delegated callers only) rotate in another caller's vault. Ignored/own
                 vault if equal to the caller; rejected for non-delegated callers.

    Returns:
        The newly generated password string.
    """
    actor = _authed_caller()
    inputs = {"item_id": item_id}

    async def _fn():
        actor2, eff_caller, creds, xvault_target = _resolve_target(target_caller)
        _check_write_permission(actor2, xvault_target)
        return await _rotate_password_tool.run(
            item_id=item_id,
            length=length,
            caller=eff_caller,
            creds=creds,
        )

    return await _wrap(
        "vault.rotate_password", inputs, _fn,
        actor=actor, target_caller=_audit_target(actor, target_caller), action="write",
    )


# ---------------------------------------------------------------------------
# ASGI application assembly
# ---------------------------------------------------------------------------

def _build_asgi_app():
    # Preserve the deployed finite idle lifetime for abandoned MCP sessions.
    app = mcp.http_app(transport="streamable-http", path="/mcp", session_idle_timeout=300)
    app.add_middleware(BearerAuthMiddleware)

    async def health(request: Request):
        return JSONResponse({"status": "ok", "service": "onelink-vault"})

    app.add_route("/health", health)
    app.add_route("/admin/add_caller", admin_routes.add_caller_endpoint, methods=["POST"])
    app.add_route("/admin/rotate", provision_routes.rotate_endpoint, methods=["POST"])
    app.add_route("/admin/remove_caller", provision_routes.remove_caller_endpoint, methods=["POST"])
    app.add_route("/admin/callers", provision_routes.callers_endpoint, methods=["GET"])
    app.add_route("/admin/deliver", provision_routes.deliver_endpoint, methods=["POST"])
    # Opt-in rollout: old deployments remain unchanged until explicitly enabled.
    if os.environ.get("INTAKE_PUBLIC_BASE_URL"):
        from app.intake import register
        app.state.intake = register(mcp, app)
    return app


asgi_app = _build_asgi_app()

if __name__ == "__main__":
    import sys
    transport = sys.argv[1] if len(sys.argv) > 1 else "http"
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        import uvicorn
        uvicorn.run(asgi_app, host="0.0.0.0", port=8000, log_level="info")
