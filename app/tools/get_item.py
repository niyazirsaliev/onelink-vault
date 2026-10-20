"""
tools/get_item.py — retrieve full vault item details.

Returns a sanitised dict: {id, name, type, login, notes, fields, custom_fields}.
The password field IS included here (callers explicitly request full item data).
"""

from __future__ import annotations

from typing import Optional

from app import bw_client


def _extract_custom_fields(fields: list) -> list[dict]:
    """Convert bw 'fields' list to {name, value, type} dicts."""
    result = []
    for f in fields or []:
        result.append({
            "name": f.get("name"),
            "value": f.get("value"),
            "type": f.get("type"),
        })
    return result


async def run(
    name: Optional[str] = None,
    item_id: Optional[str] = None,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> dict:
    """
    Retrieve a full vault item by name or item ID.

    Parameters
    ----------
    name    : item name to look up (used if item_id not provided)
    item_id : direct item UUID
    caller  : bot_name for bw session routing
    creds   : bw credentials dict

    Returns
    -------
    dict with keys:
        id, name, type, login (username, password, uris), notes,
        fields (bw fields list), custom_fields (name/value/type)

    Raises
    ------
    ValueError  if neither name nor item_id provided, or no creds
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError("<NAME> requires bw credentials for this caller")

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    if not name and not item_id:
        raise ValueError("Either 'name' or 'item_id' must be provided")

    cipher = await bw_client.get_cipher(
        bot_name=caller,
        creds=creds,
        name=name,
        cipher_id=item_id,
    )

    if not isinstance(cipher, dict):
        raise RuntimeError(f"Unexpected bw response for item '{name or item_id}'")

    login_raw = cipher.get("login") or {}
    fields_raw = cipher.get("fields") or []

    login = {
        "username": login_raw.get("username"),
        "password": login_raw.get("password"),
        "uris": [u.get("uri") for u in (login_raw.get("uris") or [])],
    }

    return {
        "id": cipher.get("id"),
        "name": cipher.get("name"),
        "type": cipher.get("type"),
        "login": login,
        "notes": cipher.get("notes"),
        "fields": fields_raw,
        "custom_fields": _extract_custom_fields(fields_raw),
    }
