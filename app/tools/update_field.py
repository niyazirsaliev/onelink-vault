"""
tools/update_field.py — update a specific field on an existing vault item.

Supported built-in fields: password, username, notes, url (first URI).
Custom fields (arbitrary name) are also supported and matched case-insensitively.

Returns {"ok": True} on success.
"""

from __future__ import annotations

from typing import Any, Optional

from app import bw_client

# Fields that live in cipher.login
_LOGIN_FIELDS = {"password", "username"}
# Fields that live at cipher root
_ROOT_FIELDS = {"notes"}


async def run(
    item_id: str,
    field: str,
    value: Any,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> dict:
    """
    Update a single field on a vault item.

    Parameters
    ----------
    item_id : vault item UUID
    field   : field to update — one of: password, username, notes, url,
              or a custom field name (matched case-insensitively)
    value   : new value for the field
    caller  : bot_name for bw session routing
    creds   : bw credentials dict

    Returns
    -------
    {"ok": True}

    Raises
    ------
    ValueError  if item_id/field missing, field unknown, or no creds
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError("<NAME> requires bw credentials for this caller")

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    if not item_id:
        raise ValueError("'item_id' is required")

    if not field:
        raise ValueError("'field' is required")

    field_lower = field.lower()

    if field_lower in _LOGIN_FIELDS:
        updates = {"login": {field_lower: value}}

    elif field_lower == "notes":
        updates = {"notes": value}

    elif field_lower == "url":
        # Replace the first URI; preserve others
        existing = await bw_client.get_cipher(bot_name=caller, creds=creds, cipher_id=item_id)
        existing_login = existing.get("login") or {}
        uris = list(existing_login.get("uris") or [])
        if uris:
            uris[0] = {"match": uris[0].get("match"), "uri": value}
        else:
            uris = [{"match": None, "uri": value}]
        updates = {"login": {"uris": uris}}

    else:
        # Custom field — fetch item, find field by name, update value
        existing = await bw_client.get_cipher(bot_name=caller, creds=creds, cipher_id=item_id)
        fields_list: list = list(existing.get("fields") or [])

        matched = False
        for f in fields_list:
            if (f.get("name") or "").lower() == field_lower:
                f["value"] = str(value)
                matched = True
                break

        if not matched:
            # Append a new text custom field
            fields_list.append({"name": field, "value": str(value), "type": 0})

        updates = {"fields": fields_list}

    await bw_client.update_cipher(
        bot_name=caller,
        creds=creds,
        cipher_id=item_id,
        updates=updates,
    )

    return {"ok": True}
