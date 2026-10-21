"""
tools/create_item.py — create a new vault item.

Builds a bw-compatible cipher payload and delegates to bw_client.create_cipher.
Returns the new item's ID string.
"""

from __future__ import annotations

from typing import Optional

from app import bw_client

# bw item type codes
TYPE_LOGIN = 1
TYPE_SECURE_NOTE = 2


def _pick_collection(cols: list[dict], caller: str, wanted: Optional[str]) -> Optional[dict]:
    """Owner-visible default: the collection named after the caller, else the caller's
    only non-'shared' collection. `wanted` (e.g. 'shared') must match by name."""
    if wanted:
        hit = [c for c in cols if c.get("name") == wanted]
        if not hit:
            raise ValueError(f"collection '{wanted}' is not available to this caller")
        return hit[0]
    hit = [c for c in cols if c.get("name") == caller]
    if hit:
        return hit[0]
    own = [c for c in cols if c.get("name") != "shared"]
    return own[0] if len(own) == 1 else None


def _build_login_payload(
    name: str,
    username: Optional[str],
    password: Optional[str],
    url: Optional[str],
    notes: Optional[str],
    collection_id: Optional[str],
    organization_id: Optional[str],
    custom_fields: Optional[list[dict]],
) -> dict:
    """Assemble a bw-format login cipher dict."""
    payload: dict = {
        "type": TYPE_LOGIN,
        "name": name,
        "login": {
            "username": username or "",
            "password": password or "",
            "uris": [{"match": None, "uri": url}] if url else [],
        },
        "notes": notes or "",
        "fields": [],
    }

    if custom_fields:
        for cf in custom_fields:
            payload["fields"].append({
                "name": cf.get("name", ""),
                "value": cf.get("value", ""),
                "type": cf.get("type", 0),  # 0 = text
            })

    if collection_id:
        payload["collectionIds"] = [collection_id]
        # A cipher in a collection MUST also carry the owning organization, or
        # Vaultwarden stores it as a personal item and the collection link is
        # silently dropped — the item then only shows in "My Vault".
        if organization_id:
            payload["organizationId"] = organization_id
    else:
        payload["collectionIds"] = []

    return payload


async def run(
    name: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    collection_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    custom_fields: Optional[list[dict]] = None,
    collection: Optional[str] = None,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> str:
    """
    Create a new login item in the vault.

    Parameters
    ----------
    name          : display name for the item (required)
    username      : login username
    password      : login password
    url           : website/service URL
    notes         : free-text notes
    collection_id : collection UUID to place the item in
    organization_id : organization UUID owning that collection; required
                    whenever collection_id is set, otherwise Vaultwarden
                    silently files the item under the caller's personal vault
    custom_fields : list of {name, value, type} dicts (type: 0=text, 1=hidden, 2=boolean)
    caller        : bot_name for bw session routing
    creds         : bw credentials dict

    Returns
    -------
    str — the new item's UUID

    Raises
    ------
    ValueError  if missing required args or no creds
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError("onelink-vault requires bw credentials for this caller")

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    if not name:
        raise ValueError("'name' is required to create an item")

    if not collection_id:
        # Personal-vault items are invisible to the owner; file into the bot's collection.
        col = _pick_collection(await bw_client.list_collections(caller, creds), caller, collection)
        if col:
            collection_id, organization_id = col["id"], col["organizationId"]

    payload = _build_login_payload(
        name=name,
        username=username,
        password=password,
        url=url,
        notes=notes,
        collection_id=collection_id,
        organization_id=organization_id,
        custom_fields=custom_fields,
    )

    item_id = await bw_client.create_cipher(
        bot_name=caller,
        creds=creds,
        payload=payload,
    )

    return item_id
