"""
tools/list.py — list vault items with optional search and collection filter.

Returns a list of {id, name, collection, type} summary records.
No secret values are included.
"""

from __future__ import annotations

from typing import Optional

from app import bw_client


# bw type codes → human-readable labels
_TYPE_LABELS = {
    1: "login",
    2: "secure_note",
    3: "card",
    4: "identity",
}


async def run(
    search: Optional[str] = None,
    collection: Optional[str] = None,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> list[dict]:
    """
    List vault items, optionally filtered by search term and/or collection.

    Parameters
    ----------
    search     : text search term (matched against item name/username)
    collection : collection name filter (client-side after fetching all items)
    caller     : bot_name for bw session routing
    creds      : bw credentials dict

    Returns
    -------
    List of dicts with keys: id, name, collection, type

    Raises
    ------
    ValueError  if no creds provided
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError("onelink-vault requires bw credentials for this caller")

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    ciphers = await bw_client.list_ciphers(
        bot_name=caller,
        creds=creds,
        search=search,
        collection=collection,
    )

    # Fetch collection name map once if we have collection IDs to resolve.
    # list_collections enforces its own successful sync; do not bypass it via
    # the lower-level _bw_run helper, which could return stale cache data.
    col_ids_all: set[str] = set()
    for c in ciphers:
        col_ids_all.update(c.get("collectionIds") or [])

    col_name_map: dict[str, str] = {}
    if col_ids_all:
        # A failed collection sync is a failed read, not a reason to return a
        # potentially stale item response with incomplete collection metadata.
        cols = await bw_client.list_collections(caller, creds)
        for col in cols:
            cid = col.get("id")
            cname = col.get("name", "")
            if cid:
                col_name_map[cid] = cname

    result = []
    for c in ciphers:
        col_names = [
            col_name_map.get(cid, cid)
            for cid in (c.get("collectionIds") or [])
        ]
        result.append({
            "id": c.get("id"),
            "name": c.get("name"),
            "collection": col_names[0] if col_names else None,
            "type": _TYPE_LABELS.get(c.get("type"), "unknown"),
        })

    return result
