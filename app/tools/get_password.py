"""
tools/get_password.py — retrieve the password for a named vault item.

Returns only the password string; the value never appears in audit logs.
"""

from __future__ import annotations

from typing import Optional

from app import bw_client


async def run(
    name: str,
    collection: Optional[str] = None,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> str:
    """
    Retrieve the password for the vault item identified by `name`.

    Parameters
    ----------
    name       : item name (or partial name) to look up
    collection : optional collection name to narrow the search
    caller     : bot_name of the requesting caller (used for per-bot BW_HOME)
    creds      : dict with bw_clientid, bw_clientsecret, bw_password

    Returns
    -------
    The password string for the matching item.

    Raises
    ------
    ValueError  if no creds are provided, item not found, or item has no password
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError(
            "onelink-vault requires bw credentials for this caller"
        )

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    password = await bw_client.get_password(
        bot_name=caller,
        creds=creds,
        name=name,
        collection=collection,
    )

    return password
