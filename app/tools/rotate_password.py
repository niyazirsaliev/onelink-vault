"""
tools/rotate_password.py — generate a new strong password and update the vault item.

Uses secrets.token_urlsafe for cryptographically-strong generation.
Returns the new password string so the caller can store/deliver it.
The new password is NOT written to the audit log.
"""

from __future__ import annotations

from typing import Optional

from app import bw_client


async def run(
    item_id: str,
    length: int = 32,
    caller: Optional[str] = None,
    creds: Optional[dict] = None,
) -> str:
    """
    Rotate the password for a vault item.

    Parameters
    ----------
    item_id : vault item UUID (required)
    length  : desired password length in characters (default 32, range 16-128)
    caller  : bot_name for bw session routing
    creds   : bw credentials dict

    Returns
    -------
    str — the newly generated password

    Raises
    ------
    ValueError  if item_id missing or no creds
    RuntimeError on bw CLI errors
    """
    if not creds:
        raise ValueError("<NAME> requires bw credentials for this caller")

    if not caller:
        raise ValueError("caller name is required for bw session routing")

    if not item_id:
        raise ValueError("'item_id' is required")

    length = max(16, min(128, int(length)))

    new_password = await bw_client.rotate_password(
        bot_name=caller,
        creds=creds,
        cipher_id=item_id,
        length=length,
    )

    return new_password
