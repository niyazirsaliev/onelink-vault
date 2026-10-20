"""
auth.py — caller authentication and credential management for <NAME>.

callers.json supports two schemas:
  Simple (legacy):  {"bot_name": "token_string"}
  Extended:         {"bot_name": {"token": "...", "bw_clientid": "...", "bw_clientsecret": "...", "bw_password": "...", "write_ok": false}}

The extended schema adds bw_password for vault unlock alongside the API key fields.
Callers without bw_creds can still authenticate but will get a 503 on vault operations.
"""

from __future__ import annotations

import json
import os
import threading
from contextvars import ContextVar
from typing import Optional

from app.config import CALLERS_FILE_PATH

# ---------------------------------------------------------------------------
# ContextVar — holds the resolved caller name for the current request
# ---------------------------------------------------------------------------
_current_caller: ContextVar[Optional[str]] = ContextVar("_current_caller", default=None)

# ---------------------------------------------------------------------------
# File-based cache with mtime check
# ---------------------------------------------------------------------------
_cache_lock = threading.Lock()
_cached_data: dict = {}          # name -> entry (str token or full dict)
_cached_mtime: float = -1.0


def _load_callers_locked() -> dict:
    """Load callers.json; caller must already hold _cache_lock."""
    global _cached_data, _cached_mtime

    path = CALLERS_FILE_PATH
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return {}

    if mtime == _cached_mtime:
        return _cached_data

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}  # Fail closed: never continue accepting a stale credential file.
    if not isinstance(data, dict):
        return {}

    _cached_data = data
    _cached_mtime = mtime
    return _cached_data


def _load_callers() -> dict:
    """Load callers.json, using in-memory cache if file has not changed."""
    with _cache_lock:
        return _load_callers_locked()


def _save_callers_locked(data: dict) -> None:
    """Persist callers dict to disk atomically; caller must hold _cache_lock."""
    global _cached_data, _cached_mtime

    path = CALLERS_FILE_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)

    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix=".callers-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    _cached_data = data
    _cached_mtime = os.path.getmtime(path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def merged_tokens() -> dict[str, str]:
    """Return mapping of {name -> token_string} for all callers."""
    callers = _load_callers()
    result: dict[str, str] = {}
    for name, entry in callers.items():
        if isinstance(entry, str):
            result[name] = entry
        elif isinstance(entry, dict):
            token = entry.get("token")
            if token:
                result[name] = token
    return result


def resolve_caller(token: str) -> Optional[str]:
    """
    Given a Bearer token string, return the caller name or None if unknown.
    Also sets the _current_caller ContextVar.
    """
    tokens = merged_tokens()
    for name, tok in tokens.items():
        if tok == token:
            _current_caller.set(name)
            return name
    return None


def caller_has_write(name: str) -> bool:
    """Return True if the caller is permitted to perform write operations."""
    callers = _load_callers()
    entry = callers.get(name)
    if isinstance(entry, str):
        return False  # simple tokens default to read-only
    if isinstance(entry, dict):
        return bool(entry.get("write_ok", False))
    return False


def caller_bw_creds(name: str) -> Optional[dict]:
    """
    Return bw credentials for a caller or None if not configured.

    Returns dict with keys: bw_clientid, bw_clientsecret, bw_password
    All three must be non-empty for the credentials to be considered valid.
    """
    callers = _load_callers()
    entry = callers.get(name)
    if not isinstance(entry, dict):
        return None

    clientid = entry.get("bw_clientid", "")
    clientsecret = entry.get("bw_clientsecret", "")
    password = entry.get("bw_password", "")

    if not (clientid and clientsecret and password):
        return None

    return {
        "bw_clientid": clientid,
        "bw_clientsecret": clientsecret,
        "bw_password": password,
    }


def add_caller(
    bot_name: str,
    token: str,
    write_ok: bool = False,
    bw_clientid: Optional[str] = None,
    bw_clientsecret: Optional[str] = None,
    bw_password: Optional[str] = None,
) -> None:
    """
    Add or update a caller entry in callers.json (atomic read-modify-write).
    Existing bw fields are preserved when not explicitly overridden.
    """
    with _cache_lock:
        callers = _load_callers_locked()

        existing = callers.get(bot_name, {})
        if isinstance(existing, str):
            existing = {"token": existing}

        entry: dict = {
            "token": token,
            "write_ok": write_ok,
            "bw_clientid": bw_clientid if bw_clientid is not None else existing.get("bw_clientid", ""),
            "bw_clientsecret": bw_clientsecret if bw_clientsecret is not None else existing.get("bw_clientsecret", ""),
            "bw_password": bw_password if bw_password is not None else existing.get("bw_password", ""),
        }

        callers[bot_name] = entry
        _save_callers_locked(callers)
