"""
bw_client.py — async wrapper around the `bw` CLI for onelink-vault.

Design decisions:
- Each caller bot gets its own HOME directory so bw stores per-user config/data
  without cross-contamination.
- Sessions are cached in-memory with a TTL slightly shorter than Vaultwarden's
  access_token lifetime (7200 s → we use 7000 s).
- A per-bot asyncio.Lock prevents thundering-herd re-logins under concurrent load.
- Every vault read is preceded by a successful `bw sync`; an in-flight sync is
  shared by concurrent reads for the same bot, never cached by a stale TTL.
- On session invalidity (detected from stderr or return code) the cache is cleared
  and the operation retried once with a fresh session.
- NOTHING secret is logged at any point.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import secrets
import time
from typing import Optional

from app.config import BW_HOME_BASE, VW_URL

# ---------------------------------------------------------------------------
# Session cache
# ---------------------------------------------------------------------------
# Structure: { bot_name: {"session_key": str, "expires_at": float} }
_session_cache: dict[str, dict] = {}
_session_locks: dict[str, asyncio.Lock] = {}
_sync_locks: dict[str, asyncio.Lock] = {}
_sync_inflight: dict[str, asyncio.Task] = {}

SESSION_TTL = 3000  # seconds — kept safely under Vaultwarden's access-token
# lifetime so we proactively refresh before the underlying token dies (avoids
# the "valid cache key but dead access token" window that produced intermittent
# vault_read_fail noise on long-running cron callers).
def _positive_timeout_from_env(name: str, default: str) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{name} must be a finite positive number")
    return value


BW_COMMAND_TIMEOUT_SECONDS = _positive_timeout_from_env(
    "BW_COMMAND_TIMEOUT_SECONDS", "30"
)
BW_REAP_TIMEOUT_SECONDS = _positive_timeout_from_env("BW_REAP_TIMEOUT_SECONDS", "5")


def _get_lock(bot_name: str) -> asyncio.Lock:
    if bot_name not in _session_locks:
        _session_locks[bot_name] = asyncio.Lock()
    return _session_locks[bot_name]


def _get_sync_lock(bot_name: str) -> asyncio.Lock:
    """Return the per-caller lock that protects only sync task creation."""
    if bot_name not in _sync_locks:
        _sync_locks[bot_name] = asyncio.Lock()
    return _sync_locks[bot_name]


def _scrub(text: str, creds: dict) -> str:
    """
    Redact any bw credential value from an error string before it is raised,
    logged, or returned to a caller.

    The bw CLI can echo an argv-supplied password back in its own stderr (e.g.
    when a password begins with '-', bw reports it as an "unknown option"), so
    error text from bw is NOT trusted to be secret-free. This guarantees secrets
    never reach exception messages, the audit log, or tool error responses.
    """
    if not text or not creds:
        return text
    for key in ("bw_password", "bw_clientsecret", "bw_clientid"):
        val = creds.get(key)
        if val and val in text:
            text = text.replace(val, "***REDACTED***")
    return text


async def _kill_and_reap(proc, communication_task: asyncio.Task) -> None:
    """Kill a bw child and finish/cancel its communicate task within a bound."""
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(
            asyncio.shield(communication_task), timeout=BW_REAP_TIMEOUT_SECONDS
        )
    except (TimeoutError, asyncio.CancelledError, Exception):
        if not communication_task.done():
            communication_task.cancel()
        await asyncio.gather(communication_task, return_exceptions=True)


async def _communicate(proc, *, command: str, input_data: bytes | None = None):
    """Bound every bw subprocess and kill/reap it on timeout or cancellation.

    ``command`` is a fixed non-secret operation label (for example ``sync`` or
    ``unlock``), never argv or user-controlled input. This keeps errors useful
    without exposing passwords or encoded vault payloads.
    """
    communication_task = asyncio.create_task(proc.communicate(input=input_data))
    try:
        return await asyncio.wait_for(
            asyncio.shield(communication_task),
            timeout=BW_COMMAND_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        await _kill_and_reap(proc, communication_task)
        raise RuntimeError(
            f"bw {command} timed out after {BW_COMMAND_TIMEOUT_SECONDS:g}s"
        ) from None
    except asyncio.CancelledError:
        await _kill_and_reap(proc, communication_task)
        raise


def _bw_home(bot_name: str) -> str:
    import re
    if not isinstance(bot_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", bot_name):
        raise ValueError("Invalid caller name")
    home = os.path.join(BW_HOME_BASE, bot_name)
    os.makedirs(home, exist_ok=True)
    return home


# ---------------------------------------------------------------------------
# Login / unlock
# ---------------------------------------------------------------------------

async def _login_and_unlock(creds: dict, bw_home: str, *, force_fresh: bool = False) -> str:
    """
    Perform full bw login + unlock sequence and return the session key.

    Steps:
      0. (force_fresh) bw logout — clear any stale login/access-token state
      1. bw config server <VW_URL>
      2. bw login --apikey          (uses BW_CLIENTID / BW_CLIENTSECRET env vars)
      3. bw unlock <password> --raw → session key

    force_fresh is used on the post-auth-error retry path: a stale access token
    can leave bw "logged in" with a dead token, so `bw login --apikey` no-ops and
    the failure repeats. Logging out first guarantees a brand-new access token.
    """
    env = {
        **os.environ,
        "HOME": bw_home,
        "BW_CLIENTID": creds["bw_clientid"],
        "BW_CLIENTSECRET": creds["bw_clientsecret"],
        # Never expose these in logs — subprocess inherits but we don't print them
        "BITWARDENCLI_APPDATA_DIR": bw_home,
    }

    # 0. On a forced refresh, log out first so the next login mints a fresh token
    if force_fresh:
        proc = await asyncio.create_subprocess_exec(
            "bw", "logout",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await _communicate(proc, command="logout")
        # Non-fatal if not logged in; continue regardless

    # 1. Configure server
    proc = await asyncio.create_subprocess_exec(
        "bw", "config", "server", VW_URL,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await _communicate(proc, command="config")
    # Non-fatal if already configured; continue regardless

    # 2. Login via API key (idempotent — bw ignores if already logged in)
    proc = await asyncio.create_subprocess_exec(
        "bw", "login", "--apikey",
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await _communicate(proc, command="login")
    if proc.returncode != 0:
        err_text = _scrub(stderr.decode(errors="replace").strip(), creds)
        if "already logged in" not in err_text.lower():
            # A failed login (e.g. Vaultwarden 429) must surface as itself, not as
            # a confusing "not logged in" from the unlock that follows.
            raise RuntimeError(f"bw login failed (rc={proc.returncode}): {err_text}")

    # Native CLI records a 24h migration cooldown when an older server lacks
    # key-id backfill. Retry unlock once so its own supported cooldown takes
    # effect; never modify crypto state or log out/re-authenticate for this.
    for attempt in range(2):
        proc = await asyncio.create_subprocess_exec(
            "bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw",
            env={**env, "BW_PASSWORD": creds["bw_password"]},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await _communicate(proc, command="unlock")
        if proc.returncode == 0:
            break
        err_text = _scrub(stderr.decode(errors="replace").strip(), creds)
        if attempt == 0 and all(marker in err_text for marker in ("KeyIdBackfillError", "Api", "404")):
            continue
        raise RuntimeError(f"bw unlock failed (rc={proc.returncode}): {err_text}")

    session_key = stdout.decode().strip()
    if not session_key:
        raise RuntimeError("bw unlock returned empty session key")

    return session_key


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

LOGIN_BACKOFF_SECONDS = 60  # Vaultwarden rate-limits identity logins; retrying sooner only extends the 429
_login_blocked_until: dict[str, float] = {}


async def _get_session(bot_name: str, creds: dict, *, stale: str | None = None) -> str:
    """Return a valid BW_SESSION key, logging in at most once per bot at a time.

    ``stale`` is the session key that just failed with an auth error. If another
    waiter already replaced it while we queued on the lock, reuse the new key
    instead of logging out and in again (concurrent retries used to log the bot
    out repeatedly until Vaultwarden answered 429 and left it logged out).
    """
    lock = _get_lock(bot_name)
    async with lock:
        cached = _session_cache.get(bot_name)
        if cached and cached["expires_at"] > time.monotonic() and cached["session_key"] != stale:
            return cached["session_key"]

        wait = _login_blocked_until.get(bot_name, 0) - time.monotonic()
        if wait > 0:
            raise RuntimeError(f"bw login backing off after a failed login; retry in {math.ceil(wait)}s")

        bw_home = _bw_home(bot_name)
        try:
            session_key = await _login_and_unlock(creds, bw_home, force_fresh=stale is not None)
        except Exception:
            _session_cache.pop(bot_name, None)
            _login_blocked_until[bot_name] = time.monotonic() + LOGIN_BACKOFF_SECONDS
            raise
        _login_blocked_until.pop(bot_name, None)
        _session_cache[bot_name] = {
            "session_key": session_key,
            "expires_at": time.monotonic() + SESSION_TTL,
        }
        return session_key


# ---------------------------------------------------------------------------
# Core subprocess runner
# ---------------------------------------------------------------------------

def _is_auth_error(returncode: int, stderr: str) -> bool:
    if returncode == 0:
        return False
    lowered = stderr.lower()
    return any(phrase in lowered for phrase in (
        "session key is invalid",
        "you are not logged in",
        "vault is locked",
        "not logged in",
        "invalid session",
        # access-token / sync expiry phrases (caused intermittent cron failures)
        "access token",
        "token has expired",
        "expired",
        "unauthorized",
        "401",
        "master password",
        "you are not logged in.",
    ))


async def _bw_run(
    bot_name: str,
    creds: dict,
    args: list[str],
    input_data: Optional[str] = None,
    *,
    _retry: bool = True,
    _stale: str | None = None,
) -> "dict | list":
    """
    Run a bw CLI command and return parsed JSON output.

    On session invalidity: clear cache and retry once with a full fresh re-login
    (logout + login + unlock) so a dead access token cannot persist.
    input_data is passed to stdin (used for create/edit via bw encode).
    """
    session_key = await _get_session(bot_name, creds, stale=_stale)
    bw_home = _bw_home(bot_name)

    env = {
        **os.environ,
        "HOME": bw_home,
        "BW_SESSION": session_key,
        "BITWARDENCLI_APPDATA_DIR": bw_home,
    }

    stdin_bytes = input_data.encode() if input_data else None

    proc = await asyncio.create_subprocess_exec(
        "bw", *args,
        env=env,
        stdin=asyncio.subprocess.PIPE if stdin_bytes else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await _communicate(
        proc, command=str(args[0]), input_data=stdin_bytes
    )

    stderr_text = stderr.decode(errors="replace").strip()

    if _is_auth_error(proc.returncode, stderr_text):
        if _retry:
            return await _bw_run(
                bot_name, creds, args, input_data,
                _retry=False, _stale=session_key,
            )
        raise RuntimeError("bw authentication failed after session refresh")

    if proc.returncode != 0:
        # Sanitize: never echo back any input_data (may contain passwords/secrets),
        # and redact any credential value bw may have echoed into its own stderr.
        raise RuntimeError(
            f"bw {args[0]} failed (rc={proc.returncode}): {_scrub(stderr_text, creds)}"
        )

    raw = stdout.decode().strip()
    if not raw:
        return {}

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Some bw commands return plain text (e.g. bw unlock --raw); caller handles
        return raw  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# bw encode helper (for create/edit)
# ---------------------------------------------------------------------------

async def _bw_encode(bot_name: str, creds: dict, json_str: str) -> str:
    """Run `echo <json> | bw encode` and return the Base64 encoded string."""
    session_key = await _get_session(bot_name, creds)
    bw_home = _bw_home(bot_name)

    env = {
        **os.environ,
        "HOME": bw_home,
        "BW_SESSION": session_key,
        "BITWARDENCLI_APPDATA_DIR": bw_home,
    }

    proc = await asyncio.create_subprocess_exec(
        "bw", "encode",
        env=env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await _communicate(
        proc, command="encode", input_data=json_str.encode()
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"bw encode failed: {_scrub(stderr.decode(errors='replace').strip(), creds)}"
        )

    return stdout.decode().strip()


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def _sync_task_done(bot_name: str, task: asyncio.Task) -> None:
    """Identity-safe cleanup for a per-caller shared sync task."""
    if _sync_inflight.get(bot_name) is task:
        _sync_inflight.pop(bot_name, None)
    # Retrieve an unobserved exception when every waiter was cancelled. Existing
    # waiters still receive the same task result/exception normally.
    if not task.cancelled():
        try:
            task.exception()
        except Exception:
            pass


async def sync_vault(bot_name: str, creds: dict, force: bool = True) -> dict:
    """Synchronize a caller's local Bitwarden cache and return safe metadata.

    There is deliberately no freshness TTL: every independent read must contact
    the server so a password created just before that read is observable. Only
    concurrent callers sharing the same in-flight sync are deduplicated. The
    sync lock is separate from the session lock, so `_bw_run` can safely perform
    its normal authentication refresh/retry while a sync is in progress.
    Cancelling one waiter does not cancel the shared sync for other readers.
    """
    lock = _get_sync_lock(bot_name)
    async with lock:
        task = _sync_inflight.get(bot_name)
        if task is None or task.done():
            task = asyncio.create_task(_bw_run(bot_name, creds, ["sync"]))
            _sync_inflight[bot_name] = task
            task.add_done_callback(
                lambda done, name=bot_name: _sync_task_done(name, done)
            )

    await asyncio.shield(task)
    return {"status": "synced", "forced": bool(force)}


async def list_collections(bot_name: str, creds: dict) -> list[dict]:
    """List collections only after a successful, fail-closed vault sync."""
    await sync_vault(bot_name, creds)
    collections = await _bw_run(bot_name, creds, ["list", "collections"])
    return collections if isinstance(collections, list) else []

async def list_ciphers(
    bot_name: str,
    creds: dict,
    search: Optional[str] = None,
    collection: Optional[str] = None,
) -> list[dict]:
    """
    List vault items, optionally filtered by search term and/or collection name.

    Returns list of {id, name, type, collectionIds}.
    Collection filtering is done client-side by matching collection names.
    """
    await sync_vault(bot_name, creds)

    args = ["list", "items"]
    if search:
        args += ["--search", search]

    items = await _bw_run(bot_name, creds, args)
    if not isinstance(items, list):
        return []

    # Normalise to safe summary fields only
    result = []
    for item in items:
        result.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "type": item.get("type"),
            "collectionIds": item.get("collectionIds", []),
        })

    if not collection:
        return result

    # Filter by collection name — a collection read is also sync-protected.
    # Sync failures intentionally propagate: returning unfiltered cached data
    # would violate the fail-closed freshness contract.
    cols_raw = await list_collections(bot_name, creds)

    col_ids = {
        col["id"]
        for col in cols_raw
        if col.get("name", "").lower() == collection.lower()
    }
    if not col_ids:
        return []

    return [r for r in result if any(cid in col_ids for cid in r["collectionIds"])]


async def get_cipher(
    bot_name: str,
    creds: dict,
    name: Optional[str] = None,
    cipher_id: Optional[str] = None,
) -> dict:
    """
    Retrieve a single cipher by name or ID.
    Returns the full cipher dict from bw.
    """
    await sync_vault(bot_name, creds)
    if cipher_id:
        return await _bw_run(bot_name, creds, ["get", "item", cipher_id])

    if name:
        return await _bw_run(bot_name, creds, ["get", "item", name])

    raise ValueError("Either name or cipher_id must be provided")


async def get_password(
    bot_name: str,
    creds: dict,
    name: str,
    collection: Optional[str] = None,
) -> str:
    """
    Return the password field for the named vault item.
    Raises ValueError if the item has no login password.
    """
    if collection:
        # Search within collection to disambiguate
        items = await list_ciphers(bot_name, creds, search=name, collection=collection)
        if not items:
            raise ValueError(f"Item '{name}' not found in collection '{collection}'")
        cipher = await get_cipher(bot_name, creds, cipher_id=items[0]["id"])
    else:
        cipher = await get_cipher(bot_name, creds, name=name)

    password = (cipher.get("login") or {}).get("password")
    if password is None:
        raise ValueError(f"Item '{name}' has no login password field")

    return password


async def create_cipher(bot_name: str, creds: dict, payload: dict) -> str:
    """
    Create a new vault item from a payload dict.
    Returns the new item's ID string.
    """
    payload_json = json.dumps(payload)
    encoded = await _bw_encode(bot_name, creds, payload_json)

    result = await _bw_run(bot_name, creds, ["create", "item"], input_data=encoded)

    if not isinstance(result, dict):
        raise RuntimeError("bw create item returned unexpected output")

    item_id = result.get("id")
    if not item_id:
        raise RuntimeError("bw create item did not return an item ID")

    return item_id


async def update_cipher(
    bot_name: str,
    creds: dict,
    cipher_id: str,
    updates: dict,
) -> bool:
    """
    Merge `updates` into an existing cipher and persist via bw edit item.
    Returns True on success.
    """
    existing = await get_cipher(bot_name, creds, cipher_id=cipher_id)

    if not isinstance(existing, dict):
        raise RuntimeError(f"Could not fetch item {cipher_id} for update")

    # Deep-merge updates into existing — top-level keys only for safety
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(existing.get(key), dict):
            existing[key] = {**existing[key], **value}
        else:
            existing[key] = value

    payload_json = json.dumps(existing)
    encoded = await _bw_encode(bot_name, creds, payload_json)

    await _bw_run(bot_name, creds, ["edit", "item", cipher_id], input_data=encoded)
    return True


async def rotate_password(
    bot_name: str,
    creds: dict,
    cipher_id: str,
    length: int = 32,
) -> str:
    """
    Generate a cryptographically-strong password, update the vault item, and
    return the new password.

    length must be between 16 and 128.
    """
    length = max(16, min(128, length))
    # Generate length bytes of URL-safe Base64, then trim to exact length
    new_password = secrets.token_urlsafe((length * 3 + 3) // 4)[:length]

    await update_cipher(
        bot_name,
        creds,
        cipher_id,
        updates={"login": {"password": new_password}},
    )

    return new_password
