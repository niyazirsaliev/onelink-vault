"""
audit.py — SQLite-backed audit log for onelink-vault.

Records every tool invocation with caller identity (the authenticated actor),
tool name, item reference, outcome, and timing. For delegated cross-vault accesses
the target namespace and read|write action are also recorded. Passwords, session
keys, and secret values are NEVER logged — only item names and IDs appear.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from app.config import AUDIT_DB_PATH

_db_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    """Return (and lazily initialise) the shared SQLite connection."""
    global _conn
    if _conn is not None:
        return _conn

    with _db_lock:
        if _conn is not None:
            return _conn

        path = Path(AUDIT_DB_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invocations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            REAL    NOT NULL,
                caller        TEXT    NOT NULL,
                tool          TEXT    NOT NULL,
                item_name     TEXT,
                status        TEXT    NOT NULL,
                duration_ms   INTEGER NOT NULL,
                error         TEXT,
                target_caller TEXT,
                action        TEXT
            )
            """
        )
        # Non-destructive migration for pre-existing DBs created before the
        # cross-vault columns were added. ADD COLUMN is additive and keeps all
        # existing rows intact (new columns default to NULL).
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(invocations)")}
        if "target_caller" not in existing_cols:
            conn.execute("ALTER TABLE invocations ADD COLUMN target_caller TEXT")
        if "action" not in existing_cols:
            conn.execute("ALTER TABLE invocations ADD COLUMN action TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_invocations_ts ON invocations (ts)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_invocations_caller ON invocations (caller)"
        )
        # Index for fast cross-vault audit queries (rows where target_caller IS NOT NULL)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_invocations_target ON invocations (target_caller)"
        )
        conn.commit()
        _conn = conn
        return _conn


def _extract_item_ref(inputs: dict) -> Optional[str]:
    """
    Pull a safe, non-secret reference out of the tool inputs dict.
    Returns item name or item_id if present; never returns passwords/values.
    """
    # Prefer 'name' then 'item_id' then 'cipher_id' — these are safe identifiers
    for key in ("name", "item_id", "cipher_id", "item_name"):
        val = inputs.get(key)
        if val:
            return str(val)
    return None


def log_call(
    caller: str,
    tool: str,
    inputs: dict,
    status: str,
    duration_ms: int,
    error: Optional[str] = None,
    target_caller: Optional[str] = None,
    action: Optional[str] = None,
) -> None:
    """
    Insert one audit row.

    Parameters
    ----------
    caller        : authenticated actor (from the bearer token) — never spoofable
    tool          : fully-qualified tool name, e.g. "vault.get_password"
    inputs        : raw tool input dict — only item name/id extracted, never secrets
    status        : "ok" | "error" | "denied"
    duration_ms   : wall-clock milliseconds for the operation
    error         : optional error message (no secret values)
    target_caller : for delegated cross-vault accesses, the namespace acted upon;
                    None for ordinary own-vault calls
    action        : "read" | "write" — the operation class
    """
    item_name = _extract_item_ref(inputs)
    ts = time.time()

    conn = _get_conn()
    with _db_lock:
        conn.execute(
            """
            INSERT INTO invocations
                (ts, caller, tool, item_name, status, duration_ms, error, target_caller, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, caller, tool, item_name, status, duration_ms, error, target_caller, action),
        )
        conn.commit()


def fetch_cross_vault(limit: int = 50) -> list[dict]:
    """
    Return the most recent cross-vault audit rows (target_caller IS NOT NULL),
    newest first. Metadata only — no secret values are stored or returned.

    Intended for ops/audit review of every delegated cross-vault access.
    """
    conn = _get_conn()
    with _db_lock:
        cur = conn.execute(
            """
            SELECT ts, caller, tool, item_name, status, duration_ms, error,
                   target_caller, action
            FROM invocations
            WHERE target_caller IS NOT NULL
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
