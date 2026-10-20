"""
Security tests for the operator_a-gated cross-vault superuser capability.

These tests prove the GATING — they never touch a real Vaultwarden. The bw_client
layer is fully mocked, and each mock records the (bot_name, creds) it was routed
with so we can assert that:
  * operator_a + target_caller=X routes to X's namespace using X's OWN creds (R and W),
  * a non-operator_a caller supplying target_caller is REJECTED and never reaches bw,
  * identity is taken from the authenticated-caller ContextVar (set from the bearer
    token), never from a tool argument,
  * operator_a without target_caller is unchanged (own vault),
  * every cross-vault access is audited (metadata only) and is queryable.
"""

from __future__ import annotations

import inspect
import json
import sqlite3

import pytest

import app.auth as auth
import app.audit as audit
import app.bw_client as bw_client
import app.main as main


# Fake fleet. Creds are dummy strings — bw_client is mocked, so they are never used
# to talk to a real vault; we only assert WHICH creds get routed where.
CALLERS = {
    "operator_a": {"token": "tok-operator_a", "write_ok": True,
               "bw_clientid": "id-operator_a", "bw_clientsecret": "sec-operator_a", "bw_password": "pw-operator_a"},
    "agent_a": {"token": "tok-agent_a", "write_ok": False,
              "bw_clientid": "id-agent_a", "bw_clientsecret": "sec-agent_a", "bw_password": "pw-agent_a"},
    "agent_b": {"token": "tok-agent_b", "write_ok": False,
              "bw_clientid": "id-agent_b", "bw_clientsecret": "sec-agent_b", "bw_password": "pw-agent_b"},
    "reader_a-hermes": {"token": "tok-reader_a", "write_ok": True,
                      "bw_clientid": "id-reader_a", "bw_clientsecret": "sec-reader_a", "bw_password": "pw-reader_a"},
    "retired_operator": {"token": "tok-vk", "write_ok": True,
                     "bw_clientid": "id-vk", "bw_clientsecret": "sec-vk", "bw_password": "pw-vk"},
    "operator_b": {"token": "tok-operator_b", "write_ok": True,
              "bw_clientid": "id-operator_b", "bw_clientsecret": "sec-operator_b", "bw_password": "pw-operator_b"},
}

# A canary secret returned by the mocked read path; must NEVER appear in audit rows.
CANARY = "CANARY-SECRET-VALUE"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "CROSS_VAULT_READ_CALLERS", frozenset({"operator_a", "operator_a-hermes", "reader_a-hermes", "operator_b"}))
    monkeypatch.setattr(main, "CROSS_VAULT_WRITE_CALLERS", frozenset({"operator_a", "operator_a-hermes", "operator_b"}))
    # ---- callers.json (controlled fleet) ----
    cf = tmp_path / "callers.json"
    cf.write_text(json.dumps(CALLERS))
    monkeypatch.setattr(auth, "CALLERS_FILE_PATH", str(cf))
    with auth._cache_lock:
        auth._cached_data = {}
        auth._cached_mtime = -1.0

    # ---- fresh audit DB (exercises the full CREATE TABLE incl. new columns) ----
    adb = tmp_path / "audit.db"
    monkeypatch.setattr(audit, "AUDIT_DB_PATH", str(adb))
    audit._conn = None

    # ---- mock the bw layer; record routing (bot_name + creds) ----
    calls: list[tuple] = []

    async def fake_get_password(bot_name, creds, name, collection=None):
        calls.append(("get_password", bot_name, creds, name))
        return CANARY

    async def fake_get_cipher(bot_name, creds, name=None, cipher_id=None):
        calls.append(("get_cipher", bot_name, creds, name or cipher_id))
        return {"id": cipher_id or "id1", "name": name or "item", "type": 1,
                "login": {"username": "u", "password": CANARY, "uris": []},
                "notes": None, "fields": []}

    async def fake_list(bot_name, creds, search=None, collection=None):
        calls.append(("list", bot_name, creds, search))
        return [{"id": "id1", "name": "item", "type": 1, "collectionIds": []}]

    async def fake_create(bot_name, creds, payload):
        calls.append(("create", bot_name, creds, payload.get("name")))
        return "newid"

    async def fake_update(bot_name, creds, cipher_id, updates):
        calls.append(("update", bot_name, creds, cipher_id))
        return True

    async def fake_rotate(bot_name, creds, cipher_id, length=32):
        calls.append(("rotate", bot_name, creds, cipher_id))
        return CANARY

    monkeypatch.setattr(bw_client, "get_password", fake_get_password)
    monkeypatch.setattr(bw_client, "get_cipher", fake_get_cipher)
    monkeypatch.setattr(bw_client, "list_ciphers", fake_list)
    async def fake_collections(bot_name, creds):
        return []

    monkeypatch.setattr(bw_client, "list_collections", fake_collections)
    monkeypatch.setattr(bw_client, "create_cipher", fake_create)
    monkeypatch.setattr(bw_client, "update_cipher", fake_update)
    monkeypatch.setattr(bw_client, "rotate_password", fake_rotate)

    return {"calls": calls, "audit_db": str(adb)}


def _set_caller(name):
    """Simulate what BearerAuthMiddleware does after validating the bearer token."""
    auth._current_caller.set(name)


def _rows(db):
    con = sqlite3.connect(db)
    try:
        cur = con.execute(
            "SELECT caller, tool, item_name, status, target_caller, action, error FROM invocations"
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 1. operator_a + target_caller -> READ another vault, routed with the target's creds
# ---------------------------------------------------------------------------

async def test_operator_a_cross_vault_read_ok_and_audited(env):
    _set_caller("operator_a")
    pw = await main.vault_get_password(name="github", target_caller="agent_a")
    assert pw == CANARY

    op = [c for c in env["calls"] if c[0] == "get_password"][-1]
    assert op[1] == "agent_a"                       # routed to TARGET namespace
    assert op[2]["bw_clientid"] == "id-agent_a"     # using TARGET's creds, not operator_a's

    xv = audit.fetch_cross_vault()
    match = [r for r in xv if r["tool"] == "vault.get_password"]
    assert match and match[0]["caller"] == "operator_a"
    assert match[0]["target_caller"] == "agent_a"
    assert match[0]["action"] == "read"
    assert match[0]["status"] == "ok"
    assert match[0]["item_name"] == "github"


# ---------------------------------------------------------------------------
# 2. operator_a + target_caller -> WRITE another vault (update_field & create_item)
# ---------------------------------------------------------------------------

async def test_operator_a_cross_vault_write_ok_and_audited(env):
    _set_caller("operator_a")
    res = await main.vault_update_field(item_id="abc", field="password", value="x", target_caller="agent_a")
    assert res == {"ok": True}

    op = [c for c in env["calls"] if c[0] == "update"][-1]
    assert op[1] == "agent_a" and op[2]["bw_clientid"] == "id-agent_a"

    xv = audit.fetch_cross_vault()
    w = [r for r in xv if r["tool"] == "vault.update_field"]
    assert w and w[0]["target_caller"] == "agent_a" and w[0]["action"] == "write" and w[0]["status"] == "ok"


async def test_operator_a_cross_vault_create_ok(env):
    _set_caller("operator_a")
    nid = await main.vault_create_item(name="svc-acct", password="p", target_caller="agent_b")
    assert nid == "newid"
    op = [c for c in env["calls"] if c[0] == "create"][-1]
    assert op[1] == "agent_b" and op[2]["bw_clientid"] == "id-agent_b"
    xv = audit.fetch_cross_vault()
    assert any(r["tool"] == "vault.create_item" and r["target_caller"] == "agent_b"
               and r["action"] == "write" and r["status"] == "ok" for r in xv)


# ---------------------------------------------------------------------------
# 3. non-operator_a + target_caller -> REJECTED (read AND write); bw never reached
# ---------------------------------------------------------------------------

async def test_non_operator_a_cross_vault_read_rejected(env):
    _set_caller("agent_b")
    with pytest.raises(PermissionError):
        await main.vault_get_password(name="github", target_caller="agent_a")

    # bw_client was NEVER invoked against agent_a (stayed isolated)
    assert not any(c[0] == "get_password" and c[1] == "agent_a" for c in env["calls"])
    assert not any(c[1] == "agent_a" for c in env["calls"])

    # the denied attempt is audited with the true actor + attempted target
    xv = audit.fetch_cross_vault()
    d = [r for r in xv if r["caller"] == "agent_b" and r["target_caller"] == "agent_a"]
    assert d and d[0]["status"] == "denied"


async def test_non_operator_a_cross_vault_write_rejected(env):
    _set_caller("agent_a")
    with pytest.raises(PermissionError):
        await main.vault_update_field(item_id="abc", field="password", value="x", target_caller="agent_b")
    assert not any(c[0] == "update" for c in env["calls"])
    xv = audit.fetch_cross_vault()
    assert any(r["caller"] == "agent_a" and r["target_caller"] == "agent_b" and r["status"] == "denied" for r in xv)


# ---------------------------------------------------------------------------
# 4. Identity comes from the TOKEN (ContextVar), never from a request/body field
# ---------------------------------------------------------------------------

def test_no_tool_param_can_set_identity():
    # The only client-controllable inputs are item/query fields + target_caller.
    # There is NO 'caller'/'actor'/'as_caller'/'identity' parameter on any tool.
    forbidden = {"caller", "actor", "as_caller", "identity", "principal", "bot_name"}
    for fn in (main.vault_get_password, main.vault_get_item, main.vault_list,
               main.vault_create_item, main.vault_update_field, main.vault_rotate_password):
        params = set(inspect.signature(fn).parameters)
        assert params.isdisjoint(forbidden), f"{fn.__name__} exposes an identity param"
        assert "target_caller" in params


async def test_claiming_operator_a_via_target_caller_does_not_grant_powers(env):
    # A non-operator_a caller cannot "become" operator_a by naming operator_a in a field.
    _set_caller("agent_b")
    with pytest.raises(PermissionError):
        await main.vault_get_password(name="x", target_caller="operator_a")
    # And the resolver always derives the actor from the ContextVar alone.
    _set_caller("agent_a")
    actor, eff, creds, xv = main._resolve_target(None)
    assert actor == "agent_a" and eff == "agent_a" and xv is None
    _set_caller("operator_a")
    actor, eff, creds, xv = main._resolve_target("agent_a")
    assert actor == "operator_a" and eff == "agent_a" and xv == "agent_a"
    assert creds["bw_clientid"] == "id-agent_a"


async def test_unauthenticated_request_denied(env):
    _set_caller(None)
    with pytest.raises(PermissionError):
        await main.vault_get_password(name="x")


# ---------------------------------------------------------------------------
# 5. operator_a WITHOUT target_caller -> own vault, byte-identical behavior
# ---------------------------------------------------------------------------

async def test_operator_a_own_vault_unchanged(env):
    _set_caller("operator_a")
    pw = await main.vault_get_password(name="own-item")
    assert pw == CANARY
    op = [c for c in env["calls"] if c[0] == "get_password"][-1]
    assert op[1] == "operator_a" and op[2]["bw_clientid"] == "id-operator_a"

    # No cross-vault audit row produced for an own-vault call.
    assert not any(r["item_name"] == "own-item" for r in audit.fetch_cross_vault())

    # A normal audit row exists with target_caller NULL and action 'read'.
    rows = [r for r in _rows(env["audit_db"]) if r["item_name"] == "own-item"]
    assert rows == [{
        "caller": "operator_a", "tool": "vault.get_password", "item_name": "own-item",
        "status": "ok", "target_caller": None, "action": "read", "error": None,
    }]


async def test_operator_a_target_self_is_not_cross_vault(env):
    _set_caller("operator_a")
    await main.vault_get_password(name="self-named", target_caller="operator_a")
    # target == actor -> own vault, NOT a cross-vault access
    assert not any(r["item_name"] == "self-named" for r in audit.fetch_cross_vault())


# ---------------------------------------------------------------------------
# 6. Ordinary callers keep their own-vault access + read/write gating unchanged
# ---------------------------------------------------------------------------

async def test_ordinary_caller_own_vault_and_write_gate(env):
    _set_caller("agent_a")
    pw = await main.vault_get_password(name="x")
    assert pw == CANARY
    op = [c for c in env["calls"] if c[0] == "get_password"][-1]
    assert op[1] == "agent_a" and op[2]["bw_clientid"] == "id-agent_a"
    # agent_a has write_ok=False -> own-vault write still denied (unchanged)
    with pytest.raises(PermissionError):
        await main.vault_create_item(name="new")
    assert not any(c[0] == "create" for c in env["calls"])


# ---------------------------------------------------------------------------
# 7. Audit hygiene + queryability
# ---------------------------------------------------------------------------

async def test_audit_never_contains_secret_values(env):
    _set_caller("operator_a")
    await main.vault_get_password(name="github", target_caller="agent_a")
    await main.vault_get_item(name="github", target_caller="agent_a")
    await main.vault_rotate_password(item_id="abc", target_caller="agent_a")
    blob = json.dumps(_rows(env["audit_db"]))
    assert CANARY not in blob
    assert "pw-agent_a" not in blob and "sec-agent_a" not in blob and "id-agent_a" not in blob


async def test_fetch_cross_vault_is_queryable(env):
    _set_caller("operator_a")
    await main.vault_list(target_caller="agent_a")
    await main.vault_get_password(name="k", target_caller="agent_b")
    xv = audit.fetch_cross_vault(limit=10)
    assert len(xv) == 2
    # newest first, metadata-only keys
    assert set(xv[0].keys()) == {
        "ts", "caller", "tool", "item_name", "status", "duration_ms",
        "error", "target_caller", "action",
    }
    assert {r["target_caller"] for r in xv} == {"agent_a", "agent_b"}


# ---------------------------------------------------------------------------
# 8. Non-destructive migration of a pre-existing (old-schema) audit DB
# ---------------------------------------------------------------------------

def test_bw_error_scrub_redacts_credentials():
    creds = {"bw_clientid": "id-XYZ", "bw_clientsecret": "sec-XYZ", "bw_password": "-pw-with-dash"}
    # bw can echo an argv password into its own stderr (e.g. when it starts with '-')
    leaky = "error: unknown option '-pw-with-dash'; clientid id-XYZ secret sec-XYZ"
    out = bw_client._scrub(leaky, creds)
    assert "-pw-with-dash" not in out
    assert "id-XYZ" not in out and "sec-XYZ" not in out
    assert "***REDACTED***" in out
    # no creds / empty text are safe no-ops
    assert bw_client._scrub("", creds) == ""
    assert bw_client._scrub("plain text", {}) == "plain text"


def test_audit_db_migration_is_additive(tmp_path, monkeypatch):
    db = tmp_path / "old.db"
    con = sqlite3.connect(str(db))
    con.execute(
        """CREATE TABLE invocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, caller TEXT NOT NULL,
            tool TEXT NOT NULL, item_name TEXT, status TEXT NOT NULL,
            duration_ms INTEGER NOT NULL, error TEXT)"""
    )
    con.execute(
        "INSERT INTO invocations (ts,caller,tool,item_name,status,duration_ms,error) VALUES (?,?,?,?,?,?,?)",
        (1.0, "agent_a", "vault.list", None, "ok", 5, None),
    )
    con.commit()
    con.close()

    monkeypatch.setattr(audit, "AUDIT_DB_PATH", str(db))
    audit._conn = None

    conn = audit._get_conn()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(invocations)")}
    assert "target_caller" in cols and "action" in cols
    # pre-existing row preserved
    assert conn.execute("SELECT count(*) FROM invocations").fetchone()[0] == 1
    # and new cross-vault writes work against the migrated DB
    audit.log_call("operator_a", "vault.get_password", {"name": "x"}, "ok", 3, None,
                   target_caller="agent_a", action="read")
    row = conn.execute(
        "SELECT caller, target_caller, action FROM invocations WHERE caller='operator_a'"
    ).fetchone()
    assert row == ("operator_a", "agent_a", "read")


# ---------------------------------------------------------------------------
# 9. Read-only cross-vault tier (reader_a-hermes): read allowed, write denied,
#    own-vault write unaffected, other superusers' write unaffected.
# ---------------------------------------------------------------------------

async def test_reader_a_cross_vault_read_ok_and_audited(env):
    _set_caller("reader_a-hermes")
    pw = await main.vault_get_password(name="github", target_caller="agent_a")
    assert pw == CANARY

    op = [c for c in env["calls"] if c[0] == "get_password"][-1]
    assert op[1] == "agent_a"                    # routed to TARGET namespace
    assert op[2]["bw_clientid"] == "id-agent_a"  # using TARGET's creds

    xv = audit.fetch_cross_vault()
    match = [r for r in xv if r["tool"] == "vault.get_password"]
    assert match and match[0]["caller"] == "reader_a-hermes"
    assert match[0]["target_caller"] == "agent_a"
    assert match[0]["action"] == "read"
    assert match[0]["status"] == "ok"


async def test_reader_a_cross_vault_list_and_get_item_ok(env):
    _set_caller("reader_a-hermes")
    items = await main.vault_list(target_caller="agent_b")
    assert items and items[0]["id"] == "id1"
    assert any(c[0] == "list" and c[1] == "agent_b" for c in env["calls"])

    item = await main.vault_get_item(name="github", target_caller="agent_b")
    assert item["login"]["password"] == CANARY
    assert any(c[0] == "get_cipher" and c[1] == "agent_b" for c in env["calls"])


async def test_reader_a_cross_vault_create_denied(env):
    _set_caller("reader_a-hermes")
    with pytest.raises(PermissionError):
        await main.vault_create_item(name="svc-acct", password="p", target_caller="agent_b")
    # bw_client never reached for the target — no mutation attempted
    assert not any(c[0] == "create" for c in env["calls"])
    xv = audit.fetch_cross_vault()
    d = [r for r in xv if r["caller"] == "reader_a-hermes" and r["tool"] == "vault.create_item"]
    assert d and d[0]["target_caller"] == "agent_b" and d[0]["status"] == "denied"


async def test_reader_a_cross_vault_update_field_denied(env):
    _set_caller("reader_a-hermes")
    with pytest.raises(PermissionError):
        await main.vault_update_field(item_id="abc", field="password", value="x", target_caller="agent_b")
    assert not any(c[0] == "update" for c in env["calls"])
    xv = audit.fetch_cross_vault()
    d = [r for r in xv if r["caller"] == "reader_a-hermes" and r["tool"] == "vault.update_field"]
    assert d and d[0]["target_caller"] == "agent_b" and d[0]["status"] == "denied"


async def test_reader_a_cross_vault_rotate_denied(env):
    _set_caller("reader_a-hermes")
    with pytest.raises(PermissionError):
        await main.vault_rotate_password(item_id="abc", target_caller="agent_b")
    assert not any(c[0] == "rotate" for c in env["calls"])
    xv = audit.fetch_cross_vault()
    d = [r for r in xv if r["caller"] == "reader_a-hermes" and r["tool"] == "vault.rotate_password"]
    assert d and d[0]["target_caller"] == "agent_b" and d[0]["status"] == "denied"


async def test_reader_a_own_vault_write_unaffected(env):
    # xvault_target is None for own-vault calls, so the new read/write-tier
    # gate is a no-op here; write_ok alone governs, exactly as before.
    _set_caller("reader_a-hermes")
    res = await main.vault_update_field(item_id="own-item", field="username", value="u")
    assert res == {"ok": True}
    op = [c for c in env["calls"] if c[0] == "update"][-1]
    assert op[1] == "reader_a-hermes" and op[2]["bw_clientid"] == "id-reader_a"
    # own-vault write is NOT a cross-vault audit row
    assert not any(r["item_name"] == "own-item" for r in audit.fetch_cross_vault())


async def test_operator_a_and_operator_b_cross_vault_write(env):
    # Full (read+write) superusers; retired_operator was retired 2026-09-24.
    assert "retired_operator" not in main.CROSS_VAULT_READ_CALLERS
    for caller in ("operator_a", "operator_b"):
        _set_caller(caller)
        res = await main.vault_update_field(item_id="abc", field="password", value="x", target_caller="agent_b")
        assert res == {"ok": True}
        op = [c for c in env["calls"] if c[0] == "update"][-1]
        assert op[1] == "agent_b" and op[2]["bw_clientid"] == "id-agent_b"


def test_write_tier_is_subset_of_read_tier(delegation_policy):
    assert main.CROSS_VAULT_WRITE_CALLERS <= main.CROSS_VAULT_READ_CALLERS
    assert "reader_a-hermes" in main.CROSS_VAULT_READ_CALLERS
    assert "reader_a-hermes" not in main.CROSS_VAULT_WRITE_CALLERS
