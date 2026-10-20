"""Fail-closed vault sync freshness tests; no real Bitwarden CLI is invoked."""

from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest

import app.audit as audit
import app.auth as auth
import app.bw_client as bw_client
import app.main as main
from app.tools import list as list_tool

CREDS = {"bw_clientid": "id", "bw_clientsecret": "secret", "bw_password": "password"}
CALLERS = {
    "operator_a": {"token": "tok-operator_a", "write_ok": True, **CREDS},
    "agent_a": {"token": "tok-agent_a", "write_ok": False, **CREDS},
    "agent_b": {"token": "tok-agent_b", "write_ok": False, **CREDS},
}


@pytest.fixture(autouse=True)
def reset_sync_state():
    bw_client._sync_locks.clear()
    bw_client._sync_inflight.clear()
    bw_client._session_cache.clear()


async def test_list_syncs_before_read(monkeypatch):
    calls = []

    async def fake_run(bot_name, creds, args, **kwargs):
        calls.append(args)
        if args == ["list", "items"]:
            return []
        return {}

    monkeypatch.setattr(bw_client, "_bw_run", fake_run)

    assert await bw_client.list_ciphers("bot", CREDS) == []
    assert calls == [["sync"], ["list", "items"]]


async def test_get_syncs_before_read(monkeypatch):
    calls = []

    async def fake_run(bot_name, creds, args, **kwargs):
        calls.append(args)
        if args[:2] == ["get", "item"]:
            return {"id": "item-id"}
        return {}

    monkeypatch.setattr(bw_client, "_bw_run", fake_run)

    assert await bw_client.get_cipher("bot", CREDS, cipher_id="item-id") == {"id": "item-id"}
    assert calls == [["sync"], ["get", "item", "item-id"]]


async def test_hung_sync_is_killed_and_fails_closed(monkeypatch):
    release = asyncio.Event()

    class HungProcess:
        returncode = None
        killed = False

        async def communicate(self, input=None):
            await release.wait()
            self.returncode = -9 if self.killed else 0
            return b"", b""

        def kill(self):
            self.killed = True
            release.set()

    process = HungProcess()

    async def fake_session(*args, **kwargs):
        return "session"

    async def fake_exec(*args, **kwargs):
        return process

    monkeypatch.setattr(bw_client, "BW_COMMAND_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(bw_client, "_get_session", fake_session)
    monkeypatch.setattr(bw_client.asyncio, "create_subprocess_exec", fake_exec)

    with pytest.raises(RuntimeError, match="bw sync timed out") as exc:
        await bw_client.sync_vault("bot", CREDS)
    assert process.killed is True
    assert CREDS["bw_password"] not in str(exc.value)
    assert CREDS["bw_clientsecret"] not in str(exc.value)


async def test_cancelled_subprocess_is_killed_and_reaped(monkeypatch):
    started = asyncio.Event()
    release = asyncio.Event()

    class Process:
        killed = False
        reaped = False

        async def communicate(self, input=None):
            started.set()
            await release.wait()
            self.reaped = True
            return b"", b""

        def kill(self):
            self.killed = True
            release.set()

    process = Process()
    monkeypatch.setattr(bw_client, "BW_COMMAND_TIMEOUT_SECONDS", 60)
    monkeypatch.setattr(bw_client, "BW_REAP_TIMEOUT_SECONDS", 1)

    operation = asyncio.create_task(
        bw_client._communicate(process, command="sync")
    )
    await started.wait()
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert process.killed is True
    assert process.reaped is True


async def test_sync_failure_blocks_stale_read(monkeypatch):
    calls = []

    async def fake_run(bot_name, creds, args, **kwargs):
        calls.append(args)
        if args == ["sync"]:
            raise RuntimeError("bw sync failed")
        pytest.fail("a read must not run after failed sync")

    monkeypatch.setattr(bw_client, "_bw_run", fake_run)

    with pytest.raises(RuntimeError, match="bw sync failed"):
        await bw_client.list_ciphers("bot", CREDS)
    assert calls == [["sync"]]


async def test_collection_sync_failure_blocks_list_result(monkeypatch):
    async def fake_list_ciphers(*args, **kwargs):
        return [{"id": "item", "name": "name", "type": 1, "collectionIds": ["collection"]}]

    async def failed_collections(*args, **kwargs):
        raise RuntimeError("bw sync failed")

    monkeypatch.setattr(bw_client, "list_ciphers", fake_list_ciphers)
    monkeypatch.setattr(bw_client, "list_collections", failed_collections)

    with pytest.raises(RuntimeError, match="bw sync failed"):
        await list_tool.run(caller="bot", creds=CREDS)


async def test_concurrent_reads_share_one_inflight_sync_without_deadlock(monkeypatch):
    sync_started = asyncio.Event()
    release_sync = asyncio.Event()
    calls = []

    async def fake_run(bot_name, creds, args, **kwargs):
        calls.append(args)
        if args == ["sync"]:
            sync_started.set()
            await release_sync.wait()
            return {}
        if args == ["list", "items"]:
            return []
        raise AssertionError(args)

    monkeypatch.setattr(bw_client, "_bw_run", fake_run)
    first = asyncio.create_task(bw_client.list_ciphers("bot", CREDS))
    await sync_started.wait()
    second = asyncio.create_task(bw_client.list_ciphers("bot", CREDS))
    await asyncio.sleep(0)
    release_sync.set()
    assert await asyncio.gather(first, second) == [[], []]
    assert calls.count(["sync"]) == 1
    assert calls.count(["list", "items"]) == 2


async def test_cancelling_one_waiter_does_not_cancel_shared_sync(monkeypatch):
    sync_started = asyncio.Event()
    release_sync = asyncio.Event()
    calls = []

    async def fake_run(bot_name, creds, args, **kwargs):
        calls.append(args)
        sync_started.set()
        await release_sync.wait()
        return {}

    monkeypatch.setattr(bw_client, "_bw_run", fake_run)
    first = asyncio.create_task(bw_client.sync_vault("bot", CREDS))
    await sync_started.wait()
    second = asyncio.create_task(bw_client.sync_vault("bot", CREDS))
    await asyncio.sleep(0)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    release_sync.set()
    assert await second == {"status": "synced", "forced": True}
    await asyncio.sleep(0)
    assert calls == [["sync"]]
    assert "bot" not in bw_client._sync_inflight


@pytest.fixture
def tool_env(tmp_path, monkeypatch):
    callers_file = tmp_path / "callers.json"
    callers_file.write_text(json.dumps(CALLERS))
    monkeypatch.setattr(auth, "CALLERS_FILE_PATH", str(callers_file))
    with auth._cache_lock:
        auth._cached_data = {}
        auth._cached_mtime = -1.0

    audit_db = tmp_path / "audit.db"
    monkeypatch.setattr(audit, "AUDIT_DB_PATH", str(audit_db))
    audit._conn = None
    calls = []

    async def fake_sync(bot_name, creds, force=True):
        calls.append((bot_name, creds, force))
        return {"status": "synced", "forced": force}

    monkeypatch.setattr(bw_client, "sync_vault", fake_sync)
    return calls, audit_db


def _audit_rows(db):
    with sqlite3.connect(db) as con:
        return con.execute(
            "SELECT caller, tool, status, target_caller, action FROM invocations"
        ).fetchall()


def test_vault_sync_is_registered():
    tools = asyncio.run(main.mcp.list_tools())
    assert "vault.sync" in {tool.name for tool in tools}


async def test_vault_sync_own_vault_and_audit(tool_env):
    calls, audit_db = tool_env
    auth._current_caller.set("agent_a")

    assert await main.vault_sync() == {"status": "synced", "forced": True}
    assert calls == [("agent_a", CREDS, True)]
    assert _audit_rows(audit_db) == [("agent_a", "vault.sync", "ok", None, "read")]


async def test_vault_sync_cross_vault_uses_read_gate_and_audit(tool_env, delegation_policy):
    calls, audit_db = tool_env
    auth._current_caller.set("operator_a")

    await main.vault_sync(target_caller="agent_a")
    assert calls == [("agent_a", CREDS, True)]
    assert _audit_rows(audit_db) == [("operator_a", "vault.sync", "ok", "agent_a", "read")]


async def test_vault_sync_cross_vault_denial_is_audited(tool_env):
    calls, audit_db = tool_env
    auth._current_caller.set("agent_b")

    with pytest.raises(PermissionError):
        await main.vault_sync(target_caller="agent_a")
    assert calls == []
    assert _audit_rows(audit_db) == [("agent_b", "vault.sync", "denied", "agent_a", "read")]
