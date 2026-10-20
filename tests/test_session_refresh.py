"""Concurrent auth failures must cause one re-login, and a failed login backs off instead of hammering Vaultwarden."""

from __future__ import annotations

import asyncio

import pytest

import app.bw_client as bw_client

CREDS = {"bw_clientid": "id", "bw_clientsecret": "secret", "bw_password": "password"}


@pytest.fixture(autouse=True)
def reset():
    bw_client._session_cache.clear()
    bw_client._login_blocked_until.clear()
    bw_client._session_locks.clear()


async def test_concurrent_stale_sessions_login_once(monkeypatch):
    logins = []

    async def fake_login(creds, home, *, force_fresh=False):
        logins.append(force_fresh)
        await asyncio.sleep(0.01)
        return f"key-{len(logins)}"

    monkeypatch.setattr(bw_client, "_login_and_unlock", fake_login)
    monkeypatch.setattr(bw_client, "_bw_home", lambda bot: "/nonexistent")
    first = await bw_client._get_session("bot", CREDS)
    keys = await asyncio.gather(*(bw_client._get_session("bot", CREDS, stale=first) for _ in range(5)))
    assert keys == ["key-2"] * 5
    assert logins == [False, True]


async def test_failed_login_backs_off_then_recovers(monkeypatch):
    calls = []

    async def failing(creds, home, *, force_fresh=False):
        calls.append(force_fresh)
        raise RuntimeError("bw login failed (rc=1): 429 Too Many Requests")

    monkeypatch.setattr(bw_client, "_login_and_unlock", failing)
    monkeypatch.setattr(bw_client, "_bw_home", lambda bot: "/nonexistent")
    with pytest.raises(RuntimeError, match="login failed"):
        await bw_client._get_session("bot", CREDS)
    with pytest.raises(RuntimeError, match="backing off"):
        await bw_client._get_session("bot", CREDS)
    assert calls == [False]

    async def ok(creds, home, *, force_fresh=False):
        return "fresh"

    bw_client._login_blocked_until["bot"] = 0
    monkeypatch.setattr(bw_client, "_login_and_unlock", ok)
    assert await bw_client._get_session("bot", CREDS) == "fresh"
