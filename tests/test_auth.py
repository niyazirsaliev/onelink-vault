"""
tests/test_auth.py — unit tests for app.auth module.

Tests cover:
  - Adding callers with and without bw credentials
  - write_ok defaulting to False
  - Backward-compatible simple string token schema
  - caller_bw_creds returning None for callers without bw creds
  - caller_bw_creds returning a full dict for callers with bw creds
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from unittest.mock import patch

import pytest

# We need to patch CALLERS_FILE_PATH before importing the module under test
# so we use a temp file per test via a fixture.


@pytest.fixture()
def callers_file(tmp_path):
    """Provide a temporary callers.json path, resetting auth module cache between tests."""
    fpath = str(tmp_path / "callers.json")

    with patch("app.auth.CALLERS_FILE_PATH", fpath):
        # Reset module-level cache
        import app.auth as auth_mod
        auth_mod._cached_data = {}
        auth_mod._cached_mtime = -1.0
        yield fpath, auth_mod

        # Cleanup after test
        auth_mod._cached_data = {}
        auth_mod._cached_mtime = -1.0


# ---------------------------------------------------------------------------
# test_add_caller_basic
# ---------------------------------------------------------------------------

def test_add_caller_basic(callers_file):
    fpath, auth_mod = callers_file

    auth_mod.add_caller(bot_name="alpha", token="tok-alpha")

    with open(fpath) as f:
        data = json.load(f)

    assert "alpha" in data
    entry = data["alpha"]
    assert entry["token"] == "tok-alpha"
    assert entry["write_ok"] is False


# ---------------------------------------------------------------------------
# test_add_caller_with_bw_creds
# ---------------------------------------------------------------------------

def test_add_caller_with_bw_creds(callers_file):
    fpath, auth_mod = callers_file

    auth_mod.add_caller(
        bot_name="beta",
        token="tok-beta",
        write_ok=True,
        bw_clientid="client-id-123",
        bw_clientsecret="secret-xyz",
        bw_password="vault-pass-456",
    )

    with open(fpath) as f:
        data = json.load(f)

    entry = data["beta"]
    assert entry["token"] == "tok-beta"
    assert entry["write_ok"] is True
    assert entry["bw_clientid"] == "client-id-123"
    assert entry["bw_clientsecret"] == "secret-xyz"
    assert entry["bw_password"] == "vault-pass-456"


# ---------------------------------------------------------------------------
# test_write_ok_defaults_false
# ---------------------------------------------------------------------------

def test_write_ok_defaults_false(callers_file):
    fpath, auth_mod = callers_file

    auth_mod.add_caller(bot_name="gamma", token="tok-gamma")

    assert auth_mod.caller_has_write("gamma") is False


# ---------------------------------------------------------------------------
# test_backward_compat_string_token
# ---------------------------------------------------------------------------

def test_backward_compat_string_token(callers_file):
    fpath, auth_mod = callers_file

    # Write a legacy simple-string callers.json
    with open(fpath, "w") as f:
        json.dump({"legacy-bot": "simple-token-abc"}, f)

    # Invalidate cache so it reloads
    auth_mod._cached_mtime = -1.0

    # Should resolve correctly
    tokens = auth_mod.merged_tokens()
    assert "legacy-bot" in tokens
    assert tokens["legacy-bot"] == "simple-token-abc"

    # Should default to no write access
    assert auth_mod.caller_has_write("legacy-bot") is False

    # resolve_caller should work
    caller = auth_mod.resolve_caller("simple-token-abc")
    assert caller == "legacy-bot"


# ---------------------------------------------------------------------------
# test_caller_bw_creds_returns_none_for_no_creds
# ---------------------------------------------------------------------------

def test_caller_bw_creds_returns_none_for_no_creds(callers_file):
    fpath, auth_mod = callers_file

    auth_mod.add_caller(bot_name="delta", token="tok-delta")

    result = auth_mod.caller_bw_creds("delta")
    assert result is None


def test_caller_bw_creds_returns_none_for_missing_caller(callers_file):
    fpath, auth_mod = callers_file
    # Ensure file exists but does not contain the caller
    auth_mod.add_caller(bot_name="epsilon", token="tok-epsilon")

    result = auth_mod.caller_bw_creds("nonexistent-bot")
    assert result is None


def test_caller_bw_creds_returns_none_for_partial_creds(callers_file):
    """Caller with only clientid but no password → None (all three required)."""
    fpath, auth_mod = callers_file

    auth_mod.add_caller(
        bot_name="partial",
        token="tok-partial",
        bw_clientid="client-id-only",
        # bw_clientsecret and bw_password omitted → empty strings
    )

    result = auth_mod.caller_bw_creds("partial")
    assert result is None


# ---------------------------------------------------------------------------
# test_caller_bw_creds_returns_dict_for_creds
# ---------------------------------------------------------------------------

def test_caller_bw_creds_returns_dict_for_creds(callers_file):
    fpath, auth_mod = callers_file

    auth_mod.add_caller(
        bot_name="zeta",
        token="tok-zeta",
        bw_clientid="zeta-clientid",
        bw_clientsecret="zeta-secret",
        bw_password="zeta-vault-pw",
    )

    result = auth_mod.caller_bw_creds("zeta")
    assert result is not None
    assert result["bw_clientid"] == "zeta-clientid"
    assert result["bw_clientsecret"] == "zeta-secret"
    assert result["bw_password"] == "zeta-vault-pw"
    # Ensure only these three keys are present
    assert set(result.keys()) == {"bw_clientid", "bw_clientsecret", "bw_password"}


# ---------------------------------------------------------------------------
# Thread-safety smoke test
# ---------------------------------------------------------------------------

def test_concurrent_add_callers(callers_file):
    """Multiple threads adding callers simultaneously should not corrupt the file."""
    fpath, auth_mod = callers_file

    errors: list[Exception] = []

    def add(n: int):
        try:
            auth_mod.add_caller(bot_name=f"bot-{n}", token=f"tok-{n}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=add, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors during concurrent writes: {errors}"

    auth_mod._cached_mtime = -1.0
    tokens = auth_mod.merged_tokens()
    # All 20 bots should be present
    for i in range(20):
        assert f"bot-{i}" in tokens
