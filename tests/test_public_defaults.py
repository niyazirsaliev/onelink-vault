import json
import os
import pytest
from app import auth, bw_client, main

@pytest.mark.parametrize('name', ['../escape', '/absolute', 'agent/child', '', 'a' * 65])
def test_caller_home_rejects_traversal(name):
    with pytest.raises(ValueError, match='Invalid caller name'):
        bw_client._bw_home(name)


def test_caller_store_private(tmp_path, monkeypatch):
    path = tmp_path / 'callers.json'
    monkeypatch.setattr(auth, 'CALLERS_FILE_PATH', str(path))
    monkeypatch.setattr(auth, '_cached_mtime', -1)
    auth.add_caller('agent-a', 'fixture-token')
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_corrupt_store_denies_cached_token(tmp_path, monkeypatch):
    path = tmp_path / 'callers.json'
    monkeypatch.setattr(auth, 'CALLERS_FILE_PATH', str(path))
    monkeypatch.setattr(auth, '_cached_mtime', -1)
    auth.add_caller('agent-a', 'fixture-token')
    path.write_text('{')
    monkeypatch.setattr(auth, '_cached_mtime', -1)
    assert auth.resolve_caller('fixture-token') is None


def test_public_defaults_disable_cross_vault():
    # Policy fixtures patch individual tests, not the public application defaults.
    assert not main.CROSS_VAULT_READ_CALLERS
    assert not main.CROSS_VAULT_WRITE_CALLERS
