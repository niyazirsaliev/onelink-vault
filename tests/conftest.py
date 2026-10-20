"""All unit tests use local temporary state and explicit delegation policy."""
import pytest
from app import bw_client

@pytest.fixture(autouse=True)
def isolated_bw_home(tmp_path, monkeypatch):
    monkeypatch.setattr(bw_client, 'BW_HOME_BASE', str(tmp_path / 'bw-homes'))

@pytest.fixture
def delegation_policy(monkeypatch):
    from app import main
    monkeypatch.setattr(main, 'CROSS_VAULT_READ_CALLERS', frozenset({'operator_a', 'reader_a-hermes', 'operator_b'}))
    monkeypatch.setattr(main, 'CROSS_VAULT_WRITE_CALLERS', frozenset({'operator_a', 'operator_b'}))
