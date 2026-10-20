"""Regression checks for the real Vault sink (remote I/O mocked)."""
import hashlib
from unittest.mock import AsyncMock

import pytest

from app import intake_vault as sink


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(sink.auth, 'caller_has_write', lambda name: name == 'operator_b')
    monkeypatch.setattr(sink.auth, 'caller_bw_creds', lambda name: {'fixture': True})
    col = {'id': 'own', 'organizationId': 'org', 'name': 'operator_b'}
    monkeypatch.setattr(sink.bw_client, 'list_collections', AsyncMock(return_value=[col]))
    monkeypatch.setattr(sink.bw_client, 'sync_vault', AsyncMock(return_value={}))
    items = []
    async def run(*args, **kwargs):
        return items.copy()
    monkeypatch.setattr(sink.bw_client, '_bw_run', run)
    async def create(caller, creds, payload):
        items.append({**payload, 'id': 'new-id'})
        return 'new-id'
    monkeypatch.setattr(sink.bw_client, 'create_cipher', AsyncMock(side_effect=create))
    async def get(caller, creds, cipher_id):
        return next(i for i in items if i['id'] == cipher_id)
    monkeypatch.setattr(sink.bw_client, 'get_cipher', AsyncMock(side_effect=get))
    sink._locks.clear()
    return items


@pytest.mark.asyncio
async def test_create_readback_and_retry_is_one_item(setup):
    result = await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'not-a-real-secret')
    retry = await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'not-a-real-secret')
    assert result == retry == {'item_id': 'new-id'}
    assert len(setup) == 1
    assert setup[0]['collectionIds'] == ['own']
    assert sink.bw_client.get_cipher.await_count >= 3


@pytest.mark.asyncio
async def test_changed_retry_rejected(setup):
    await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'first')
    with pytest.raises(RuntimeError, match='could not be confirmed'):
        await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'second')
    assert len(setup) == 1


@pytest.mark.asyncio
async def test_permission_rechecked(setup):
    with pytest.raises(PermissionError):
        await sink.save_to_vault('other', 'request1', 'Fixture', 'value')
    assert not setup


def test_shared_and_other_collections_never_selected():
    with pytest.raises(RuntimeError):
        sink._own_collection([{'id': 'shared', 'name': 'shared', 'organizationId': 'org'}], 'operator_b')
    with pytest.raises(RuntimeError):
        sink._own_collection([{'id': 'peer', 'name': 'reader_a', 'organizationId': 'org'}], 'operator_b')


@pytest.mark.parametrize('caller', ['operator_a', 'operator_a-hermes'])
def test_own_legacy_collection_is_recognized(caller):
    legacy = {'id': 'own', 'name': 'operator_a-legacy', 'organizationId': 'org'}
    shared = {'id': 'shared', 'name': 'shared', 'organizationId': 'org'}
    assert sink._own_collection([legacy, shared], caller) == legacy


@pytest.mark.parametrize('names', [
    ['reader_a-legacy', 'shared'],
    ['operator_a', 'operator_a-legacy'],
    ['operator_a-legacy', 'operator_a-legacy'],
    ['operator_a-legacy-other', 'shared'],
])
def test_legacy_collection_does_not_widen_or_guess_scope(names):
    cols = [{'id': str(i), 'name': n, 'organizationId': 'org'} for i, n in enumerate(names)]
    with pytest.raises(RuntimeError):
        sink._own_collection(cols, 'operator_a')


@pytest.mark.asyncio
async def test_readback_mismatch_is_not_success(setup, monkeypatch):
    monkeypatch.setattr(sink.bw_client, 'get_cipher', AsyncMock(return_value={
        'id': 'new-id', 'login': {'password': 'wrong'}, 'organizationId': 'org', 'collectionIds': ['own']}))
    with pytest.raises(RuntimeError, match='could not be confirmed'):
        await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value')


@pytest.mark.asyncio
async def test_screenshot_must_finish_attachment_readback(setup, monkeypatch):
    attach = AsyncMock(side_effect=RuntimeError('private content must not escape'))
    monkeypatch.setattr(sink, '_attach', attach)
    with pytest.raises(RuntimeError, match='could not be confirmed') as error:
        await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value', b'fixture-image')
    assert 'private content' not in str(error.value)
    attach.assert_awaited_once()
    assert len(setup) == 1
    attach.side_effect = None
    attach.return_value = 'attachment-id'
    result = await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value', b'fixture-image')
    assert result == {'item_id': 'new-id', 'attachment_id': 'attachment-id'}
    assert len(setup) == 1


@pytest.mark.asyncio
async def test_uncertain_create_reconciles_marker(setup, monkeypatch):
    original = sink.bw_client.create_cipher.side_effect
    async def uncertain(*args):
        await original(*args)
        raise RuntimeError('response lost')
    monkeypatch.setattr(sink.bw_client, 'create_cipher', AsyncMock(side_effect=uncertain))
    with pytest.raises(RuntimeError):
        await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value')
    assert len(setup) == 1
    result = await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value')
    assert result == {'item_id': 'new-id'} and len(setup) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid', [{}, None, 'bad response', [None]])
async def test_invalid_reconciliation_never_creates(setup, monkeypatch, invalid):
    monkeypatch.setattr(sink.bw_client, '_bw_run', AsyncMock(return_value=invalid))
    with pytest.raises(RuntimeError):
        await sink.save_to_vault('operator_b', 'request1', 'Fixture', 'value')
    assert not setup
    sink.bw_client.create_cipher.assert_not_awaited()


@pytest.mark.asyncio
async def test_attachment_uses_anonymous_memory_and_verified_readback(setup, monkeypatch):
    import io
    from pathlib import Path
    from PIL import Image
    buf = io.BytesIO()
    Image.new('RGB', (8,8)).save(buf, 'PNG')
    image = buf.getvalue()
    seen = []
    async def upload(caller, creds, args):
        path = Path(args[args.index('--file') + 1])
        assert path.is_symlink()
        assert path.read_bytes() == image
        seen.append(path)
        return {}
    monkeypatch.setattr(sink.bw_client, '_bw_run', upload)
    monkeypatch.setattr(sink.bw_client, 'get_cipher', AsyncMock(return_value={
        'id':'item', 'attachments':[{'id':'attached', 'fileName':'intake-request1.png'}]}))
    monkeypatch.setattr(sink, '_attachment_read', AsyncMock(return_value=image))
    assert await sink._attach('operator_b', {}, {'id':'item'}, image, 'request1') == 'attached'
    assert len(seen) == 1 and not seen[0].exists()
