"""Own-collection intake sink; secrets never leave the caller's Vault boundary."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

from app import auth, bw_client
from app.tools.create_item import _build_login_payload

_locks: dict[str, asyncio.Lock] = {}


def _own_collection(collections: list[dict], caller: str) -> dict:
    names = {caller, caller.removesuffix('-hermes')}
    # Runtime migrations retain the caller's original named collection.
    # Accept only its exact legacy alias, never an arbitrary non-shared folder.
    names |= {f'{name}-legacy' for name in names}
    matches = [c for c in collections if c.get('name') in names]
    if len(matches) != 1 or not matches[0].get('id') or not matches[0].get('organizationId'):
        raise RuntimeError('Own Vault collection unavailable')
    return matches[0]


def _marker(item: dict, name: str) -> str | None:
    return next((f.get('value') for f in item.get('fields', []) if f.get('name') == name), None)


def _digest(text: str, image: bytes | None) -> str:
    return hashlib.sha256(json.dumps([text, hashlib.sha256(image or b'').hexdigest()], ensure_ascii=False).encode()).hexdigest()


async def _attachment_read(caller: str, creds: dict, item_id: str, attachment_id: str) -> bytes:
    # Binary stdout, never decode/print or put plaintext in persistent files.
    session = await bw_client._get_session(caller, creds)
    home = bw_client._bw_home(caller)
    env = {**os.environ, 'HOME': home, 'BITWARDENCLI_APPDATA_DIR': home, 'BW_SESSION': session}
    proc = await asyncio.create_subprocess_exec(
        'bw', 'get', 'attachment', attachment_id, '--itemid', item_id, '--raw',
        env=env, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    data, _ = await bw_client._communicate(proc, command='attachment-read')
    if proc.returncode or len(data) > 5 * 1024 * 1024:
        raise RuntimeError('Vault attachment readback failed')
    return data


async def _attach(caller: str, creds: dict, item: dict, image: bytes, request_id: str) -> str:
    from PIL import Image
    import io
    fmt = Image.open(io.BytesIO(image)).format or ''
    suffix = {'PNG': 'png', 'JPEG': 'jpg', 'WEBP': 'webp'}.get(fmt)
    if suffix is None:
        raise ValueError('Unsupported screenshot')
    name = f'intake-{request_id}.{suffix}'
    matches = [a for a in item.get('attachments') or [] if a.get('fileName') == name]
    if len(matches) > 1:
        raise RuntimeError('Ambiguous Vault attachment')
    if matches:
        attachment_id = matches[0]['id']
    else:
        # bw requires a file path. /dev/shm is memory-backed, not persistent disk.
        # Refuse to silently use a disk-based tempfile directory.
        if not Path('/dev/shm').is_dir():
            raise RuntimeError('Memory-backed attachment staging unavailable')
        with tempfile.TemporaryDirectory(prefix='vault-intake-', dir='/dev/shm') as folder:
            path = Path(folder) / name
            # Anonymous RAM file dies even on SIGKILL; a crash can leave only a
            # dangling filename link, never a named plaintext screenshot.
            with tempfile.TemporaryFile(dir='/dev/shm') as source:
                source.write(image)
                source.flush()
                os.symlink(f'/proc/{os.getpid()}/fd/{source.fileno()}', path)
                await bw_client._bw_run(caller, creds, ['create', 'attachment', '--file', str(path), '--itemid', item['id']])
        item = await bw_client.get_cipher(caller, creds, cipher_id=item['id'])
        matches = [a for a in item.get('attachments') or [] if a.get('fileName') == name]
        if len(matches) != 1:
            raise RuntimeError('Vault attachment save not confirmed')
        attachment_id = matches[0]['id']
    downloaded = await _attachment_read(caller, creds, item['id'], attachment_id)
    if not hmac.compare_digest(hashlib.sha256(downloaded).digest(), hashlib.sha256(image).digest()):
        raise RuntimeError('Vault attachment readback mismatch')
    return attachment_id


async def save_to_vault(caller: str, request_id: str, title: str, secret_text: str,
                        image_bytes: bytes | None = None, existing_item_id: str | None = None) -> dict:
    """Idempotent create-only sink. No arbitrary target, item overwrite or shared collection."""
    if not auth.caller_has_write(caller):
        raise PermissionError('Vault write access required')
    creds = auth.caller_bw_creds(caller)
    if not creds:
        raise PermissionError('Own Vault credentials unavailable')
    if not secret_text and not image_bytes:
        raise ValueError('Nothing to save')
    # Serialize all intake writes in a caller namespace, including uncertain-write reconciliation.
    lock = _locks.setdefault(caller, asyncio.Lock())
    async with lock:
        try:
            col = _own_collection(await bw_client.list_collections(caller, creds), caller)
            payload_hash = _digest(secret_text, image_bytes)
            await bw_client.sync_vault(caller, creds)
            found = await bw_client._bw_run(caller, creds, ['list', 'items', '--search', request_id])
            if not isinstance(found, list) or any(not isinstance(item, dict) for item in found):
                raise RuntimeError('Intake reconciliation response invalid')
            matches = [item for item in found if isinstance(item, dict)
                       and _marker(item, 'intake_request') == request_id
                       and _marker(item, 'intake_caller') == caller
                       and item.get('organizationId') == col['organizationId']
                       and item.get('collectionIds') == [col['id']]]
            if len(matches) > 1:
                raise RuntimeError('Ambiguous intake record')
            if matches:
                item = matches[0]
                if _marker(item, 'intake_digest') != payload_hash:
                    raise RuntimeError('Intake content changed after a save attempt')
                if existing_item_id and existing_item_id != item['id']:
                    raise RuntimeError('Intake record mismatch')
            elif existing_item_id:
                raise RuntimeError('Previous intake record unavailable')
            else:
                payload = _build_login_payload(
                    name=f'{title} [intake:{request_id}]', username=None, password=secret_text,
                    url=None, notes='Owner-confirmed secure intake. Screenshot attached when provided.',
                    collection_id=col['id'], organization_id=col['organizationId'],
                    custom_fields=[{'name': 'intake_request', 'value': request_id, 'type': 0},
                                   {'name': 'intake_caller', 'value': caller, 'type': 0},
                                   {'name': 'intake_digest', 'value': payload_hash, 'type': 1}],
                )
                item_id = await bw_client.create_cipher(caller, creds, payload)
                item = await bw_client.get_cipher(caller, creds, cipher_id=item_id)
            # Independent post-sync readback, including scope, before acknowledging completion.
            item = await bw_client.get_cipher(caller, creds, cipher_id=item['id'])
            if (item.get('organizationId') != col['organizationId']
                    or item.get('collectionIds') != [col['id']]
                    or _marker(item, 'intake_request') != request_id
                    or _marker(item, 'intake_caller') != caller
                    or _marker(item, 'intake_digest') != payload_hash
                    or not hmac.compare_digest((item.get('login') or {}).get('password', '').encode(), secret_text.encode())):
                raise RuntimeError('Vault save readback mismatch')
            result = {'item_id': item['id']}
            if image_bytes:
                result['attachment_id'] = await _attach(caller, creds, item, image_bytes, request_id)
            return result
        except (PermissionError, ValueError):
            raise
        except Exception:
            # CLI/remote errors may contain submitted content; expose only a fixed diagnostic.
            raise RuntimeError('Vault save could not be confirmed; retry the same submission') from None
