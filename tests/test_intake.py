import asyncio
import base64
import io
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
import pytest
from PIL import Image
from starlette.applications import Starlette

from app import auth


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from app.intake import Intake
    allowed = {'reader_a': True, 'bob': True, 'reader': False}
    monkeypatch.setattr(auth, 'caller_has_write', lambda name: allowed.get(name, False))
    monkeypatch.setattr(auth, 'caller_bw_creds', lambda name: {'configured': True} if name in allowed else None)
    token = auth._current_caller.set('reader_a')
    calls = []
    async def save(*args):
        calls.append(args)
        return {'item_id': 'item-1', 'attachment_id': 'attachment-1' if args[4] else None}
    service = Intake(save, state_dir=tmp_path, public_base_url='https://vault.example')
    app = Starlette()
    service.register_routes(app)
    yield service, app, calls, allowed
    auth._current_caller.reset(token)


async def browser(setup):
    service, app, _, _ = setup
    created = await service.intake_create('Sample')
    cap = urlsplit(created['url']).fragment
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example', headers={'Origin': 'https://vault.example'})
    session = await client.post('/intake/session', json={'capability': cap})
    assert session.status_code == 200, session.text
    common = {'capability': cap, 'csrf': session.json()['csrf']}
    return created, client, common


@asynccontextmanager
async def closing_client(client):
    try:
        yield client
    finally:
        await client.aclose()


async def settled(c, common):
    for _ in range(100):
        r = await c.post('/intake/status', json=common)
        if r.json()['status'] != 'saving':
            return r
        await asyncio.sleep(0)
    raise AssertionError('save did not finish')


def png():
    out = io.BytesIO()
    Image.new('RGB', (8, 8), 'white').save(out, 'PNG')
    return out.getvalue()


@pytest.mark.asyncio
async def test_create_binding_idempotence_permissions(setup):
    s, _, _, allowed = setup
    a = await s.intake_create('Title', 60, 'same')
    assert a == await s.intake_create('Title', 60, 'same')
    assert '?' not in a['url'] and '/intake/#' in a['url']
    assert 'url' not in await s.intake_status(a['request_id'])
    auth._current_caller.set('bob')
    with pytest.raises(PermissionError):
        await s.intake_status(a['request_id'])
    auth._current_caller.set('reader')
    with pytest.raises(PermissionError):
        await s.intake_create('Denied')
    auth._current_caller.set(None)
    with pytest.raises(PermissionError):
        await s.intake_create('Denied')
    auth._current_caller.set('reader_a')
    with pytest.raises(ValueError):
        await s.intake_create('Title', 59)


@pytest.mark.asyncio
async def test_review_confirm_encrypted_purge(setup, monkeypatch):
    s, _, calls, _ = setup
    async def ocr(data):
        return 'OCR-SENSITIVE-EXAMPLE'
    monkeypatch.setattr(s, 'ocr', ocr)
    created, c, common = await browser(setup)
    async with closing_client(c):
        r = await c.post('/intake/submit', json={**common, 'text': 'UNIQUE-SECRET-TEXT', 'image': base64.b64encode(png()).decode()})
        assert r.status_code == 200
        assert 'OCR-SENSITIVE-EXAMPLE' in r.json()['suggestion']
        assert not calls
        for path in s.state_dir.iterdir():
            if path.is_file():
                assert b'UNIQUE-SECRET-TEXT' not in path.read_bytes()
                assert b'OCR-SENSITIVE-EXAMPLE' not in path.read_bytes()
        r = await c.post('/intake/confirm', json={**common, 'text': 'CORRECTED-SECRET'})
        assert r.json()['status'] == 'saving'
        assert (await settled(c, common)).json()['status'] == 'saved'
        assert calls[0][0] == 'reader_a' and calls[0][3] == 'CORRECTED-SECRET'
        assert calls[0][4] == png()
        assert 'CORRECTED' not in json.dumps(await s.intake_status(created['request_id']))
        with s.db() as db:
            row = db.execute('SELECT * FROM requests').fetchone()
            assert row['payload'] is None
        assert os.stat(s.state_dir).st_mode & 0o777 == 0o700
        assert os.stat(s.state_dir / 'state.sqlite3').st_mode & 0o777 == 0o600
        assert os.stat(s.state_dir / 'key').st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_concurrent_confirm_and_failed_retry(setup):
    s, _, calls, _ = setup
    created, c, common = await browser(setup)
    entered, release = asyncio.Event(), asyncio.Event()
    async def failing(*args):
        calls.append(args)
        entered.set()
        await release.wait()
        raise RuntimeError('PRIVATE ERROR')
    s.save_to_vault = failing
    async with closing_client(c):
        await c.post('/intake/submit', json={**common, 'text': 'abc'})
        result = await c.post('/intake/confirm', json={**common, 'text': 'abc'})
        assert result.json()['status'] == 'saving'
        await asyncio.wait_for(entered.wait(), 1)
        replay = await c.post('/intake/confirm', json={**common, 'text': 'abc'})
        assert replay.json()['status'] == 'saving'
        assert len(calls) == 1
        release.set()
        result = await settled(c, common)
        assert result.json()['status'] == 'failed' and 'PRIVATE' not in result.text
        assert len(calls) == 1
        assert (await c.post('/intake/submit', json={**common, 'text': 'different'})).status_code == 409
        assert (await c.post('/intake/confirm', json={**common, 'text': 'different'})).status_code == 409
        async def success(*args):
            calls.append(args)
            return {'item_id': 'retry-item'}
        s.save_to_vault = success
        assert (await c.post('/intake/confirm', json={**common, 'text': 'abc'})).json()['status'] == 'saving'
        assert (await settled(c, common)).json()['status'] == 'saved'
        assert (await c.post('/intake/confirm', json={**common, 'text': 'abc'})).json()['status'] == 'saved'
        assert len(calls) == 2


@pytest.mark.asyncio
async def test_origin_csrf_size_content_and_revocation(setup):
    s, _, calls, allowed = setup
    _, c, common = await browser(setup)
    async with closing_client(c):
        assert (await c.post('/intake/submit', json={**common, 'text': 'x'}, headers={'Origin': 'https://evil.example'})).status_code == 403
        assert (await c.post('/intake/submit', json={**common, 'csrf': 'bad', 'text': 'x'})).status_code == 403
        assert (await c.post('/intake/submit', content='{}', headers={'Content-Type': 'text/plain'})).status_code == 415
        for image in (b'<svg></svg>', b'not image', png()[:30], png()[:-1], png()[:-4]):
            assert (await c.post('/intake/submit', json={**common, 'image': base64.b64encode(image).decode()})).status_code == 400
        assert (await c.post('/intake/submit', json={**common, 'text': 'x' * 70000})).status_code == 400
        assert (await c.post('/intake/submit', content=b'x' * (8 * 1024 * 1024 + 1), headers={'Content-Type': 'application/json'})).status_code == 413
        await c.post('/intake/submit', json={**common, 'text': 'x'})
        allowed['reader_a'] = False
        assert (await c.post('/intake/confirm', json={**common, 'text': 'x'})).status_code == 403
        assert not calls


@pytest.mark.asyncio
async def test_expiry_restart_and_saving_recovery(setup):
    from app.intake import Intake
    s, _, _, _ = setup
    created = await s.intake_create('Expiry', 60)
    with s.db() as db:
        db.execute('UPDATE requests SET expires=0 WHERE id=?', (created['request_id'],))
    assert (await s.intake_status(created['request_id']))['status'] == 'expired'
    created = await s.intake_create('Recovery')
    with s.db() as db:
        db.execute("UPDATE requests SET status='saving', attempted=1 WHERE id=?", (created['request_id'],))
    restarted = Intake(s.save_to_vault, state_dir=s.state_dir, public_base_url=s.public_base_url)
    assert (await restarted.intake_status(created['request_id']))['status'] == 'failed'


@pytest.mark.asyncio
async def test_html_security_and_no_autosave(setup):
    _, app, _, _ = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example') as c:
        r = await c.get('/intake/')
        assert r.status_code == 200
        assert 'Save to vault' in r.text and 'location.hash' in r.text
        assert 'innerHTML' not in r.text
        assert r.headers['cache-control'] == 'no-store'
        assert r.headers['x-frame-options'] == 'DENY'
        assert 'default-src' in r.headers['content-security-policy']

@pytest.mark.asyncio
async def test_expiry_does_not_interrupt_acknowledged_save(setup):
    s, _, calls, _ = setup
    created, c, common = await browser(setup)
    release = asyncio.Event()
    async def slow(*args):
        calls.append(args)
        await release.wait()
        return {'item_id': 'slow-item'}
    s.save_to_vault = slow
    async with closing_client(c):
        await c.post('/intake/submit', json={**common, 'text': 'text'})
        assert (await c.post('/intake/confirm', json={**common, 'text': 'text'})).json()['status'] == 'saving'
        with s.db() as db:
            db.execute('UPDATE requests SET expires=0 WHERE id=?', (created['request_id'],))
        assert (await c.post('/intake/status', json=common)).json()['status'] == 'saving'
        assert (await c.post('/intake/confirm', json={**common, 'text': 'text'})).json()['status'] == 'saving'
        release.set()
        assert (await settled(c, common)).json()['status'] == 'saved'
        assert len(calls) == 1


@pytest.mark.asyncio
async def test_text_only_and_screenshot_only(setup, monkeypatch):
    s, _, calls, _ = setup
    async def ocr(raw):
        return ''  # a screenshot may contain no recognizable text
    monkeypatch.setattr(s, 'ocr', ocr)
    _, c, common = await browser(setup)
    async with closing_client(c):
        response = await c.post('/intake/submit', json={**common, 'image': base64.b64encode(png()).decode()})
        assert response.json()['suggestion'] == ''
        assert (await c.post('/intake/confirm', json={**common, 'text': ''})).json()['status'] == 'saving'
        assert (await settled(c, common)).json()['status'] == 'saved'
        assert calls[0][4] == png()


@pytest.mark.asyncio
async def test_cookie_flags_session_isolation_and_capability(setup):
    s, app, _, _ = setup
    _, c, common = await browser(setup)
    async with closing_client(c):
        assert (await c.post('/intake/status', json={**common, 'capability': '0' * 64})).status_code == 403
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example', headers={'Origin': 'https://vault.example'}) as stranger:
            assert (await stranger.post('/intake/status', json=common)).status_code == 403
        r = await c.post('/intake/session', json={'capability': common['capability']})
        cookie = r.headers['set-cookie'].lower()
        assert 'secure' in cookie and 'httponly' in cookie and 'samesite=strict' in cookie
        assert (await c.post('/intake/status', json=common)).status_code == 403  # old CSRF invalid
        assert (await c.post('/intake/status', json={**common, 'csrf': r.json()['csrf']}, headers={'Origin': ''})).status_code == 403


@pytest.mark.asyncio
async def test_animated_and_oversized_images_rejected(setup):
    from app.intake import MAX_IMAGE
    _, c, common = await browser(setup)
    a, b = Image.new('RGB', (8, 8), 'red'), Image.new('RGB', (8, 8), 'blue')
    animated = io.BytesIO()
    a.save(animated, 'PNG', save_all=True, append_images=[b])
    huge = io.BytesIO()
    Image.new('1', (5001, 4000)).save(huge, 'PNG')
    async with closing_client(c):
        for raw in (animated.getvalue(), huge.getvalue(), b'x' * (MAX_IMAGE + 1)):
            r = await c.post('/intake/submit', json={**common, 'image': base64.b64encode(raw).decode()})
            assert r.status_code == 400


@pytest.mark.asyncio
async def test_capacity_and_rate_limits(setup):
    s, app, _, _ = setup
    for i in range(5):
        await s.intake_create(str(i))
    with pytest.raises(ValueError):
        await s.intake_create('six')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example', headers={'Origin': 'https://vault.example'}) as c:
        statuses = [(await c.post('/intake/submit', json={'capability': 'invalid'})).status_code for _ in range(13)]
        assert statuses[-1] == 429


@pytest.mark.asyncio
async def test_restart_preserves_idempotent_url_and_review(setup):
    from app.intake import Intake
    s, _, _, _ = setup
    original = await s.intake_create('Persisted', idempotency_key='restart-key')
    restarted = Intake(s.save_to_vault, state_dir=s.state_dir, public_base_url=s.public_base_url)
    assert await restarted.intake_create('Persisted', idempotency_key='restart-key') == original


@pytest.mark.asyncio
async def test_real_local_ocr_smoke(setup):
    import shutil
    from PIL import ImageDraw, ImageFont
    if not shutil.which('tesseract'):
        pytest.skip('local tesseract not installed')
    s, _, _, _ = setup
    im = Image.new('RGB', (900, 160), 'white')
    draw = ImageDraw.Draw(im)
    draw.text((25, 30), 'LOCAL INTAKE 12345', fill='black', font=ImageFont.load_default(size=55))
    out = io.BytesIO()
    im.save(out, 'PNG')
    text = await s.ocr(out.getvalue())
    assert '12345' in text and 'LOCAL' in text


@pytest.mark.asyncio
async def test_ocr_output_is_bounded_and_timeout_safe(setup, monkeypatch):
    from app.intake import MAX_TEXT, Rejected
    s, _, _, _ = setup
    class FakeProc:
        def __init__(self, chunks):
            self.returncode = None
            self.chunks = chunks
            self.stdin = self
            self.stdout = self
        def write(self, data):
            pass
        async def drain(self):
            pass
        def close(self):
            pass
        async def read(self, n):
            return self.chunks.pop(0) if self.chunks else b''
        async def wait(self):
            self.returncode = 0
        def kill(self):
            self.returncode = -9
    processes = []
    async def launch(*args, **kwargs):
        proc = FakeProc([b'eng\n']) if '--list-langs' in args else FakeProc([b'x' * 1000] * (MAX_TEXT // 1000 + 2))
        processes.append(proc)
        return proc
    monkeypatch.setattr('app.intake.shutil.which', lambda _: '/usr/bin/tesseract')
    monkeypatch.setattr('app.intake.asyncio.create_subprocess_exec', launch)
    with pytest.raises(Rejected):
        await s.ocr(png())
    assert processes[-1].returncode is not None


@pytest.mark.asyncio
async def test_mcp_catalog_is_own_vault_only(setup):
    from fastmcp import FastMCP
    service, _, _, _ = setup
    mcp = FastMCP('test-intake')
    service.register_tools(mcp)
    tools = await mcp.list_tools()
    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == {'vault.intake_create', 'vault.intake_status'}
    for tool in tools:
        assert 'target_caller' not in json.dumps(tool.parameters)


@pytest.mark.asyncio
async def test_supported_image_formats_and_missing_credentials(setup, monkeypatch):
    from app.intake import Intake
    service, _, _, _ = setup
    for fmt in ('PNG', 'JPEG', 'WEBP'):
        buf = io.BytesIO()
        Image.new('RGB', (8, 8)).save(buf, fmt)
        raw = buf.getvalue()
        assert Intake.image(base64.b64encode(raw).decode()) == raw
    monkeypatch.setattr(auth, 'caller_bw_creds', lambda _: None)
    with pytest.raises(PermissionError):
        await service.intake_create('no credentials')


@pytest.mark.asyncio
async def test_ocr_concurrency_bound(setup, monkeypatch):
    from app.intake import Rejected
    service, _, _, _ = setup
    monkeypatch.setattr('app.intake.shutil.which', lambda _: '/usr/bin/tesseract')
    await service.ocr_slots.acquire()
    await service.ocr_slots.acquire()
    try:
        with pytest.raises(Rejected) as exc:
            await service.ocr(png())
        assert exc.value.status == 429
    finally:
        service.ocr_slots.release()
        service.ocr_slots.release()


@pytest.mark.asyncio
async def test_idle_maintenance_erases_expired_payload_without_requests(setup):
    service, _, _, _ = setup
    made = await service.intake_create('Expired')
    with service.db() as db:
        db.execute('UPDATE requests SET expires=0,payload=? WHERE id=?', (service.encrypt({'text':'fixture'}), made['request_id']))
    task = asyncio.create_task(service.maintain(interval=0.01))
    try:
        await asyncio.sleep(0.02)
        with service.db() as db:
            row = db.execute('SELECT status,payload FROM requests WHERE id=?', (made['request_id'],)).fetchone()
            assert row['status'] == 'expired' and row['payload'] is None
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


