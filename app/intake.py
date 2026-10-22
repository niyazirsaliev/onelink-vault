"""Own-vault capability intake, deliberately independent of MCP transport.

Integration: instance = register(mcp, starlette_app, save_to_vault=callback).
Alternatively instantiate Intake(callback) and call register_tools/register_routes.
Only exempt /intake/ and /intake/{session,submit,confirm,status} from bearer auth.
Requires Pillow, cryptography, and local tesseract (optional until OCR is used).
One Intake instance per state directory / process deployment (startup recovery
assumes the previous worker is stopped). Do not run multiple workers against it.

Callback signature: async (caller, request_id, title, secret_text, image_bytes,
existing_item_id) -> {item_id: str, attachment_id?: str}. It MUST durably read
back writes and be idempotent by (caller, request_id), INCLUDING recovery after
an ambiguous failure. No success is reported before it returns verified refs.
Callback exceptions are never logged or returned. A failed attempt freezes the
content for retry until the original link expiry. Active saves never expire;
expired pending data is erased. Metadata lasts seven days.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import time
import warnings
from contextlib import contextmanager, asynccontextmanager
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from PIL import Image, ImageFile
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from app import auth

MAX_IMAGE = 5 * 1024 * 1024
MAX_BODY = 8 * 1024 * 1024
MAX_TEXT = 65536
RETENTION = 7 * 86400
COOKIE = '__Secure-vault-intake'


class Rejected(Exception):
    def __init__(self, status=400):
        self.status = status


class Intake:
    def __init__(self, save_to_vault, *, state_dir=None, public_base_url=None):
        self.save_to_vault = save_to_vault
        self.public_base_url = (public_base_url or os.environ.get('INTAKE_PUBLIC_BASE_URL', '')).rstrip('/')
        u = urlsplit(self.public_base_url)
        if u.scheme != 'https' or not u.netloc or u.path or u.query or u.fragment or u.username or u.password:
            raise ValueError('INTAKE_PUBLIC_BASE_URL must be a fixed HTTPS origin')
        self.state_dir = Path(state_dir or os.environ.get('INTAKE_STATE_DIR', '/var/lib/vault-gateway/intake'))
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        keypath = self.state_dir / 'key'
        try:
            fd = os.open(keypath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(Fernet.generate_key())
                f.flush()
                os.fsync(f.fileno())
            directory_fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        os.chmod(keypath, 0o600)
        self.key = keypath.read_bytes()
        self.fernet = Fernet(self.key)
        self.dbpath = self.state_dir / 'state.sqlite3'
        fd = os.open(self.dbpath, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.dbpath, 0o600)
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY, caller TEXT NOT NULL, title BLOB NOT NULL,
                idem TEXT, caphash TEXT UNIQUE NOT NULL, created REAL NOT NULL,
                expires REAL NOT NULL, status TEXT NOT NULL, payload BLOB,
                attempted INTEGER NOT NULL DEFAULT 0, item_id TEXT, attachment_id TEXT,
                session TEXT, csrf TEXT, UNIQUE(caller, idem))''')
            db.execute("UPDATE requests SET status='failed' WHERE status='saving'")
        self.cleanup()
        self.ocr_slots = asyncio.Semaphore(2)
        self.upload_slots = asyncio.Semaphore(4)
        self.rate = {}
        self.tasks = set()

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.dbpath, timeout=5, isolation_level='DEFERRED')
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA secure_delete=ON')
        db.execute('PRAGMA journal_mode=DELETE')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def encrypt(self, value):
        return self.fernet.encrypt(json.dumps(value, ensure_ascii=False).encode())

    def decrypt(self, value):
        return json.loads(self.fernet.decrypt(value))

    def cleanup(self):
        now = time.time()
        with self.db() as db:
            db.execute("UPDATE requests SET status='expired', payload=NULL, session=NULL, csrf=NULL WHERE status NOT IN ('saved','saving','expired') AND expires<?", (now,))
            db.execute("DELETE FROM requests WHERE status IN ('saved','expired') AND created<?", (now - RETENTION,))

    async def maintain(self, interval=30):
        """Enforce erasure on an idle service too, not just on owner requests."""
        while True:
            self.cleanup()
            await asyncio.sleep(interval)

    @staticmethod
    def authorized(caller=None):
        caller = caller or auth._current_caller.get()
        if not caller or not auth.caller_has_write(caller) or not auth.caller_bw_creds(caller):
            raise PermissionError('Intake requires own-vault write access')
        return caller

    def capability(self, request_id):
        return hmac.new(self.key, ('intake-cap:' + request_id).encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def metadata(row):
        result = {k: row[k] for k in ('id', 'status', 'expires', 'item_id', 'attachment_id')}
        result['request_id'] = result.pop('id')
        return result

    async def intake_create(self, title: str, ttl_seconds: int = 1800, idempotency_key: str | None = None):
        """Create a temporary owner link for text/screenshots into your own Vault only.

        Send the URL privately to the owner. OCR stays local; saving requires human
        review and confirmation. Poll intake_status for verified item references.
        Never put credentials in title or idempotency_key. Requires own write access.
        """
        caller = self.authorized()
        if not isinstance(title, str) or not title.strip() or len(title) > 200:
            raise ValueError('Invalid title')
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 3600:
            raise ValueError('TTL must be 60..3600 seconds')
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('Invalid idempotency key')
        idem = self.digest(idempotency_key) if idempotency_key is not None else None
        self.cleanup()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM requests WHERE caller=? AND idem=?', (caller, idem)).fetchone() if idem else None
            if row is None:
                active = db.execute("SELECT count(*) FROM requests WHERE caller=? AND status NOT IN ('saved','expired')", (caller,)).fetchone()[0]
                total = db.execute('SELECT count(*) FROM requests').fetchone()[0]
                global_active = db.execute("SELECT count(*) FROM requests WHERE status NOT IN ('saved','expired')").fetchone()[0]
                if active >= 5 or global_active >= 100 or total >= 10000:
                    raise ValueError('Intake capacity reached')
                rid = secrets.token_hex(16)
                now = time.time()
                db.execute('INSERT INTO requests(id,caller,title,idem,caphash,created,expires,status) VALUES(?,?,?,?,?,?,?,?)', (rid, caller, self.encrypt(title), idem, self.digest(self.capability(rid)), now, now + ttl_seconds, 'pending'))
                row = db.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
            elif self.decrypt(row['title']) != title:
                raise ValueError('Idempotency key already used for a different title')
        return {**self.metadata(row), 'url': self.public_base_url + '/intake/#' + self.capability(row['id'])}

    async def intake_status(self, request_id: str):
        """Read your request state and verified Vault refs, never submitted content.

        'saving' is not success; only 'saved' confirms Vault text/attachment readback.
        """
        caller = self.authorized()
        self.cleanup()
        with self.db() as db:
            row = db.execute('SELECT * FROM requests WHERE id=? AND caller=?', (request_id, caller)).fetchone()
        if row is None:
            raise PermissionError('Intake request unavailable')
        return self.metadata(row)

    def throttle(self, request, action):
        # Ignore forwarded IP headers: parent proxy must not allow arbitrary trusted IPs.
        now = time.monotonic()
        key = ((request.client.host if request.client else 'unknown'), action)
        self.rate = {k: v for k, v in self.rate.items() if v[0] > now - 60}
        if len(self.rate) >= 2048 and key not in self.rate:
            raise Rejected(429)
        start, n = self.rate.get(key, (now, 0))
        limit = 12 if action == 'submit' else 90
        if n >= limit:
            raise Rejected(429)
        self.rate[key] = (start, n + 1)

    async def body(self, request):
        if request.headers.get('origin') != self.public_base_url:
            raise Rejected(403)
        if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise Rejected(415)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_BODY:
                raise Rejected(413)
            data.extend(chunk)
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            raise Rejected() from None
        if not isinstance(value, dict):
            raise Rejected()
        return value

    def lookup(self, data, request, session=True):
        cap = data.get('capability')
        if not isinstance(cap, str) or len(cap) != 64:
            raise Rejected(403)
        with self.db() as db:
            row = db.execute('SELECT * FROM requests WHERE caphash=?', (self.digest(cap),)).fetchone()
        if row is None or row['status'] == 'expired':
            raise Rejected(403)
        if session:
            cookie, csrf = request.cookies.get(COOKIE, ''), data.get('csrf')
            if not cookie or not isinstance(csrf, str) or not row['session'] or not row['csrf']:
                raise Rejected(403)
            if not hmac.compare_digest(self.digest(cookie), row['session']) or not hmac.compare_digest(self.digest(csrf), row['csrf']):
                raise Rejected(403)
        return row

    @staticmethod
    def text(value):
        if not isinstance(value, str) or len(value.encode('utf-8')) > MAX_TEXT or '\x00' in value:
            raise Rejected()
        return value

    @staticmethod
    def image(encoded):
        if encoded is None:
            return None
        if not isinstance(encoded, str) or len(encoded) > ((MAX_IMAGE + 2) // 3) * 4:
            raise Rejected()
        try:
            raw = base64.b64decode(encoded, validate=True)
            if not raw or len(raw) > MAX_IMAGE:
                raise ValueError()
            if not (raw.startswith(b'\x89PNG\r\n\x1a\n') or raw.startswith(b'\xff\xd8\xff') or (raw.startswith(b'RIFF') and raw[8:12] == b'WEBP')):
                raise ValueError()
            # Pillow tolerates missing end markers; intake deliberately does not.
            if raw.startswith(b'\x89PNG') and not raw.endswith(b'\x00\x00\x00\x00IEND\xaeB\x60\x82'):
                raise ValueError()
            if raw.startswith(b'\xff\xd8') and not raw.endswith(b'\xff\xd9'):
                raise ValueError()
            if raw.startswith(b'RIFF') and int.from_bytes(raw[4:8], 'little') + 8 != len(raw):
                raise ValueError()
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(raw)) as im:
                    if im.format not in ('PNG', 'JPEG', 'WEBP') or im.width * im.height > 20_000_000 or getattr(im, 'n_frames', 1) != 1:
                        raise ValueError()
                    im.verify()
                with Image.open(io.BytesIO(raw)) as im:
                    if ImageFile.LOAD_TRUNCATED_IMAGES:
                        raise ValueError()  # fail closed if another module relaxed Pillow globally
                    im.load()
            return raw
        except Exception:
            raise Rejected() from None

    async def ocr(self, raw):
        if not shutil.which('tesseract'):
            raise Rejected(503)
        if self.ocr_slots.locked():
            raise Rejected(429)
        async with self.ocr_slots:
            # Convert locally to strip metadata and guarantee decoder-safe OCR input.
            with Image.open(io.BytesIO(raw)) as im:
                out = io.BytesIO()
                im.convert('RGB').save(out, 'PNG')
            proc = None
            async def run(args, data, limit):
                nonlocal proc
                child = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                proc = child
                assert child.stdin is not None and child.stdout is not None
                stdin, stdout = child.stdin, child.stdout
                async def feed():
                    try:
                        stdin.write(data)
                        await stdin.drain()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        stdin.close()
                task = asyncio.create_task(feed())
                try:
                    value = bytearray()
                    while chunk := await stdout.read(min(8192, limit + 1 - len(value))):
                        value.extend(chunk)
                        if len(value) > limit:
                            raise Rejected(503)
                    await task
                    await child.wait()
                    if child.returncode:
                        raise Rejected(503)
                    return bytes(value)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            try:
                async with asyncio.timeout(20):
                    langs = await run(['tesseract', '--list-langs'], b'', 8192)
                    available = set(langs.decode(errors='replace').splitlines())
                    language = '+'.join(x for x in ('eng', 'rus') if x in available)
                    if not language:
                        raise Rejected(503)
                    return (await run(['tesseract', 'stdin', 'stdout', '-l', language], out.getvalue(), MAX_TEXT)).decode(errors='replace').strip()
            except (TimeoutError, OSError):
                raise Rejected(503) from None
            finally:
                if proc and proc.returncode is None:
                    proc.kill()
                    await proc.wait()

    async def finish(self, row, payload):
        try:
            self.authorized(row['caller'])  # re-read current grant, not browser identity
            result = await self.save_to_vault(row['caller'], row['id'], self.decrypt(row['title']), payload['text'], base64.b64decode(payload['image']) if payload.get('image') else None, row['item_id'])
            if not isinstance(result, dict) or not isinstance(result.get('item_id'), str) or not result['item_id']:
                raise ValueError()
            attachment = result.get('attachment_id')
            if attachment is not None and not isinstance(attachment, str):
                raise ValueError()
            with self.db() as db:
                db.execute("UPDATE requests SET status='saved',payload=NULL,item_id=?,attachment_id=? WHERE id=? AND status='saving'", (result['item_id'], attachment, row['id']))
        except Exception:
            with self.db() as db:
                db.execute("UPDATE requests SET status='failed' WHERE id=? AND status='saving'", (row['id'],))

    async def handle(self, request):
        nonce = secrets.token_urlsafe(24)
        headers = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}
        if request.method == 'GET':
            return HTMLResponse(HTML.replace('__NONCE__', nonce), headers=headers)
        try:
            action = request.url.path.rsplit('/', 1)[-1]
            self.throttle(request, action)
            if self.upload_slots.locked():
                raise Rejected(429)
            async with self.upload_slots:
                data = await self.body(request)
                self.cleanup()
                row = self.lookup(data, request, session=action != 'session')
                if action == 'session':
                    cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    with self.db() as db:
                        db.execute('UPDATE requests SET session=?,csrf=? WHERE id=?', (self.digest(cookie), self.digest(csrf), row['id']))
                    result = {**self.metadata(row), 'csrf': csrf}
                    if row['payload'] and row['status'] in ('review', 'failed'):
                        result['suggestion'] = self.decrypt(row['payload'])['text']
                    response = JSONResponse(result, headers=headers)
                    response.set_cookie(COOKIE, cookie, secure=True, httponly=True, samesite='strict', path='/intake/', max_age=RETENTION)
                    return response
                if action == 'submit':
                    if row['status'] not in ('pending', 'review') or row['attempted']:
                        raise Rejected(409)
                    text = self.text(data.get('text', ''))
                    raw = self.image(data.get('image'))
                    if not text.strip() and not raw:
                        raise Rejected()
                    suggestion = await self.ocr(raw) if raw else ''
                    combined = self.text('\n\n'.join(x for x in (text, suggestion) if x))
                    payload = self.encrypt({'text': combined, 'image': base64.b64encode(raw).decode() if raw else None})
                    with self.db() as db:
                        changed = db.execute("UPDATE requests SET status='review',payload=? WHERE id=? AND status IN ('pending','review') AND attempted=0 AND expires>?", (payload, row['id'], time.time())).rowcount
                    if not changed:
                        raise Rejected(409)
                    return JSONResponse({'status': 'review', 'suggestion': combined}, headers=headers)
                if action == 'confirm':
                    if row['status'] in ('saved', 'saving'):
                        return JSONResponse(self.metadata(row), headers=headers)
                    try:
                        self.authorized(row['caller'])
                    except PermissionError:
                        raise Rejected(403) from None
                    if row['status'] not in ('review', 'failed') or not row['payload']:
                        raise Rejected(409)
                    text = self.text(data.get('text', ''))
                    payload = self.decrypt(row['payload'])
                    if row['attempted'] and payload['text'] != text:
                        raise Rejected(409)
                    if not text.strip() and not payload.get('image'):
                        raise Rejected()
                    if len(self.tasks) >= 4:
                        raise Rejected(429)
                    with self.db() as db:
                        db.execute('BEGIN IMMEDIATE')
                        current = db.execute('SELECT * FROM requests WHERE id=?', (row['id'],)).fetchone()
                        if current['status'] != row['status'] or current['payload'] != row['payload']:
                            return JSONResponse(self.metadata(current), headers=headers)
                        payload['text'] = text
                        db.execute("UPDATE requests SET status='saving',attempted=1,payload=? WHERE id=?", (self.encrypt(payload), row['id']))
                    # The durable saving state commits BEFORE a task can touch Vault.
                    # Keep strong references; never tie completion to browser lifetime.
                    task = asyncio.create_task(self.finish(row, payload))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                with self.db() as db:
                    row = db.execute('SELECT * FROM requests WHERE id=?', (row['id'],)).fetchone()
                return JSONResponse(self.metadata(row), headers=headers)
        except Rejected as exc:
            return JSONResponse({'error': 'Request rejected. Check the link, expiry, and submitted data.'}, status_code=exc.status, headers=headers)
        except Exception:
            return JSONResponse({'error': 'Unable to process the request.'}, status_code=503, headers=headers)

    def register_routes(self, app):
        app.router.routes.extend([Route('/intake/', self.handle, methods=['GET'])] + [Route('/intake/' + action, self.handle, methods=['POST']) for action in ('session', 'submit', 'confirm', 'status')])

    def register_tools(self, mcp):
        mcp.tool(name='vault.intake_create')(self.intake_create)
        mcp.tool(name='vault.intake_status')(self.intake_status)


def register(mcp, app, save_to_vault=None, **kwargs):
    if save_to_vault is None:
        from app.intake_vault import save_to_vault
    service = Intake(save_to_vault, **kwargs)
    service.register_tools(mcp)
    service.register_routes(app)
    previous = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with previous(application) as state:
            maintenance = asyncio.create_task(service.maintain())
            try:
                yield state
            finally:
                maintenance.cancel()
                await asyncio.gather(maintenance, return_exceptions=True)
    app.router.lifespan_context = lifespan
    return service


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Save to Vault</title>
<style nonce="__NONCE__">
:root{color-scheme:dark;--bg:#111318;--surface:#1b1e24;--line:#758096;--ink:#edf2fa;--muted:#bdc9dc;--accent:#c4ddfa;--danger:#ffb9af}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.shell{max-width:560px;min-height:var(--viewport-height,100svh);margin:auto;padding:clamp(56px,12svh,112px) 24px max(28px,env(safe-area-inset-bottom));display:flex;flex-direction:column;justify-content:flex-start}
.brand{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px;font-weight:500}.brand svg{width:15px;height:15px}
h1{margin:14px 0 5px;font-size:26px;line-height:1.25;letter-spacing:-.035em;font-weight:600}header p{margin:0 0 24px;color:var(--muted);font-size:14px}.step{display:none}
.composer{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:18px;transition:border-color 120ms ease}.composer:focus-within{border-color:var(--accent)}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:10px}textarea{display:block;resize:none;min-height:84px;max-height:320px;width:100%;border:0;padding:0;background:transparent;color:var(--ink);font:400 17px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;caret-color:var(--accent);overflow-y:auto}textarea::placeholder{color:#aebdd2;opacity:1}textarea:focus-visible{outline:2px solid var(--accent);outline-offset:4px;border-radius:3px}textarea:read-only{color:var(--muted)}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px}button{font:inherit;cursor:pointer;touch-action:manipulation;min-height:44px;border:0;transition:background-color 120ms ease}button:disabled{cursor:default;opacity:.5}.icon{display:grid;place-items:center;flex:0 0 44px;width:44px;height:44px;border-radius:12px;background:#303640;color:var(--ink)}button svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8}.prepare{display:flex;align-items:center;justify-content:center;gap:9px;border-radius:12px;padding:0 16px;background:var(--accent);color:#081523;font-size:14px;font-weight:600}button:focus-visible{outline:3px solid var(--accent);outline-offset:4px}
.attachment{display:flex;gap:10px;align-items:center;margin-bottom:20px;min-width:0}.attachment img{display:block;width:56px;height:56px;object-fit:contain;border-radius:8px;background:var(--bg)}.file-info{flex:1;min-width:0}.filename{font-size:13px;overflow-wrap:anywhere;margin:0}.file-detail{font-size:11px;color:var(--muted);margin:3px 0 0}.attachment .icon{background:transparent}
.limits,.privacy{font-size:12px;color:var(--muted);margin:10px 0 0}.privacy{margin-top:22px;font-size:11px}.error{color:var(--danger);font-size:13px;margin:12px 0 0;overflow-wrap:anywhere}
.review-title{font-size:17px;margin:0 0 6px;line-height:1.3;font-weight:600}.review-note{color:var(--muted);font-size:13px;margin:0 0 16px}.save,.retry{border-radius:12px;padding:12px 18px;font-size:14px;font-weight:600}.save{width:100%;margin-top:14px;background:var(--accent);color:#081523}.retry{margin-top:12px;background:#303640;color:var(--ink)}
.status{min-height:88px;padding:20px 0 0}.status-title{font-size:14px;font-weight:600;margin:0 0 5px}.status p:last-of-type{font-size:13px;color:var(--muted);margin:0}body[data-phase=input] .status,body[data-phase=review] .status{display:none}body[data-phase=review] header p{display:none}.terminal .status{background:var(--surface);padding:22px;border-radius:16px;margin:16px 0 0}.terminal[data-phase=saved] .status-title{color:#b8e4c9}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}
@media(hover:hover){.icon:not(:disabled):hover,.retry:not(:disabled):hover{background:#3c4452}.prepare:not(:disabled):hover,.save:not(:disabled):hover{background:#d7e8fc}}@media(max-width:420px){.shell{padding:64px 20px max(24px,env(safe-area-inset-bottom))}.composer{padding:16px}h1{font-size:25px}.attachment{gap:8px}.file-detail{max-width:24ch}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;scroll-behavior:auto!important}}
</style></head>
<body data-phase="boot"><main class="shell">
<header><div class="brand"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>Private intake</div><h1>Save to Vault</h1><p>Review first. Save only when you’re ready.</p></header>
<p id="step" class="step">1 of 2 · Add details</p>
<section id="input" aria-label="Add details"><div class="composer" id="composer" aria-busy="false">
<div id="attachment" class="attachment" hidden><img id="preview" alt="Selected screenshot preview" draggable="false" hidden><div class="file-info"><p id="filename" class="filename"></p><p id="file-detail" class="file-detail"></p></div><button id="remove" class="icon" type="button" aria-label="Remove screenshot" title="Remove screenshot"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
<label for="text" class="sr-only">Text to save</label><textarea id="text" rows="3" autocomplete="off" spellcheck="false" autocapitalize="off" autocorrect="off" aria-describedby="limits input-error" placeholder="Paste text or add a screenshot…"></textarea>
<div class="toolbar"><input id="image" type="file" accept="image/png,image/jpeg,image/webp" hidden><button id="add" class="icon" type="button" aria-label="Add or replace screenshot" title="Add or replace screenshot" disabled><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg></button><button id="prepare" class="prepare" type="button" aria-label="Review details" disabled>Review <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button></div></div>
<p id="limits" class="limits">One image · PNG, JPEG or WebP · Up to 5 MiB</p><p id="input-error" class="error" role="alert" hidden></p></section>
<section id="review" hidden aria-labelledby="review-title"><h2 id="review-title" class="review-title" tabindex="-1">Review your details</h2><p id="review-note" class="review-note">Make any changes before saving.</p><div class="composer"><label for="edited">Text to save</label><textarea id="edited" aria-describedby="review-error" rows="4" autocomplete="off" spellcheck="false" autocapitalize="off" autocorrect="off"></textarea></div><p id="review-error" class="error" role="alert" hidden></p><button id="confirm" class="save" type="button">Save to Vault</button></section>
<div id="status" class="status" role="status" aria-live="polite" aria-atomic="true"><p id="status-title" class="status-title">Checking your link…</p><p id="message">Please wait a moment.</p><button id="reconnect" class="retry" type="button" hidden>Try again</button></div>
<p class="privacy">Local recognition. No external AI. Keep this link private.</p>
</main><script nonce="__NONCE__">'use strict';
const el=id=>document.getElementById(id);
const IMAGE_TYPES=['image/png','image/jpeg','image/webp'],MAX_IMAGE=5*1024*1024,MAX_TEXT=65536;
let capability=location.hash.slice(1),csrf='',busy=false,ready=false,terminal=false,selected=null,previewUrl='',immutableText=null,reviewHasImage=false,pollTimer=0,expiryTimer=0,phase='boot';
history.replaceState(null,'',location.pathname);
function say(title,detail){el('status-title').textContent=title;el('message').textContent=detail;}
function grow(node){node.style.height='auto';node.style.height=Math.min(node.scrollHeight+2,Math.min(320,(window.visualViewport?.height||window.innerHeight)*.45))+'px';}
function viewport(){document.documentElement.style.setProperty('--viewport-height',(window.visualViewport?.height||window.innerHeight)+'px');grow(el('text'));grow(el('edited'));}
window.visualViewport?.addEventListener('resize',viewport);window.addEventListener('resize',viewport);
function controls(){el('prepare').disabled=!ready||busy||(!el('text').value.trim()&&!selected);el('add').disabled=!ready||busy;el('image').disabled=!ready||busy;el('remove').disabled=busy;el('text').readOnly=busy;el('confirm').disabled=busy||terminal;el('edited').readOnly=busy||immutableText!==null;el('composer').setAttribute('aria-busy',String(busy));el('review').setAttribute('aria-busy',String(busy));}
function setPhase(value){phase=value;document.body.dataset.phase=value;document.body.classList.toggle('terminal',terminal);controls();}
function error(message=''){el('input-error').textContent=message;el('input-error').hidden=!message;}
function reviewError(message=''){el('review-error').textContent=message;el('review-error').hidden=!message;el('edited').setAttribute('aria-invalid',String(!!message));}
function syncPicker(file){el('image').value='';if(file){try{const dt=new DataTransfer();dt.items.add(file);el('image').files=dt.files;}catch(_){/* selected remains the source of truth on older browsers. */}}}
function showPreview(file){if(previewUrl)URL.revokeObjectURL(previewUrl);previewUrl='';el('preview').removeAttribute('src');el('preview').hidden=!file;el('attachment').hidden=!file;if(file){previewUrl=URL.createObjectURL(file);el('preview').src=previewUrl;el('filename').textContent=file.name||'Screenshot';el('file-detail').textContent=(file.size<1024*1024?Math.max(1,Math.ceil(file.size/1024))+' KiB':(file.size/1024/1024).toFixed(2)+' MiB')+' · original attached';}else{el('filename').textContent='';el('file-detail').textContent='';}}
function selectImage(file){if(!file)return;if(!IMAGE_TYPES.includes(file.type)||file.size>MAX_IMAGE||file.size===0){syncPicker(selected);error('Choose a PNG, JPEG or WebP up to 5 MiB.');return;}selected=file;syncPicker(file);showPreview(file);error();controls();say('Ready to review','Screenshot added. You can include a note.');}
function purge(){clearTimeout(pollTimer);clearTimeout(expiryTimer);capability='';csrf='';immutableText=null;reviewHasImage=false;selected=null;syncPicker(null);showPreview(null);el('text').value='';el('edited').value='';error();reviewError();}
function finish(value,title,detail){terminal=true;ready=false;busy=false;purge();el('input').hidden=true;el('review').hidden=true;el('step').hidden=true;el('reconnect').hidden=true;setPhase(value);say(title,detail);}
function expire(){finish('expired','This link has expired','Request a new private link. If saving had started, ask your bot to check its status.');}
async function api(action,extra={}){const response=await fetch('/intake/'+action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({capability,csrf,...extra})});if(terminal)throw new Error('closed');if(!response.ok){const e=new Error('request');e.status=response.status;throw e;}return response.json();}
function schedulePoll(){clearTimeout(pollTimer);pollTimer=setTimeout(async()=>{if(terminal)return;try{await state(await api('status'));}catch(e){if(e.status===403)expire();else uncertain();}},1500);}
function uncertain(){if(terminal)return;busy=false;el('input').hidden=true;el('review').hidden=immutableText===null;el('reconnect').hidden=immutableText!==null;el('reconnect').textContent='Check status';setPhase('failed');el('confirm').textContent='Check and retry';say('Save not confirmed','We’ll check the status before retrying the same details. No duplicate item.');}
async function state(d){if(terminal)return;if(d.status==='saved'){finish('saved','Saved to Vault','Your details and any attachment are verified. You can close this page.');return;}if(d.status==='expired'){expire();return;}if(d.status==='saving'){el('reconnect').hidden=true;busy=true;el('input').hidden=true;el('review').hidden=!el('edited').value;setPhase('saving');say('Saving to Vault…','Waiting for confirmation. Please don’t send your details again.');schedulePoll();return;}if(d.status==='failed'){if(immutableText===null){busy=false;await session();return;}uncertain();return;}if(d.status==='review'){busy=false;el('input').hidden=true;el('review').hidden=false;el('step').textContent='2 of 2 · Review';setPhase('review');say('Ready to save','Nothing is saved until you choose Save to Vault.');grow(el('edited'));return;}busy=false;setPhase('input');say('Your details stay in your control','Review your details before saving.');}
async function session(){if(terminal||busy)return;busy=true;controls();el('reconnect').hidden=true;try{const d=await api('session');if(terminal)return;csrf=d.csrf;ready=true;if(Number.isFinite(d.expires)){clearTimeout(expiryTimer);const left=d.expires*1000-Date.now();if(left<=0){expire();return;}expiryTimer=setTimeout(expire,Math.min(left,2147483647));}if(d.status==='failed'&&typeof d.suggestion!=='string')throw new Error('frozen');if(d.suggestion!==undefined){if(d.status==='review')reviewHasImage=null;el('edited').value=d.suggestion;if(d.status==='failed')immutableText=d.suggestion;}busy=false;await state(d);}catch(e){if(terminal)return;busy=false;if(e.status===403){expire();return;}ready=false;setPhase('unavailable');say('Couldn’t check your link','Check your connection and try again. Nothing is confirmed yet.');el('reconnect').hidden=false;}}
el('add').onclick=()=>el('image').click();el('image').addEventListener('change',()=>selectImage(el('image').files[0]));
el('remove').onclick=()=>{selected=null;syncPicker(null);showPreview(null);error();controls();el('add').focus();};
el('text').addEventListener('input',()=>{grow(el('text'));error();controls();});el('edited').addEventListener('input',()=>{grow(el('edited'));reviewError();});
document.addEventListener('paste',event=>{if(busy||terminal||el('input').hidden)return;const files=[...((event.clipboardData&&event.clipboardData.items)||[])].filter(item=>item.kind==='file');if(!files.length)return;if(!event.clipboardData.getData('text/plain'))event.preventDefault();const image=files.find(item=>IMAGE_TYPES.includes(item.type));if(!image){error('Choose a PNG, JPEG or WebP up to 5 MiB.');return;}selectImage(image.getAsFile());});
function validText(text){return !text.includes('\u0000')&&new TextEncoder().encode(text).length<=MAX_TEXT;}
el('prepare').onclick=async()=>{if(busy||terminal||!ready)return;const text=el('text').value;if(!validText(text)){error('Use up to 64 KiB of text without null characters.');return;}if(!text.trim()&&!selected){error('Add some text or a screenshot.');return;}busy=true;setPhase('preparing');error();say(selected?'Reading your screenshot…':'Preparing your review…','Nothing is being saved yet.');try{let image=null;if(selected){const file=selected;image=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(new Error('file'));reader.readAsDataURL(file);});}if(terminal)return;const d=await api('submit',{text,image});if(terminal)return;reviewHasImage=!!selected;el('edited').value=d.suggestion;el('review-note').textContent=selected?'Your note and recognized text are below. Correct any errors; the original image stays attached.':'Make any changes before saving.';await state(d);el('review-title').focus();}catch(e){if(terminal)return;busy=false;if(e.status===403){try{await api('status');}catch(check){if(check.status===403){expire();return;}}}setPhase('input');error('Couldn’t prepare your details. Check the image and your connection, then try again.');say('Not saved yet','Your text and screenshot are still here. Try again when you’re ready.');}finally{if(!terminal){busy=false;controls();}}};
el('confirm').onclick=async()=>{if(busy||terminal||!ready)return;const firstAttempt=immutableText===null;if(firstAttempt){const value=el('edited').value;if(!validText(value)){reviewError('Use up to 64 KiB of text without null characters.');el('edited').focus();return;}if(!value.trim()&&reviewHasImage===false){reviewError('Add some text before saving.');el('edited').focus();return;}reviewError();immutableText=value;}busy=true;setPhase('saving');say('Checking save status…','Keep this page open until saving is confirmed.');try{const current=await api('status');if(['saved','saving'].includes(current.status)){await state(current);return;}await state(await api('confirm',{text:immutableText}));}catch(e){if(terminal)return;if(e.status===403)expire();else if(e.status===400&&firstAttempt){immutableText=null;busy=false;setPhase('review');reviewError('Add some text or correct your details before saving.');el('edited').focus();}else uncertain();}finally{if(!terminal&&phase!=='saving'){busy=false;controls();}}};
el('reconnect').onclick=session;
window.addEventListener('pagehide',()=>{terminal=true;ready=false;busy=false;purge();el('input').hidden=true;el('review').hidden=true;controls();});
window.addEventListener('pageshow',event=>{if(event.persisted)expire();});
viewport();session();
</script></body></html>'''
