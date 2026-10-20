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


HTML = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Save to vault</title>
<style nonce="__NONCE__">#preview:not([hidden]){display:block;max-width:100%;max-height:320px;margin-top:12px;border-radius:10px}body{font:17px system-ui;background:#101722;color:#edf2fa;max-width:640px;margin:0 auto;padding:24px}h1{font-size:26px}label{display:block;margin:20px 0 8px}textarea,input,button{box-sizing:border-box;width:100%;font:inherit;border-radius:10px;padding:13px}textarea{min-height:180px;background:#1b2638;color:inherit}button{margin-top:20px;background:#8fc7ff;color:#06101c;border:0;min-height:50px}button:disabled{opacity:.45}p{line-height:1.5}#message{white-space:pre-wrap}small{color:#b6c3d6}[hidden]{display:none!important}</style></head>
<body><h1>Save a secret to your vault</h1><p>Data will be saved only to the vault of the agent that created this link. Do not forward this link.</p>
<section id="input"><label for="image">Screenshot (optional)</label><input id="image" type="file" accept="image/png,image/jpeg,image/webp"><small>PNG, JPEG or WebP, up to 5 MiB. Paste with Cmd+V or Ctrl+V. OCR runs locally.</small><img id="preview" alt="Selected screenshot" hidden><label for="text">Text (optional)</label><textarea id="text" autocomplete="off" spellcheck="false"></textarea><button id="prepare" disabled>Recognize and review</button></section>
<section id="review" hidden><h2>Review your data</h2><p>OCR can make mistakes. Correct the text before saving. The original screenshot will be attached to the item.</p><label for="edited">Text to save</label><textarea id="edited" autocomplete="off" spellcheck="false"></textarea><button id="confirm">Save to vault</button></section><p id="message" role="status" aria-live="polite">Checking link...</p>
<script nonce="__NONCE__">'use strict';
const el=id=>document.getElementById(id);let capability=location.hash.slice(1),csrf='',busy=false;
history.replaceState(null,'',location.pathname);
const say=s=>el('message').textContent=s;
async function api(action,extra={}){const r=await fetch('/intake/'+action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({capability,csrf,...extra})});const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
function state(d){if(d.status==='saved'){say('Saved to the vault. You can close this page.');el('input').hidden=true;el('review').hidden=true;capability='';el('text').value='';el('edited').value='';el('image').value='';pasted=null;showPreview(null);}else if(d.status==='saving'){say('Saving. Do not resubmit the data.');setTimeout(()=>api('status').then(state).catch(e=>say(e.message)),1500);}else if(d.status==='failed'){say('Save not confirmed. Retry with the same text; duplicate items will not be created.');el('edited').readOnly=true;}else say('Review the text and confirm saving.');}
(async()=>{try{const d=await api('session');csrf=d.csrf;el('prepare').disabled=false;say('Add a screenshot, text, or both.');if(d.suggestion!==undefined){el('edited').value=d.suggestion;el('input').hidden=true;el('review').hidden=false;}if(['saved','saving','failed'].includes(d.status))state(d);}catch(e){say(e.message);}})();
const IMAGE_TYPES=['image/png','image/jpeg','image/webp'];let pasted=null,previewUrl='';function showPreview(f){if(previewUrl)URL.revokeObjectURL(previewUrl);previewUrl='';const p=el('preview');if(!f){p.hidden=true;p.removeAttribute('src');return;}previewUrl=URL.createObjectURL(f);p.src=previewUrl;p.hidden=false;}function chosenImage(){return el('image').files[0]||pasted;}el('image').addEventListener('change',()=>{pasted=null;showPreview(el('image').files[0]);});document.addEventListener('paste',e=>{if(busy||el('input').hidden)return;const items=[...((e.clipboardData&&e.clipboardData.items)||[])].filter(i=>i.kind==='file');if(!items.length)return;const item=items.find(i=>IMAGE_TYPES.includes(i.type));e.preventDefault();if(!item){say('Choose PNG, JPEG or WebP up to 5 MiB.');return;}const f=item.getAsFile();if(!f)return;try{const dt=new DataTransfer();dt.items.add(f);el('image').files=dt.files;pasted=null;}catch(_){el('image').value='';pasted=f;}showPreview(f);say('Скриншот вставлен. Нажмите «Recognize and review».');});
el('prepare').onclick=async()=>{if(busy)return;busy=true;el('prepare').disabled=true;try{let image=null;const f=chosenImage();if(f){if(f.size>5*1024*1024||!IMAGE_TYPES.includes(f.type))throw Error('Choose PNG, JPEG or WebP up to 5 MiB.');image=await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result).split(',')[1]);r.onerror=()=>reject(Error('Unable to read the file'));r.readAsDataURL(f);});}say('Processing locally...');const d=await api('submit',{text:el('text').value,image});el('edited').value=d.suggestion;el('review').hidden=false;el('input').hidden=true;state(d);}catch(e){say(e.message);}finally{busy=false;el('prepare').disabled=false;}};
el('confirm').onclick=async()=>{if(busy)return;busy=true;el('confirm').disabled=true;try{state(await api('confirm',{text:el('edited').value}));}catch(e){say(e.message);}finally{busy=false;el('confirm').disabled=false;}};
</script></body></html>'''
