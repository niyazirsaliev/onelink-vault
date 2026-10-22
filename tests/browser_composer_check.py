"""Offline Chromium UI qualification; no Vault, capability URLs, traces or real secrets.

PLAYWRIGHT_BROWSERS_PATH=<own-cache> python tests/browser_composer_check.py --output <artifacts>
Install isolated test tooling: playwright==1.58.0 and its chromium --only-shell.
All HTTPS requests are intercepted; HTML and CSP come from the actual application.
"""
import argparse
import asyncio
import base64
import io
import json
import secrets
import time
from pathlib import Path
from playwright.async_api import async_playwright
from PIL import Image, ImageDraw
from browser_paste_check import form_html

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://vault.example'
CSP = "default-src 'none'; script-src 'nonce-testnonce'; style-src 'nonce-testnonce'; connect-src 'self'; img-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def picture():
    image = Image.new('RGB', (420, 200), '#edf2fa')
    draw = ImageDraw.Draw(image)
    draw.text((24, 28), 'DEMO ONLY\n\nWorkspace: Example\nNo real credentials', fill='#182332', spacing=10)
    out = io.BytesIO()
    image.save(out, 'PNG')
    return out.getvalue()


class Fixture:
    def __init__(self):
        self.status = 'pending'
        self.text = ''
        self.frozen = None
        self.calls = []  # No capability, CSRF or URL is retained.
        self.errors = []
        self.delay = 0.0
        self.confirm_mode = 'saving'
        self.drop_confirm_response = False
        self.network_status_error = False
        self.session_error = False
        self.expires = time.time() + 900
        self.image = False

    async def route(self, route):
        request = route.request
        if request.url == ORIGIN + '/intake/':
            return await route.fulfill(status=200, body=form_html(ROOT / 'app/intake.py'), headers={'Content-Type': 'text/html', 'Content-Security-Policy': CSP})
        if not request.url.startswith(ORIGIN + '/intake/'):
            self.errors.append('unexpected_network_destination')
            return await route.abort()
        action = request.url.rsplit('/', 1)[-1]
        data = request.post_data_json
        self.calls.append({'action': action, 'text': data.get('text'), 'image': bool(data.get('image'))})
        code = 200
        result = {'status': self.status, 'expires': self.expires}
        if action == 'session':
            if self.session_error:
                code = 403
            else:
                result['csrf'] = secrets.token_hex(16)
                if self.status in ('review', 'failed'):
                    result['suggestion'] = self.text
        elif action == 'submit':
            await asyncio.sleep(self.delay)
            self.image = bool(data.get('image'))
            self.text = data['text'] + ('\n\nDemo OCR: check and correct' if self.image else '')
            self.status = 'review'
            result = {'status': self.status, 'suggestion': self.text}
        elif action == 'confirm':
            # Match the actual backend: invalid empty text-only confirms never freeze/write.
            if not data['text'].strip() and not self.image:
                return await route.fulfill(status=400, body='{}', headers={'Content-Type': 'application/json'})
            if self.frozen is not None and data['text'] != self.frozen:
                self.errors.append('immutable_retry_changed')
            self.frozen = self.text = data['text']
            self.status = self.confirm_mode
            result = {'status': self.status}
            if self.drop_confirm_response:
                self.drop_confirm_response = False
                return await route.abort('failed')
        elif action == 'status':
            if self.network_status_error:
                return await route.abort('failed')
            result = {'status': self.status}
        else:
            self.errors.append('unexpected_api_action')
        await route.fulfill(status=code, body=json.dumps(result), headers={'Content-Type': 'application/json'})

    def count(self, action):
        return sum(x['action'] == action for x in self.calls)


async def main(output):
    output.mkdir(parents=True, exist_ok=True)
    checks = {}
    scope = ''
    image = picture()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        contexts = []

        async def open_page(width=390, height=844, fixture=None):
            f = fixture or Fixture()
            ctx = await browser.new_context(viewport={'width': width, 'height': height}, permissions=['clipboard-read', 'clipboard-write'], reduced_motion='reduce')
            contexts.append(ctx)
            await ctx.route('**/*', f.route)
            # Generate an ephemeral synthetic fragment inside the page, not in evidence URLs.
            await ctx.add_init_script("if(location.pathname==='/intake/')history.replaceState(null,'',location.pathname+'#'+crypto.randomUUID().replaceAll('-',''));")
            page = await ctx.new_page()
            page.on('pageerror', lambda _: f.errors.append('javascript_exception'))
            page.on('console', lambda message: f.errors.append('console_error') if message.type == 'error' and 'ERR_FAILED' not in message.text else None)
            await page.goto(ORIGIN + '/intake/')
            await page.wait_for_function("()=>document.body.dataset.phase !== 'boot'")
            return page, f

        async def phase(page, value):
            await page.wait_for_function('(v)=>document.body.dataset.phase===v', arg=value)

        async def check(name, value):
            name = scope + '/' + name if scope else name
            checks[name] = bool(value)
            assert value, name  # Never include URL, request body or token in failure text.

        async def native_image(page):
            await page.evaluate("async b64=>{const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));await navigator.clipboard.write([new ClipboardItem({'image/png':new Blob([bytes],{type:'image/png'})})]);}", base64.b64encode(image).decode())
            await page.locator('#text').focus()
            await page.keyboard.press('Control+V')
            await page.locator('#attachment').wait_for(state='visible')

        # Empty edited text must remain correctable, not an immutable uncertain write.
        for invalid_text in ('', '  \n  '):
            vp, vf = await open_page()
            await vp.locator('#text').fill('Demo text to review')
            await vp.locator('#prepare').click()
            await phase(vp, 'review')
            await vp.locator('#edited').fill(invalid_text)
            await vp.locator('#confirm').click()
            await vp.wait_for_timeout(80)
            await check('empty_review_editable_' + ('blank' if not invalid_text else 'whitespace'),
                        vf.count('confirm') == 0 and not await vp.locator('#edited').evaluate('(e)=>e.readOnly')
                        and await vp.locator('body').get_attribute('data-phase') == 'review')
            await vp.locator('#edited').fill('Corrected demo text')
            vf.confirm_mode = 'saved'
            await vp.locator('#confirm').click()
            await phase(vp, 'saved')
            await check('empty_review_correctable_' + ('blank' if not invalid_text else 'whitespace'), vf.count('confirm') == 1)

        # Reloaded reviews lack attachment metadata; server400 is definite rejection, not unknown save.
        resumed_text = Fixture(); resumed_text.status = 'review'; resumed_text.text = 'Demo resumed review'
        tp, tf = await open_page(fixture=resumed_text)
        await tp.locator('#edited').fill('')
        await tp.locator('#confirm').click()
        await tp.wait_for_timeout(80)
        await check('resumed_text_empty_rejection_stays_editable', tf.count('confirm') == 1 and
                    not await tp.locator('#edited').evaluate('(e)=>e.readOnly') and
                    await tp.locator('body').get_attribute('data-phase') == 'review')
        await tp.locator('#edited').fill('Fixed resumed demo')
        tf.confirm_mode = 'saved'
        await tp.locator('#confirm').click()
        await phase(tp, 'saved')
        await check('resumed_text_recovers_after_definite_rejection', tf.count('confirm') == 2)

        for resumed in (False, True):
            image_only = Fixture()
            if resumed:
                image_only.status = 'review'; image_only.image = True
            ip, inf = await open_page(fixture=image_only)
            if not resumed:
                await native_image(ip)
                await ip.locator('#prepare').click()
                await phase(ip, 'review')
            await ip.locator('#edited').fill('')
            inf.confirm_mode = 'saved'
            await ip.locator('#confirm').click()
            await phase(ip, 'saved')
            await check('image_only_empty_text_allowed_' + str(resumed), inf.count('confirm') == 1)

        primary_errors = []
        for primary_width in (390, 1280):
            scope = 'mobile' if primary_width == 390 else 'desktop'
            page, f = await open_page(width=primary_width)
            await check('empty_prepare_disabled', await page.locator('#prepare').is_disabled())
            await check('fragment_removed', await page.evaluate("!location.hash"))
            await check('accessible_composer_and_picker', await page.locator('#text').get_attribute('aria-describedby') is not None and await page.locator('#add').get_attribute('aria-label') is not None)
            await page.locator('#text').focus()
            await page.evaluate("navigator.clipboard.writeText('Demo workspace note')")
            await page.keyboard.press('Control+V')
            await page.wait_for_function("()=>document.getElementById('text').value==='Demo workspace note'")
            await page.keyboard.press('Enter')
            await check('native_text_paste_and_enter_no_send', f.count('submit') == 0 and '\n' in await page.locator('#text').input_value())
            initial_height = await page.locator('#text').evaluate('(e)=>e.offsetHeight')
            await page.locator('#text').fill('Demo workspace note\n' * 12)
            await check('composer_grows_with_text', await page.locator('#text').evaluate('(e)=>e.offsetHeight') > initial_height)
            await page.locator('#text').fill('Demo workspace note')
            await native_image(page)
            await check('native_image_clipboard_paste', await page.locator('#image').evaluate('(e)=>e.files.length') == 1)
            await check('preview_contained', await page.locator('#preview').evaluate('(e)=>e.offsetHeight<=76 && e.offsetWidth<=76') and await page.locator('#preview').evaluate('(e)=>!e.closest("a")'))
            await page.locator('#remove').click()
            await check('remove_clears_and_focuses_plus', await page.locator('#attachment').is_hidden() and await page.locator('#add').evaluate('(e)=>e===document.activeElement'))
            async with page.expect_file_chooser() as chooser:
                await page.locator('#add').click()
            await (await chooser.value).set_files({'name': 'demo-screen.png', 'mimeType': 'image/png', 'buffer': image})
            await check('plus_uses_native_picker', await page.locator('#filename').inner_text() == 'demo-screen.png')
            await page.locator('#image').set_input_files({'name': 'replacement.png', 'mimeType': 'image/png', 'buffer': image})
            await check('replace_one_attachment', await page.locator('#image').evaluate('(e)=>e.files.length') == 1 and await page.locator('#filename').inner_text() == 'replacement.png')
            await page.locator('#image').set_input_files({'name': 'invalid.gif', 'mimeType': 'image/gif', 'buffer': b'GIF89a'})
            await check('invalid_type_inline_preserves_valid_selection', await page.locator('#input-error').is_visible() and await page.locator('#filename').inner_text() == 'replacement.png')
            await page.locator('#image').set_input_files({'name': 'oversize.png', 'mimeType': 'image/png', 'buffer': b'x' * (5 * 1024 * 1024 + 1)})
            await check('oversize_inline_feedback', '5 MiB' in await page.locator('#input-error').inner_text())
            await page.locator('#image').set_input_files({'name': 'demo-screen.png', 'mimeType': 'image/png', 'buffer': image})
            await page.screenshot(path=str(output / f'{scope}-input.png'), full_page=True)
            f.delay = .35
            await page.locator('#prepare').click()
            await check('ocr_pending_text_and_controls', await page.locator('#text').evaluate('(e)=>e.readOnly') and await page.locator('#add').is_disabled() and 'Reading your screenshot' in await page.locator('#status-title').inner_text())
            await phase(page, 'review')
            await check('combined_review_preserves_typed_text', (await page.locator('#edited').input_value()).startswith('Demo workspace note\n\n') and f.calls[-1]['image'])
            await check('no_confirmation_before_save', f.count('confirm') == 0)
            await check('review_keyboard_focus', await page.locator('#review-title').evaluate('(e)=>e===document.activeElement'))
            await page.locator('#edited').fill('Demo workspace note\nCorrected OCR example')
            await page.screenshot(path=str(output / f'{scope}-review.png'), full_page=True)
            f.confirm_mode = 'failed'
            await page.locator('#confirm').evaluate('(e)=>{e.click();e.click();}')
            await phase(page, 'failed')
            await check('duplicate_clicks_one_confirm', f.count('confirm') == 1)
            await check('failed_result_frozen_for_retry', await page.locator('#edited').evaluate('(e)=>e.readOnly') and await page.locator('#confirm').is_enabled())
            await page.locator('#edited').evaluate("e=>{e.value='tampered client DOM';}")
            f.confirm_mode = 'saving'
            await page.locator('#confirm').click()
            await phase(page, 'saving')
            await page.wait_for_function("()=>document.getElementById('status-title').textContent.includes('Saving to Vault')")
            await check('retry_exact_immutable_payload', f.count('confirm') == 2 and f.calls[-1]['text'] == 'Demo workspace note\nCorrected OCR example')
            await check('saving_not_saved_and_locked', await page.locator('#confirm').is_disabled() and 'Saving to Vault' in await page.locator('#status-title').inner_text())
            f.status = 'saved'
            await phase(page, 'saved')
            await check('saved_sensitive_dom_cleared', await page.locator('#text').input_value() == '' and await page.locator('#edited').input_value() == '' and await page.locator('#preview').get_attribute('src') is None and await page.locator('#image').evaluate('(e)=>e.files.length') == 0)
            await check('saved_runtime_capability_cleared', await page.evaluate("capability===''&&csrf===''&&immutableText===null&&previewUrl===''") )
            await page.screenshot(path=str(output / f'{scope}-saved.png'), full_page=True)
            await check('no_storage_persistence', await page.evaluate('localStorage.length===0 && sessionStorage.length===0'))

            primary_errors.extend(f.errors)
        scope = ''

        for width in (320, 390, 1280):
            responsive, rf = await open_page(width=width, height=800)
            await responsive.locator('#text').fill('Demo text\n' * 8)
            await check(f'no_horizontal_overflow_{width}', await responsive.evaluate('document.documentElement.scrollWidth<=innerWidth'))
            await check(f'17px_input_and_44px_targets_{width}', await responsive.locator('#text').evaluate('(e)=>parseFloat(getComputedStyle(e).fontSize)>=16') and await responsive.locator('#add').evaluate('(e)=>e.offsetHeight>=44&&e.offsetWidth>=44'))
            await responsive.locator('#add').focus()
            await responsive.keyboard.press('Tab')
            await check(f'keyboard_plus_to_prepare_{width}', await responsive.locator('#prepare').evaluate('(e)=>e===document.activeElement&&parseFloat(getComputedStyle(e).outlineWidth)>=2'))
            if width == 1280:
                await responsive.screenshot(path=str(output / 'desktop-keyboard.png'), full_page=True)
            await responsive.set_viewport_size({'width': width, 'height': 420})
            await responsive.wait_for_timeout(60)
            await check(f'visual_viewport_resizes_{width}', await responsive.evaluate("parseFloat(document.documentElement.style.getPropertyValue('--viewport-height'))===visualViewport.height"))
            await check(f'reduced_motion_{width}', await responsive.locator('#prepare').evaluate('(e)=>getComputedStyle(e).transitionDuration===\'0s\''))
            await check(f'console_clean_{width}', not rf.errors)

        expired_fixture = Fixture()
        expired_fixture.expires = time.time() + 1
        ep, ef = await open_page(fixture=expired_fixture)
        await ep.locator('#text').fill('Demo expires')
        await native_image(ep)
        await phase(ep, 'expired')
        await check('ttl_expiry_clears_sensitive_dom', await ep.locator('#text').input_value() == '' and await ep.locator('#preview').get_attribute('src') is None)
        denied = Fixture();denied.session_error = True
        dp, _ = await open_page(fixture=denied)
        await check('invalid_session_fails_closed', await dp.locator('body').get_attribute('data-phase') == 'expired' and await dp.locator('#input').is_hidden())
        resume = Fixture();resume.status = 'failed';resume.text = 'Demo immutable recovery'
        rp, rr = await open_page(fixture=resume)
        await check('resumed_failure_uses_server_frozen_text', await rp.locator('#edited').input_value() == resume.text and await rp.locator('#edited').evaluate('(e)=>e.readOnly'))
        await rp.evaluate("dispatchEvent(new PageTransitionEvent('pagehide'))")
        await check('pagehide_purges_sensitive_data', await rp.locator('#edited').input_value() == '' and await rp.evaluate("capability===''"))
        unknown = Fixture();unknown.status = 'saving'
        up, uf = await open_page(fixture=unknown)
        uf.status = 'failed';uf.text = 'Demo recovered after saving'
        await phase(up, 'failed')
        await check('resumed_saving_failure_recovers_immutable_payload', await up.locator('#edited').input_value() == uf.text and await up.locator('#edited').evaluate('(e)=>e.readOnly'))
        lost = Fixture();lost.drop_confirm_response = True
        lp, lf = await open_page(fixture=lost)
        await lp.locator('#text').fill('Demo uncertain response')
        await lp.locator('#prepare').click()
        await phase(lp, 'review')
        await lp.locator('#confirm').click()
        await phase(lp, 'failed')
        await check('lost_confirm_response_freezes_text', lf.count('confirm') == 1 and await lp.locator('#edited').evaluate('(e)=>e.readOnly'))
        await lp.locator('#confirm').click()
        await lp.wait_for_function("()=>document.getElementById('status-title').textContent.includes('Saving to Vault')")
        await check('uncertain_retry_checks_status_without_duplicate_confirm', lf.count('confirm') == 1)
        lf.status = 'saved'
        await phase(lp, 'saved')
        await check('uncertain_write_eventually_verified_once', lf.count('confirm') == 1 and await lp.locator('#edited').input_value() == '')
        slow = Fixture();slow.expires = time.time() + 1;slow.delay = 1.6
        sp, sf = await open_page(fixture=slow)
        await sp.locator('#text').fill('Demo late response')
        await sp.locator('#prepare').click()
        await phase(sp, 'expired')
        await sp.wait_for_timeout(900)
        await check('late_ocr_cannot_restore_expired_dom', await sp.locator('#edited').input_value() == '' and await sp.locator('#review').is_hidden())
        await check('console_and_destinations_clean', not primary_errors and not ef.errors and not rr.errors and not uf.errors and not lf.errors and not sf.errors)
        for context in contexts:
            await context.close()
        await browser.close()
    report = {'checks': checks, 'passed': sum(checks.values()), 'total': len(checks), 'real_vault': False, 'synthetic_only': True, 'traces_recorded': False}
    (output / 'browser-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(main(parser.parse_args().output))
