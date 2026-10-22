"""Real-browser regression for clipboard image paste in the intake form.

Runs offline: the form HTML is served through Playwright request routing with
the production CSP, and the intake API is mocked. Requires the `playwright`
package with Chromium (for example the corsair-tools/playwright image).
Usage: python tests/browser_paste_check.py app/intake.py
"""
import ast
import base64
import json
import struct
import sys
import zlib

from playwright.sync_api import sync_playwright


def form_html(path):
    tree = ast.parse(open(path, encoding='utf-8').read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'HTML' for t in node.targets):
            return node.value.value.replace('__NONCE__', 'testnonce')
    raise SystemExit('HTML not found')


def png(w=4, h=3):
    raw = b''.join(b'\x00' + b'\x10\x80\xf0' * w for _ in range(h))
    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


CSP = ("default-src 'none'; script-src 'nonce-testnonce'; style-src 'nonce-testnonce'; "
       "connect-src 'self'; img-src 'self' blob:")

PASTE = """async ([b64, type]) => {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const dt = new DataTransfer();
  if (type) dt.items.add(new File([bytes], 'clip', {type}));
  else dt.setData('text/plain', 'plain text');
  const ev = new ClipboardEvent('paste', {clipboardData: dt, bubbles: true, cancelable: true});
  document.activeElement.dispatchEvent(ev);
  return ev.defaultPrevented;
}"""


def main():
    html = form_html(sys.argv[1])
    image = png()
    calls = []
    results = {}

    def route(r):
        url = r.request.url
        if url.endswith('/intake/'):
            return r.fulfill(status=200, body=html, headers={'Content-Type': 'text/html', 'Content-Security-Policy': CSP})
        action = url.rsplit('/', 1)[-1]
        body = json.loads(r.request.post_data or '{}')
        calls.append((action, body))
        reply = {'session': {'csrf': 'c', 'status': 'pending'},
                 'submit': {'status': 'review', 'suggestion': 'ocr'}}.get(action, {'status': 'review'})
        r.fulfill(status=200, body=json.dumps(reply), headers={'Content-Type': 'application/json'})

    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        errors = []
        page.on('console', lambda m: m.type == 'error' and errors.append(m.text))
        page.route('https://vault.example/**', route)
        page.goto('https://vault.example/intake/#cap')
        page.wait_for_function("document.body.dataset.phase === 'input'")
        assert page.locator('#prepare').is_disabled()

        page.focus('#text')
        results['plain_text_not_intercepted'] = page.evaluate(PASTE, ['', '']) is False
        results['gif_rejected'] = page.evaluate(PASTE, [base64.b64encode(b'GIF89a').decode(), 'image/gif'])
        results['gif_left_no_selection'] = page.evaluate("document.getElementById('image').files.length") == 0
        page.focus('body')
        results['png_paste_handled'] = page.evaluate(PASTE, [base64.b64encode(image).decode(), 'image/png'])
        results['file_input_selected'] = page.evaluate("document.getElementById('image').files.length") == 1
        results['preview_visible'] = page.evaluate(
            "(()=>{const p=document.getElementById('preview');return !p.hidden&&p.src.startsWith('blob:')&&p.getBoundingClientRect().height>0})()")
        results['no_request_before_click'] = [a for a, _ in calls] == ['session']
        page.click('#prepare')
        page.wait_for_selector('#review:not([hidden])')
        submit = [b for a, b in calls if a == 'submit']
        results['submit_carries_same_image'] = len(submit) == 1 and base64.b64decode(submit[0]['image']) == image
        results['no_confirm_without_explicit_save'] = 'confirm' not in [a for a, _ in calls]
        results['no_console_errors'] = not errors
        b.close()
    print(json.dumps(results))
    sys.exit(0 if all(results.values()) else 1)


if __name__ == '__main__':
    main()
