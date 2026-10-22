"""Static security/design contracts; importing the app or accessing Vault is unnecessary."""
import ast
import re
from pathlib import Path


def html():
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'app/intake.py').read_text())
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == 'HTML' for t in n.targets))


def contrast(a, b):
    def luminance(value):
        rgb = [int(value[i:i+2], 16) / 255 for i in (1, 3, 5)]
        linear = [x / 12.92 if x <= .04045 else ((x + .055) / 1.055) ** 2.4 for x in rgb]
        return sum(x * weight for x, weight in zip(linear, (.2126, .7152, .0722)))
    x, y = sorted((luminance(a), luminance(b)))
    return (y + .05) / (x + .05)


def test_no_new_browser_secret_storage_external_assets_or_clipboard_read():
    source = html()
    for forbidden in ('localStorage', 'sessionStorage', 'indexedDB', 'navigator.clipboard', 'console.', 'https://', 'http://'):
        assert forbidden not in source
    assert 'nonce="__NONCE__"' in source
    assert "credentials:'same-origin'" in source
    assert "history.replaceState(null,'',location.pathname)" in source
    assert 'URL.revokeObjectURL' in source and "'pagehide'" in source


def test_wcag_aa_text_and_control_boundaries():
    colors = dict(re.findall(r'--([a-z]+):(#[0-9a-f]{6})', html()))
    for foreground in ('ink', 'muted', 'danger'):
        for background in ('bg', 'surface'):
            assert contrast(colors[foreground], colors[background]) >= 4.5
    assert contrast('#081523', colors['accent']) >= 4.5
    assert contrast('#aebdd2', colors['surface']) >= 4.5
    for background in ('bg', 'surface'):
        assert contrast(colors['line'], colors[background]) >= 3


def test_single_attachment_explicit_review_and_mobile_contract():
    source = html()
    assert ' multiple' not in source
    assert 'id="image" type="file"' in source
    assert 'aria-label="Review details"' in source
    assert '>Save to Vault</button>' in source
    assert "el('confirm').onclick=async" in source
    assert 'prefers-reduced-motion' in source
    assert 'safe-area-inset-bottom' in source and 'visualViewport' in source
    assert 'min-height:44px' in source
