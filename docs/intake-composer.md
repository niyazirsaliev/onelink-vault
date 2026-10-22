# Secure intake composer

The intake form uses one growing text composer with an adjacent image picker. Paste text or one PNG, JPEG or WebP image (up to 5 MiB); remove or replace the image before continuing. Enter inserts a newline. Review prepares local OCR and editable text, without saving to the vault. A separate **Save to Vault** action confirms persistence.

The frontend preserves the existing capability, CSRF, expiry and caller boundaries. After an uncertain save it checks request status and retries only the same frozen submission. No external OCR, browser storage, framework or backend API change is introduced.

Run `python -m pytest -q`, install the isolated dependencies from `tests/requirements-ui.txt` and the matching Playwright Chromium shell, then run `python tests/browser_composer_check.py --output /path/to/synthetic-artifacts` and `python tests/browser_paste_check.py app/intake.py`. Browser fixtures are synthetic, not evidence of a real vault write. Physical-device accessibility acceptance is separate.
