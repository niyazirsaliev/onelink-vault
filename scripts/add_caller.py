#!/usr/bin/env python3
"""Register existing account credentials with a local onelink-vault gateway."""
import getpass
import json
import os
import re
import secrets
import urllib.error
import urllib.request


def main():
    port = os.environ.get('PORT', '8000')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise SystemExit('Invalid PORT')
    name = input('Agent name [agent-a]: ').strip() or 'agent-a'
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
        raise SystemExit('Invalid agent name')
    admin = getpass.getpass('Admin key: ')
    payload = {
        'bot_name': name,
        'token': secrets.token_urlsafe(32),
        'write_ok': input('Allow writes? [y/N]: ').strip().lower() == 'y',
        'bw_clientid': getpass.getpass('Bitwarden personal API client ID: '),
        'bw_clientsecret': getpass.getpass('Bitwarden personal API client secret: '),
        'bw_password': getpass.getpass('Bitwarden master password: '),
    }
    if not all(payload[k] for k in ('bw_clientid', 'bw_clientsecret', 'bw_password')):
        raise SystemExit('All account credential fields are required')
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}/admin/add_caller',
        data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json', 'X-Admin-Key': admin},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.load(response)
        if not result.get('ok') or result.get('bot_name') != name:
            raise ValueError('Registration not confirmed')
    except (urllib.error.URLError, ValueError):
        raise SystemExit('Registration failed; check the local service and admin key') from None
    print('Registered. Store this bearer token privately; it is shown once:')
    print(payload['token'])


if __name__ == '__main__':
    main()
