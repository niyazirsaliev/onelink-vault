# <NAME>

![<NAME> banner](assets/banner.svg)

<img src="assets/logo.svg" width="72" alt="Key and link logo">

A self-hosted, multi-agent secret gateway for **Bitwarden cloud and Vaultwarden**.
It wraps the official `bw` CLI in a Streamable HTTP MCP service: per-agent bearer
keys, separate vault accounts and CLI homes, opt-in cross-vault delegation,
SQLite audit metadata, and a short-lived human-to-vault intake link with **local
screenshot OCR**.

## Why this exists

[Bitwarden's official MCP server](https://github.com/bitwarden/mcp-server) already
exists. Use it when you want the official integration for a vault. <NAME> is
**not a replacement or an official Bitwarden product**: its focus is a shared,
multi-agent / fleet-scoped gateway and human handoff. Each agent gets its own
identity and Bitwarden permissions; a human can paste a secret or a screenshot
into a one-time link rather than an agent chat. OCR proposes text, the human
reviews and confirms, then the text and original image are saved into the
requesting agent's own organization collection.

## Five-minute local setup

Prerequisites: Docker with Compose, a Bitwarden-compatible account with a master
password and personal API key, and (for collection-backed writes/intake) an
organization collection named exactly after your agent, e.g. `agent-a`. Create
accounts and grant collection permissions using your server's normal UI. The
service does **not** register accounts or modify organization membership.
Account and organization preparation may take longer than five minutes.
In the web vault, create the account and organization, create an `agent-a`
collection, and grant that account access to it. The **personal** API key is
under Settings → Security → Keys → View API key (confirm the master password);
use its `client_id` and `client_secret`, not an organization API key.

For self-hosted Vaultwarden, use a TLS URL reachable **from inside the gateway
container**, not the host's `127.0.0.1`. Set Vaultwarden's `DOMAIN` to its canonical
HTTPS URL: the CLI also follows server-generated attachment URLs, so successful
login alone does not prove attachment downloads can reach the server. Use a
trusted certificate. For an isolated test with a private CA, mount its public
CA certificate into the gateway and add `NODE_EXTRA_CA_CERTS: /certs/ca.pem` to
the Compose service environment; setting an extra variable in `.env` alone does
not pass it through. Do not disable TLS verification. The web vault also requires
a secure browser origin; a private-network plain-HTTP hostname is not sufficient.

```sh
cp .env.example .env
# Edit .env: set ADMIN_KEY to a locally generated random value.
# VW_URL defaults to US Bitwarden cloud; EU uses https://vault.bitwarden.eu.
# For Vaultwarden, set VW_URL=https://vault.example.com.
docker compose up -d --build
curl --fail http://127.0.0.1:8000/health
```

Generate a key locally with `python -c 'import secrets; print(secrets.token_urlsafe(32))'`.
Do not commit `.env`, caller credentials, state volumes, or generated keys.
The image runs as UID/GID 1000 and exposes port 8000 **only on loopback**.

Register an agent without putting secrets in command arguments or shell history:

```sh
python scripts/add_caller.py
```

Run the helper on your host (Python 3, no extra dependencies).
The helper does not load `.env`: if you changed `PORT`, run it with that same
port, for example `PORT=18000 python scripts/add_caller.py`, and use that port
for the health check too. Leave `ADMIN_KEY` in `.env`; enter it privately at the
helper's prompt rather than exporting or placing it on the command line.
It prompts privately for the admin key, account API client ID, API client secret,
and master password; asks for an agent name and write permission; then registers
the caller over loopback. Its generated bearer token is shown once for storage
in the agent's private configuration. This grants no additional Bitwarden
permissions: provision least-privilege collection access in Bitwarden first.

### Enable the human intake link

1. Provide a trusted HTTPS reverse proxy for this service (same origin for the
   form and `/intake/*` API). Configure certificates and routing yourself;
   <NAME> does not provision Internet exposure or tunnels.
2. Set `INTAKE_PUBLIC_BASE_URL=https://vault-gateway.example.com` in `.env` and
   recreate the service with `docker compose up -d`.
3. Keep `/admin/*` restricted to local operator access; expose only `/mcp` and
   the exact `/intake/`, `/intake/session`, `/intake/submit`, `/intake/confirm`,
   `/intake/status` routes as needed. Do not log request bodies or auth headers.
4. The agent calls `vault.intake_create(title="Service credential")` and sends
   the returned URL privately to the human. Default TTL is 30 minutes; allowed
   range is 60–3600 seconds. Do not put secrets in the title/idempotency key.
5. The human opens the link, pastes text or a PNG/JPEG/WebP screenshot (up to
   5 MiB), reviews local OCR, corrects it, and confirms. The screenshot is stored
   as an attachment; account/organization attachment entitlement is required.
6. Poll `vault.intake_status(request_id=...)`. Only `saved` means a successful
   independent text/scope/attachment readback. Failed/uncertain writes can be
   retried with the same frozen content and request, without creating duplicates.

The browser needs HTTPS for the secure session cookie. Local HTTP MCP works
without intake; intake itself deliberately rejects non-HTTPS origins.

## MCP clients

Endpoint: `https://vault-gateway.example.com/mcp` (Streamable HTTP, not legacy
SSE). Header: `Authorization: Bearer <agent-token>`. Give each client its own
key. These are generic configuration examples; **none of these four client
applications were exercised end-to-end for this release**. Protect config files
and do not place literal keys in version-controlled project files.

### Claude Code

`.mcp.json` (or your private user-level MCP configuration):

```json
{
  "mcpServers": {
    "my-agent-vault": {
      "type": "http",
      "url": "https://vault-gateway.example.com/mcp",
      "headers": {"Authorization": "Bearer ${VAULT_GATEWAY_TOKEN}"}
    }
  }
}
```

Set `VAULT_GATEWAY_TOKEN` in the client environment. See
[Claude Code MCP docs](https://code.claude.com/docs/en/mcp); environment expansion
and policy availability depend on your installed client version.

### Codex CLI

In `~/.codex/config.toml`:

```toml
[mcp_servers.my_agent_vault]
url = "https://vault-gateway.example.com/mcp"
bearer_token_env_var = "VAULT_GATEWAY_TOKEN"
```

Export the token in Codex's environment. The `url` and `bearer_token_env_var`
fields were checked against [Codex MCP documentation](https://developers.openai.com/codex/mcp/).

### OpenClaw

**Unverified, version-dependent:** OpenClaw integrations may use a separate MCP
bridge such as `mcporter`; a universal native `openclaw.json` schema could not be
verified. Do not copy a Claude-style block into OpenClaw's main config blindly.
For an installation already using `mcporter`, this is a proposed private
`config/mcporter.json` entry; verify URL/header syntax with that installed
bridge's documentation before use:

```json
{
  "mcpServers": {
    "my-agent-vault": {
      "baseUrl": "https://vault-gateway.example.com/mcp",
      "headers": {"Authorization": "Bearer <agent-token>"}
    }
  }
}
```

This is a bridge configuration, not a claim of native OpenClaw support.

### Hermes Agent

In `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  my_agent_vault:
    url: https://vault-gateway.example.com/mcp
    headers:
      Authorization: "Bearer ${VAULT_GATEWAY_TOKEN}"
    timeout: 120
    connect_timeout: 30
```

Set the token in Hermes's private environment and restart. URL/header syntax and
runtime environment substitution were checked against the
[Hermes MCP documentation](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp/).

## Tools and operator endpoints

- `vault.sync`, `vault.list`, `vault.get_item`, `vault.get_password`.
- `vault.create_item`, `vault.update_field`, `vault.rotate_password` require
  `write_ok`. Rotation changes the **stored vault password only**; it does not
  update the upstream service's credentials.
- `vault.give`: create-only one-way handoff to another registered agent; requires
  write permission. This is an explicit exception to ordinary own-vault access:
  any write-enabled caller may create a new item in another registered caller's
  accessible collection. It does not grant read/update access to that caller.
- `vault.intake_create`, `vault.intake_status` are registered only when intake
  is enabled; status returns references, not submitted secrets.
- Admin endpoints: `POST /admin/add_caller`, `/admin/rotate`,
  `/admin/remove_caller`, `/admin/deliver`; `GET /admin/callers`. All require
  `X-Admin-Key`. Admin delivery can update an existing same-name own-collection
  item. Removing a caller revokes the gateway key, not its Bitwarden account.

Collection selection for normal creation: explicitly requested collection, exact
caller-named collection, otherwise the only non-`shared` collection; if no
collection can be selected it may create a personal-vault item. Intake is
stricter: it requires one unambiguous caller-named organization collection
(compatibility aliases `<caller>-legacy` and a stripped `-hermes` suffix are
also recognized). Avoid aliases for new deployments. Collection permissions
come from the underlying Bitwarden account, not from name filtering alone.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `VW_URL` | `https://vault.bitwarden.com` | CLI server URL; EU/self-hosted supported |
| `ADMIN_KEY` | empty | Empty disables admin endpoints |
| `PORT` | `8000` | Compose loopback host port |
| `CALLERS_FILE_PATH` | `/var/lib/vault-gateway/callers.json` | Private caller credential store |
| `BW_HOME_BASE` | `/var/lib/vault-gateway/bw-homes` | Per-caller CLI config/cache |
| `AUDIT_DB_PATH` | `/var/lib/vault-gateway/audit.db` | SQLite invocation metadata |
| `INTAKE_PUBLIC_BASE_URL` | empty | Fixed HTTPS origin; empty disables intake |
| `INTAKE_STATE_DIR` | `/var/lib/vault-gateway/intake` | Encrypted temporary intake state + key |
| `CROSS_VAULT_READ_CALLERS` | empty | Comma-separated delegated reader names |
| `CROSS_VAULT_WRITE_CALLERS` | empty | Delegated writers; must be a subset of readers |
| `BW_COMMAND_TIMEOUT_SECONDS` | `30` | Positive finite CLI deadline |
| `BW_REAP_TIMEOUT_SECONDS` | `5` | Positive finite child cleanup deadline |

Compose fixes state paths in the volume; edit its environment mapping if you
need different paths. Native Python deployments can override every path.
The caller store maps each name to `token`, `write_ok`, `bw_clientid`,
`bw_clientsecret`, and `bw_password`. Legacy token-only entries are read-only
and cannot use vault operations. Do not reuse tokens or accounts across agents.

## Security model and limits

- **Trusted gateway:** the service holds plaintext API credentials and master
  passwords in its caller store and unlocked session keys in memory. Bitwarden
  encryption does not protect secrets from this gateway or its host operator.
  Treat the state volume, process environment, backups, and host as sensitive.
- Per-agent isolation is enforced by bearer identity, separate CLI homes and
  separate Bitwarden accounts. It is not a sandbox. An account can read all
  items Bitwarden grants it; a collection argument is not an authorization rule.
- Cross-vault read/write is **off by default** and operator-configured only.
  Never grant it to an untrusted agent. The admin key is effectively root here.
- Secrets explicitly retrieved via MCP become visible to the agent/client and
  potentially its transcript. The intake path avoids initial chat submission;
  it does not prevent later authorized retrieval.
- Intake URLs are bearer capabilities, not human identity verification. Anyone
  with the link can open it; the current browser session can be replaced by a
  later opener before completion. Send links privately. Confirmed saves are
  one-time; retries only reconcile the same content and vault record.
- Intake has same-origin checks, session cookies, CSRF, CSP, request-size limits,
  local rate limits, TTL, and encrypted pending payloads. The encryption key is
  on the same volume: this protects against casual inspection, not host theft.
  Payloads are cleared on saved/expired state; metadata is retained seven days.
  SQLite deletion is not guaranteed forensic erasure on every filesystem.
- Screenshot staging uses Linux `/dev/shm`, anonymous RAM files, and verified
  attachment readback. Host swap/core dumps may still capture plaintext. OCR
  is local Tesseract (English image installed); no third-party OCR API is used.
- Run **one worker and one service replica per state directory**. Locks, rate
  limits and recovery are process-local. Do not scale with shared SQLite state.
- Audit records tool names, caller, item names/IDs, status, timing, cross-vault
  target and sanitized errors, not intentionally submitted secret values.
  Names and IDs can still be sensitive: do not embed secrets in item titles.
  Intake uses its own request-state metadata, not the general invocation table.
- Place authentication-aware TLS and access controls in front of remote use.
  Do not log request bodies, capability fragments, headers, or form contents.
  There is no formal security audit, multi-tenant hardening guarantee, or SLA.

## Development and verification

Python 3.12 is the container baseline. On Linux:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m pytest
```

Unit tests use mocked CLI/vault I/O and temporary local state, with no account or
network required. A local Tesseract test is skipped if the binary is absent.
`tests/browser_paste_check.py` is an optional offline Playwright browser check;
install Playwright + Chromium separately to run it. It is not part of pytest.

A throwaway Vaultwarden integration run verified the Docker build, real account
API-key login/unlock, collection-scoped create/read/list, unauthenticated MCP
rejection, and browser-confirmed text/screenshot intake over HTTPS. Both intake
requests reached `saved`; independent CLI download matched all original PNG
bytes, and image text was recognized by Tesseract inside the image. A failed
attachment download caused by an incorrect test-server `DOMAIN` was retried
successfully without duplicate records after fixing the server URL.
This is not a Bitwarden cloud, third-party MCP-client, or production TLS-proxy
certification; those still require operator integration testing.
Dependency minimum ranges are not a reproducible lockfile; pin and review them
for your deployment.

## Naming and license

`<NAME>` is deliberately a renameable placeholder throughout the project and
artwork. Stable on-disk paths use the neutral `vault-gateway` directory.
Candidate names and preliminary collision checks:

- **keydrop**: existing [GitHub password-receiving project](https://github.com/koseki/keydrop)
  is a direct naming collision; not recommended. PyPI lookup returned 404.
- **vaultlink**: existing [GitHub project](https://github.com/ALTIQUUM/Vaultlink)
  and [secure file transfer project](https://github.com/sabariap08/vaultlink)
  collide. PyPI lookup was unavailable (HTTP 503).
- **onelink-vault**: no relevant exact-name search result found; provisional
  preference. PyPI lookup was unavailable (HTTP 503). This is not an availability
  guarantee or trademark clearance.

[MIT license](LICENSE), copyright **The <NAME> authors**. Confirm the right to
relicense the source and replace the holder placeholder before publication.
