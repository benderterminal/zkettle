# MCP Integration Guide

zKettle exposes its secret-sharing capabilities as an MCP (Model Context Protocol) server. Any MCP-compatible agent can create, read, list, and revoke self-destructing secrets.

## Setup

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/path/to/zkettle",
      "args": ["mcp", "--port", "3001"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add zkettle -- /path/to/zkettle mcp --port 3001
```

Or add to `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/path/to/zkettle",
      "args": ["mcp", "--port", "3001"]
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/path/to/zkettle",
      "args": ["mcp", "--port", "3001"]
    }
  }
}
```

## MCP Server Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `3000` | HTTP port for the API backend |
| `--host` | `127.0.0.1` | Listen address |
| `--data` | `./data` | Data directory for SQLite database |
| `--base-url` | `http://localhost:{port}` | Base URL for generated secret links |
| `--tunnel` | off | Expose server via Cloudflare Quick Tunnel |
| `--trust-proxy` | off | Trust `X-Forwarded-For` headers (behind a reverse proxy) |
| `--log-format` | `text` | Log format: `json` or `text` |

## Tool Reference

### `create_secret`

Encrypt and store a secret, returning an expiring URL.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `content` | string | yes | — | The plaintext secret to encrypt (max 500KB) |
| `views` | integer | no | `1` | Max views before auto-delete (1–100) |
| `hours` | integer | no | `24` | Hours until expiry (1–720) |

**Returns:** The secret URL (with decryption key in the fragment) and a `delete_token` for revocation.

**Example response:**
```
url: https://your-domain.com/s/abc123#base64url-key
delete_token: def456
```

### `read_secret`

Retrieve and decrypt a secret from a zKettle URL. This consumes one view — if the secret has no remaining views, it is permanently deleted.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | The full zKettle secret URL including the `#key` fragment |

**Returns:** The decrypted plaintext.

### `revoke_secret`

Delete a secret immediately, regardless of remaining views or time.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | yes | The secret ID to revoke |
| `delete_token` | string | yes | The delete token returned when the secret was created |

**Returns:** Confirmation that the secret was revoked.

### `list_secrets`

List all active secrets on this server. Returns metadata only — no encrypted content or decryption keys are included. This tool is only accessible via the local MCP stdio transport; it is not exposed over the network.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| *(none)* | — | — | — |

**Returns:** A JSON array of secret metadata (ID, creation time, expiry, remaining views).

## Common Patterns

### Create and share a secret

An agent creates a secret and sends the URL to a human or another agent:

```
Agent: I'll create a temporary secret with your API key.
→ calls create_secret(content="sk-abc123...", views=1, hours=1)
→ "Here's your one-time link: https://example.com/s/xyz#key"
```

### Read a secret from a URL

An agent reads a secret URL received from another party:

```
User: Read this secret: https://example.com/s/abc123#key
→ calls read_secret(url="https://example.com/s/abc123#key")
→ returns the decrypted plaintext
```

### Credential rotation

Create a new secret, share it, then revoke the old one:

```
→ calls create_secret(content="new-password-here", views=2, hours=4)
→ shares the URL with the recipient
→ calls revoke_secret(id="old-secret-id", delete_token="old-token")
```

### Temporary access grant

Create a short-lived secret with a single view for one-time access:

```
→ calls create_secret(content="temp-token-xyz", views=1, hours=1)
→ "Access this within 1 hour — link expires after one view."
```

### Audit active secrets

List all active secrets to check what's still live:

```
→ calls list_secrets()
→ reviews expiry times and remaining views
→ revokes any secrets that are no longer needed
```

## Troubleshooting

### Port conflicts

If port 3000 is already in use, specify a different port:

```json
"args": ["mcp", "--port", "3001"]
```

### Remote access / custom domain

If the server is behind a reverse proxy or on a remote host, set `--base-url` so generated links point to the correct address:

```json
"args": ["mcp", "--port", "3001", "--base-url", "https://secrets.example.com"]
```

### Quick demo with Cloudflare Tunnel

For a quick public demo without configuring DNS, use `--tunnel` to get a temporary public URL:

```json
"args": ["mcp", "--port", "3001", "--tunnel"]
```

Note: `--tunnel` and `--base-url` are mutually exclusive.

### URL fragment handling

The decryption key lives in the URL fragment (after `#`). Some tools strip URL fragments. If `read_secret` fails with "no decryption key in URL", make sure the full URL including the `#key` portion is being passed.
