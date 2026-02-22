# zKettle — Self-Destructing Secret Sharing

zKettle is a zero-knowledge, self-hosted secret sharing tool. Secrets are encrypted client-side with AES-256-GCM, the server stores only ciphertext, and the decryption key lives in the URL fragment — never sent to the server. Secrets auto-delete after a configurable number of views or time limit. zKettle is MCP-native: agents can create, read, revoke, and audit secrets programmatically.

## When to Use

- **Credential sharing** — share passwords, API keys, or tokens with teammates via a one-time link
- **API key rotation** — create a new secret, share it, revoke the old one
- **Temporary access** — grant short-lived access with a low view count and short TTL
- **Secure dead drops** — leave a secret for someone to pick up once, then it vanishes

## MCP Setup

Add to your MCP client configuration:

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

The MCP server starts an HTTP backend on the specified port and communicates with the agent over stdio.

## Tool Reference

### `create_secret`

Encrypt and store a secret, returning an expiring URL.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `content` | string | yes | — | Plaintext secret to encrypt (max 500KB) |
| `views` | integer | no | `1` | Max views before auto-delete (1–100) |
| `minutes` | integer | no | `1440` | Minutes until expiry (1–43200, i.e. 30 days max) |

**Returns:** `url` (with decryption key in fragment) and `delete_token` for later revocation.

### `read_secret`

Retrieve and decrypt a secret from a zKettle URL. Consumes one view.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | Full zKettle URL including the `#key` fragment |

**Returns:** Decrypted plaintext.

### `revoke_secret`

Delete a secret immediately.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | yes | Secret ID |
| `delete_token` | string | yes | Token returned by `create_secret` |

**Returns:** Confirmation of revocation.

### `list_secrets`

List all active secrets (metadata only — no content or keys). Local MCP access only.

**Returns:** JSON array of secret metadata (ID, creation time, expiry, remaining views).

### `generate_secret`

Generate a cryptographically random secret. Optionally encrypt and store it in one step.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `length` | integer | no | `32` | Length in characters (1–4096) |
| `charset` | string | no | `"alphanumeric"` | Character set: alphanumeric, symbols, hex, base64url |
| `create` | boolean | no | `false` | If true, encrypt and store the generated secret |
| `views` | integer | no | `1` | When create=true, max views before auto-delete (1–100) |
| `minutes` | integer | no | `1440` | When create=true, minutes until expiry (1–43200) |

**Returns:** Raw generated text, or `url` + `delete_token` when `create=true`.

## Common Agent Patterns

### Credential rotation
```
1. create_secret(content="new-db-password", views=2, minutes=240)
2. Share URL with recipient
3. revoke_secret(id="old-secret-id", delete_token="old-token")
```

### Temporary access grant
```
1. create_secret(content="temp-token", views=1, minutes=60)
2. Send one-time link — expires after a single view or 60 minutes
```

### Read a shared secret
```
1. Receive URL from human or another agent
2. read_secret(url="https://example.com/s/abc123#key")
3. Use the decrypted content
```

### Audit active secrets
```
1. list_secrets() → review what's still live
2. revoke_secret() on any that are no longer needed
```

## Security Model

- **Zero-knowledge**: The server stores only AES-256-GCM ciphertext. The decryption key is in the URL fragment, which is never sent to the server.
- **Client-side encryption**: All encryption/decryption happens on the client (CLI, browser Web Crypto API, or MCP tool).
- **Self-destructing**: Secrets auto-delete after the configured view count or time limit.

## Limits and Gotchas

- **500KB** max plaintext size per secret
- **100 views** max per secret
- **43200 minutes** (30 days) max TTL
- **1 view** default if `views` is omitted
- **1440 minutes** (24 hours) default if `minutes` is omitted
- **URL fragments**: The `#key` portion of the URL contains the decryption key. Some tools strip URL fragments — ensure the full URL is passed to `read_secret`
- **Local-only list**: `list_secrets` is only available via the local MCP stdio transport, not over the network API
