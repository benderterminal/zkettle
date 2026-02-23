# zKettle — Self-Destructing Secret Sharing

zKettle is a zero-knowledge, self-hosted secret sharing tool. Secrets are encrypted client-side with AES-256-GCM, the server stores only ciphertext, and the decryption key lives in the URL fragment — never sent to the server. Secrets auto-delete after a configurable number of views or time limit. zKettle is AI-native: agents can create, read, revoke, and audit secrets programmatically.

## When to Use

- **Credential sharing** — share passwords, API keys, or tokens with teammates via a one-time link
- **API key rotation** — create a new secret, share it, revoke the old one
- **Temporary access** — grant short-lived access with a low view count and short TTL
- **Secure dead drops** — leave a secret for someone to pick up once, then it vanishes

## Installation

### Go install (requires Go 1.25+)

```bash
go install github.com/benderterminal/zkettle@latest
```

This installs to `$GOPATH/bin` (typically `~/go/bin`). Make sure it's in your PATH: `export PATH="$HOME/go/bin:$PATH"`

### Binary download

```bash
curl -fsSL https://github.com/benderterminal/zkettle/releases/latest/download/zkettle-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') -o /usr/local/bin/zkettle && chmod +x /usr/local/bin/zkettle
```

### From source

```bash
git clone https://github.com/benderterminal/zkettle.git && cd zkettle && make install
```

## MCP Setup

**Before configuring, ask the user:** Do you want zKettle to generate **public URLs** (recommended — shareable with anyone on the internet) or **local-only URLs** (only accessible on your machine/network)? Public mode uses a free Cloudflare Quick Tunnel — no account or DNS setup required. It works for both local and remote sharing. Only use local mode if sharing is strictly limited to your local network.

> **Important:** Use the **absolute path** to the `zkettle` binary in your MCP config. Many MCP clients (including Claude Code) do not inherit your shell's PATH, so a bare `zkettle` command will silently fail to start.

Add to your MCP client configuration (Claude Code, Claude Desktop, or any MCP-compatible agent):

**Public URLs (recommended)** — secrets shareable with anyone via Cloudflare Quick Tunnel:

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/absolute/path/to/zkettle",
      "args": ["mcp", "--port", "3001", "--tunnel"]
    }
  }
}
```

**Local only** — use only if sharing is strictly limited to your local network:

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/absolute/path/to/zkettle",
      "args": ["mcp", "--port", "3001"]
    }
  }
}
```

**Claude Code shortcut** — use `claude mcp add` to configure with the correct scope and path automatically:

```bash
# Public URLs (recommended)
claude mcp add -s user zkettle -- /absolute/path/to/zkettle mcp --port 3001 --tunnel

# Local only
claude mcp add -s user zkettle -- /absolute/path/to/zkettle mcp --port 3001
```

The MCP server starts an HTTP backend on the specified port and communicates with the agent over stdio. All encryption and decryption happens locally — the server never sees plaintext.

## CLI Usage

```bash
# Start the server locally
zkettle serve --port 3000

# Start with a public URL via Cloudflare Quick Tunnel (no config needed)
zkettle serve --tunnel

# Create a secret (reads from stdin)
echo "my secret password" | zkettle create --server http://localhost:3000 --views 1 --minutes 60

# Read a secret
zkettle read "http://localhost:3000/s/abc123#key"

# Revoke a secret
zkettle revoke --server http://localhost:3000 --token <delete-token> <id>

# Generate a random secret
zkettle generate --length 32 --charset symbols

# List active secrets (requires admin token)
zkettle list --server http://localhost:3000 --admin-token <token>
```

### Cloudflare Quick Tunnel

The `--tunnel` flag creates an instant public URL (e.g. `https://random-name.trycloudflare.com`) with no account, no config, and no DNS setup. Generated secret URLs will automatically use the tunnel URL. Works with both `serve` and `mcp` commands:

```bash
# Server with public URL
zkettle serve --tunnel

# MCP with public URL (shareable links use the tunnel domain)
zkettle mcp --port 3001 --tunnel
```

## Web UI

Start the server and open `http://localhost:3000` in a browser. Use `--tunnel` for a public URL shareable with anyone — without it, the web UI is only accessible on localhost. All encryption happens client-side using the Web Crypto API.

Features:
- **Create secrets** with configurable view limits and expiry (presets or custom datetime picker)
- **Generate random secrets** (password, token, or hex key presets) directly in the form
- **Reveal secrets** via shareable URLs — the viewer auto-detects if a secret has expired or been consumed
- **Recent secrets panel** tracks created secrets with view counts, expiry timestamps, and revoke buttons
- **Copy Without Revealing** copies a secret to clipboard without rendering it in the page
- **Status polling** automatically updates the viewer and recent panel when secrets expire

## Tool Reference

### `create_secret`

Encrypt and store a secret, returning an expiring URL.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `content` | string | no | — | Plaintext secret to encrypt (max 500KB). WARNING: visible in agent conversation context. Use `file` instead for maximum security. |
| `file` | string | no | — | Read secret content from this file path instead of `content`. Keeps plaintext out of agent context. |
| `views` | integer | no | `1` | Max views before auto-delete (1–100) |
| `minutes` | integer | no | `1440` | Minutes until expiry (1–43200, i.e. 30 days max) |

Provide exactly one of `content` or `file`.

**Returns:** `url` (with decryption key in fragment) and `delete_token` for later revocation.

### `read_secret`

Retrieve and decrypt a secret from a zKettle URL. Consumes one view. Use the `file` or `clipboard` parameters to keep the decrypted secret out of the agent conversation context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | Full zKettle URL including the `#key` fragment |
| `file` | string | no | Write decrypted secret to this file path (0600 permissions) instead of returning it |
| `clipboard` | boolean | no | Copy to system clipboard instead of returning it. No auto-clear. Mutually exclusive with `file`. |

**Returns:** Decrypted plaintext (default), or confirmation message when `file` or `clipboard` is used.

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

## Recommended Secure Patterns

When using zKettle via MCP, plaintext secrets can appear in the agent conversation
context (tool inputs/outputs). Use these patterns to minimize exposure:

### Reading secrets without exposing plaintext
- `read_secret(url="...", file="/tmp/secret.txt")` — writes to file, returns confirmation only
- `read_secret(url="...", clipboard=true)` — copies to user's clipboard, returns confirmation only
- Subagents can read the file at the path without the secret entering conversation context

### Creating secrets without exposing plaintext
- `create_secret(file="/path/to/secret.txt")` — reads content from file, plaintext never in tool call
- `generate_secret(create=true)` — generates + encrypts in one step, plaintext never in response

### Web UI
- Use the **Copy Without Revealing** button on the viewer page to copy a secret to clipboard without rendering it in the page

## Common Agent Patterns

> For maximum security, use `file` instead of `content` when creating secrets — see [Recommended Secure Patterns](#recommended-secure-patterns) above.

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
