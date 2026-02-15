# zKettle

Self-hosted zero-knowledge expiring secrets. Encrypt locally, store ciphertext on the server, share a URL with the decryption key in the fragment. The server never sees the plaintext or the key.

## Quick Start

```bash
# Download the binary for your platform (or build from source)
make build

# Start the server
./dist/zkettle serve --port 3000

# Create a secret (in another terminal)
./dist/zkettle create "my secret password" --views 1 --hours 24
# → http://localhost:3000/s/abc123#key

# Read a secret
./dist/zkettle read "http://localhost:3000/s/abc123#key"
# → my secret password

# Revoke a secret
./dist/zkettle revoke abc123
```

Open the URL in a browser to reveal the secret via the web viewer.

## MCP Setup

zKettle includes an MCP server for use with Claude Desktop, Claude Code, or any MCP-compatible agent.

```json
{
  "mcpServers": {
    "zkettle": {
      "command": "/path/to/zkettle",
      "args": ["mcp", "--port", "3001", "--base-url", "https://your-domain.com"]
    }
  }
}
```

The MCP server starts an HTTP backend on the specified port and communicates with the agent over stdio. Available tools:

| Tool | Description |
|------|-------------|
| `create_secret` | Encrypt and store a secret, returns an expiring URL |
| `read_secret` | Retrieve and decrypt a secret from a zKettle URL |
| `list_secrets` | List active secrets (metadata only) |
| `revoke_secret` | Delete a secret by ID |

## CLI Reference

```
zkettle serve [options]     Start the HTTP server
  --port 3000               HTTP port
  --host 0.0.0.0            Listen address
  --data ./data             Data directory for SQLite database
  --base-url ""             Base URL for generated links (default: http://localhost:{port})

zkettle create [options] <plaintext>   Encrypt and store a secret
  --views 1                 Max views before auto-delete
  --hours 24                Hours until expiry
  --server http://localhost:3000   Server URL

zkettle read <url>          Retrieve and decrypt a secret (quote the URL)

zkettle revoke [options] <id>   Delete a secret
  --server http://localhost:3000   Server URL

zkettle mcp [options]       Start MCP server on stdio with HTTP backend
  --port 3000               HTTP port for API
  --data ./data             Data directory
  --base-url ""             Base URL for generated links

zkettle version             Print version
```

## API Reference

### POST /api/secrets

Create a secret.

```json
{
  "encrypted": "<base64url ciphertext>",
  "iv": "<base64url 12-byte IV>",
  "views": 1,
  "hours": 24
}
```

Response (201):
```json
{
  "id": "abc123",
  "expires_at": "2024-01-02T03:04:05Z"
}
```

### GET /api/secrets/:id

Retrieve and consume a view. Returns the encrypted blob:

```json
{
  "encrypted": "<base64url ciphertext>",
  "iv": "<base64url IV>"
}
```

Returns 404 if expired, already consumed, or nonexistent.

### DELETE /api/secrets/:id

Delete a secret. Returns 204.

### GET /health

Health check. Returns 200 with `{"status":"ok"}`.

### GET /s/:id

Serves the web viewer HTML. The decryption key is in the URL fragment (`#key`) and never sent to the server.

## Security Model

- **Zero-knowledge**: The server stores only AES-256-GCM ciphertext. The decryption key lives in the URL fragment, which browsers never send to the server.
- **Client-side encryption**: All encryption and decryption happens on the client (CLI or browser Web Crypto API).
- **Expiring**: Secrets auto-delete after the configured number of views or time limit.
- **No auth in MVP**: Anyone with the URL can view the secret. Recipient authentication is planned for post-MVP.

## Building

```bash
make build          # Build for current platform
make build-all      # Build for darwin/linux arm64/amd64
make test           # Run all tests
make clean          # Remove build artifacts
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).
