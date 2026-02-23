# zKettle

Self-hosted zero-knowledge expiring secrets. Encrypt locally, store ciphertext on the server, share a URL with the decryption key in the fragment. The server never sees the plaintext or the key.

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

### Via AI agent

Paste this prompt into Claude Code, Cursor, or any MCP-compatible agent:

```
I want to set up zKettle — a self-hosted zero-knowledge secret sharing tool. Install it with go install github.com/benderterminal/zkettle@latest, then read the MCP setup instructions in the README at https://github.com/benderterminal/zkettle. When configuring the MCP server, use the absolute path to the installed binary (find it with which zkettle or check ~/go/bin/). Once configured, test the full workflow using the CLI: create a secret, read it back, and revoke it. Note that MCP servers are loaded at startup — the new tools won't be available until the next terminal session.
```

## Quick Start

```bash
# Start the server with a Cloudflare tunnel (instant public URL)
zkettle serve --tunnel

# Or start locally
zkettle serve --port 3000

# Create a secret (in another terminal)
echo "my secret password" | zkettle create --views 1 --minutes 60
# → http://localhost:3000/s/abc123#key

# Read a secret
zkettle read "http://localhost:3000/s/abc123#key"
# → my secret password

# Revoke a secret
zkettle revoke --server http://localhost:3000 --token <delete-token> <id>
```

Open the URL in a browser to reveal the secret via the web viewer.

## Docker Deployment

```bash
# Build and run with Docker Compose
docker compose up -d

# Or build and run manually
docker build -t zkettle .
docker run -d -p 3000:3000 -v zkettle-data:/data zkettle
```

The container listens on port 3000 and stores data in `/data`. Configure with environment variables (see [Configuration Reference](#configuration-reference)).

## Production Deployment

### With TLS (direct)

```bash
zkettle serve --host 0.0.0.0 --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

### With a reverse proxy (recommended)

Run zkettle behind Caddy, Nginx, or Traefik for automatic TLS:

```bash
zkettle serve --host 127.0.0.1 --trust-proxy
```

Enable `--trust-proxy` so zkettle reads the real client IP from `X-Forwarded-For` headers.

### Systemd

Copy the service template and enable it:

```bash
sudo cp contrib/zkettle.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zkettle
```

The service template uses `DynamicUser=yes` with `ReadWritePaths=/var/lib/zkettle`, so systemd manages the data directory automatically.

Configure via environment file at `/etc/zkettle/env`:

```bash
ZKETTLE_PORT=3000
ZKETTLE_HOST=0.0.0.0
ZKETTLE_ADMIN_TOKEN=your-secret-token
ZKETTLE_TRUST_PROXY=true
```

### Backups

The database is a single SQLite file at `<data-dir>/zkettle.db`. Back it up with:

```bash
sqlite3 /var/lib/zkettle/zkettle.db ".backup /backups/zkettle-$(date +%Y%m%d).db"
```

## Admin API

Enable the admin endpoint by setting an admin token via environment variable:

```bash
export ZKETTLE_ADMIN_TOKEN=my-secret-admin-token
zkettle serve
```

> **Note:** Passing `--admin-token` on the command line exposes the token in process listings (`ps`, `/proc/*/cmdline`). Prefer the environment variable or config file.

### List active secrets

```bash
# Via CLI
zkettle list --server http://localhost:3000 --admin-token my-secret-admin-token

# Via API
curl -H "Authorization: Bearer my-secret-admin-token" http://localhost:3000/api/admin/secrets
```

Returns metadata only (ID, views remaining, timestamps). No encrypted content or decryption keys are ever exposed.

### GET /api/admin/secrets

Returns 404 when no admin token is configured (endpoint disabled). Requires `Authorization: Bearer <token>` header.

Response (200):
```json
[
  {
    "id": "abc123...",
    "views_left": 2,
    "expires_at": "2024-01-02T03:04:05Z",
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

## Metrics

Enable the `/metrics` endpoint with the `--metrics` flag:

```bash
export ZKETTLE_ADMIN_TOKEN=my-secret-admin-token
zkettle serve --metrics
```

The `/metrics` endpoint requires the admin token (`Authorization: Bearer <token>` header). Returns 404 when no admin token is configured.

Returns JSON metrics at `GET /metrics`:

```json
{
  "zkettle_secrets_active": 5
}
```

## MCP Setup

zKettle includes an MCP server for use with Claude Desktop, Claude Code, or any MCP-compatible agent.

> **Important:** Use the **absolute path** to the `zkettle` binary. Many MCP clients do not inherit your shell's PATH, so a bare `zkettle` command will silently fail to start.

Add to your MCP client's configuration file:

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

Use `--tunnel` for public shareable URLs via Cloudflare Quick Tunnel (no account required). Omit it for local-only access. Use `--base-url https://your-domain.com` if you have a custom domain.

**Claude Code shortcut:**

```bash
claude mcp add -s user zkettle -- /absolute/path/to/zkettle mcp --port 3001 --tunnel
```

The MCP server starts an HTTP backend on the specified port and communicates with the agent over stdio. All encryption and decryption happens locally — in the browser (Web Crypto API), CLI, or MCP server process. The zKettle HTTP server never sees plaintext.

Available tools:

| Tool | Description |
|------|-------------|
| `create_secret` | Encrypt and store a secret, returns an expiring URL |
| `read_secret` | Retrieve and decrypt a secret from a zKettle URL |
| `list_secrets` | List active secrets (metadata only) |
| `revoke_secret` | Delete a secret by ID |
| `generate_secret` | Generate a random secret, optionally store it |

## CLI Reference

```
zkettle serve [options]     Start the HTTP server
  --port 3000               HTTP port
  --host 127.0.0.1          Listen address (use 0.0.0.0 for all interfaces)
  --data ./data             Data directory for SQLite database
  --base-url ""             Base URL for generated links (default: http://localhost:{port})
  --cors-origins ""         Comma-separated allowed CORS origins
  --tunnel                  Expose server via Cloudflare Quick Tunnel
  --trust-proxy             Trust X-Forwarded-For headers (behind a reverse proxy)
  --log-format ""           Log format: json or text (defaults to text)
  --tls-cert ""             TLS certificate file path
  --tls-key ""              TLS private key file path
  --admin-token ""          Admin API bearer token (enables GET /api/admin/secrets)
  --max-secret-size 0       Max encrypted secret size in bytes (0 = 500KB)
  --metrics                 Enable /metrics endpoint

zkettle create [options]    Encrypt and store a secret (reads from stdin)
  --views 1                 Max views before auto-delete
  --minutes 1440            Minutes until expiry (default 24h)
  --server http://localhost:3000   Server URL
  --json                    Output JSON to stdout
  --quiet, -q               Suppress stderr output

zkettle read [options] <url>   Retrieve and decrypt a secret (quote the URL)
  --clipboard, -c             Copy to clipboard instead of printing to stdout
  --file, -o <path>           Write to file (0600 permissions) instead of stdout

zkettle revoke [options] <id>   Delete a secret
  --server http://localhost:3000   Server URL
  --token ""                Delete token (returned by create, or set ZKETTLE_DELETE_TOKEN)

zkettle list [options]      List active secrets (requires admin token)
  --server http://localhost:3000   Server URL
  --admin-token ""          Admin API bearer token
  --json                    Output raw JSON

zkettle generate [options]  Generate a cryptographically random secret
  --length 32               Length in characters
  --charset alphanumeric    Character set: alphanumeric, symbols, hex, base64url

zkettle mcp [options]       Start MCP server on stdio with HTTP backend
  --port 3000               HTTP port for API
  --host 127.0.0.1          Listen address
  --data ./data             Data directory
  --base-url ""             Base URL for generated links
  --tunnel                  Expose server via Cloudflare Quick Tunnel
  --trust-proxy             Trust X-Forwarded-For headers (behind a reverse proxy)
  --log-format ""           Log format: json or text (defaults to text)

zkettle version             Print version
```

## Configuration Reference

Configuration is resolved in order of precedence: **flags > env vars > config file > defaults**.

### Config file

Search order: `./zkettle.toml`, `$HOME/.config/zkettle/zkettle.toml`

```toml
port = 3000
host = "127.0.0.1"
data = "./data"
base_url = ""
cors_origins = []
trust_proxy = false
tunnel = false
log_format = "" # defaults to "text"
tls_cert = ""
tls_key = ""
admin_token = ""
max_secret_size = 0 # 0 = 500KB default
metrics = false
```

> **Security:** If your config file contains `admin_token`, restrict permissions: `chmod 600 zkettle.toml`

### Environment variables

| Variable | Description |
|----------|-------------|
| `ZKETTLE_PORT` | HTTP port |
| `ZKETTLE_HOST` | Listen address |
| `ZKETTLE_DATA` | Data directory |
| `ZKETTLE_BASE_URL` | Base URL for generated links |
| `ZKETTLE_CORS_ORIGINS` | Comma-separated CORS origins |
| `ZKETTLE_TRUST_PROXY` | Trust proxy headers (`true`/`1`/`yes`) |
| `ZKETTLE_TUNNEL` | Enable Cloudflare tunnel (`true`/`1`/`yes`) |
| `ZKETTLE_LOG_FORMAT` | Log format: `json` or `text` |
| `ZKETTLE_TLS_CERT` | TLS certificate file path |
| `ZKETTLE_TLS_KEY` | TLS private key file path |
| `ZKETTLE_ADMIN_TOKEN` | Admin API bearer token |
| `ZKETTLE_MAX_SECRET_SIZE` | Max encrypted secret size in bytes |
| `ZKETTLE_METRICS` | Enable metrics endpoint (`true`/`1`/`yes`) |
| `ZKETTLE_DELETE_TOKEN` | Delete token for `zkettle revoke` (alternative to `--token`) |

## API Reference

### POST /api/secrets

Create a secret.

Request:
```json
{
  "encrypted": "<base64url ciphertext>",
  "iv": "<base64url 12-byte IV>",
  "views": 1,
  "minutes": 1440
}
```

Constraints:
- `encrypted` — required, base64url-encoded, max 500KB decoded (configurable via `--max-secret-size`)
- `iv` — required, base64url-encoded, must decode to exactly 12 bytes
- `views` — 1-100 (default: 1)
- `minutes` — 1-43200 (default: 1440)

Response (201):
```json
{
  "id": "abc123",
  "expires_at": "2024-01-02T03:04:05Z",
  "delete_token": "def456"
}
```

Errors: 400 (validation), 415 (wrong Content-Type), 429 (rate limited)

### GET /api/secrets/{id}

Retrieve and consume a view. Returns the encrypted blob:

```json
{
  "encrypted": "<base64url ciphertext>",
  "iv": "<base64url IV>"
}
```

Errors: 400 (invalid ID format), 404 (expired, consumed, or nonexistent)

### GET /api/secrets/{id}/status

Check availability without consuming a view.

Response (200):
```json
{
  "status": "available"
}
```

Errors: 400 (invalid ID format), 404 (expired, consumed, or nonexistent)

### DELETE /api/secrets/{id}

Delete a secret. Requires `Authorization: Bearer {delete_token}` header.

Response: 204 No Content

Errors: 400 (invalid ID format), 401 (missing token), 404 (not found or wrong token)

### GET /health

Health check. Returns 200 with `{"status":"ok"}`, or 503 with `{"status":"error"}` if the database is unavailable.

### GET /s/{id}

Serves the web viewer HTML. The decryption key is in the URL fragment (`#key`) and never sent to the server.

## Security Model

- **Zero-knowledge**: The server stores only AES-256-GCM ciphertext. The decryption key lives in the URL fragment, which browsers never send to the server.
- **Client-side encryption**: All encryption and decryption happens locally — in the browser (Web Crypto API), CLI, or MCP server process. The zKettle HTTP server never sees plaintext.
- **Expiring**: Secrets auto-delete after the configured number of views or time limit.
- **Composable library**: When importing zKettle as a Go library, use `ExtraRoutes` and `Middleware` to extend the server with custom routes and middleware for any deployment.
- **CLI/MCP plaintext exposure**: When reading secrets via CLI (`zkettle read`) or MCP (`read_secret`), the decrypted plaintext appears in terminal output or the MCP tool result (which enters the AI agent's conversation context). To keep secrets out of terminal scrollback and agent logs, use `--clipboard` / `--file` (CLI) or the `clipboard` / `file` parameters (MCP). When creating secrets via MCP, use the `file` parameter to read content from a file, or `generate_secret` with `create=true` to generate and encrypt without exposing plaintext.

## Building

```bash
make build          # Build for current platform
make build-all      # Build for darwin/linux/windows amd64 + darwin/linux arm64
make install        # Build and install to $GOPATH/bin or /usr/local/bin
make test           # Run all tests
make clean          # Remove build artifacts
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).
