# zKettle v1.0.0 — E2E Testing Checklist

## Build & Unit Tests (automated)

- [ ] `go test -race ./...` — all pass
- [ ] `go vet ./...` — clean
- [ ] `go build -o dist/zkettle .` — builds successfully
- [ ] Cross-platform build: `make build-all` — all 5 binaries compile
- [ ] `./dist/zkettle version` — shows version info

## CLI E2E (automated)

Start server: `./dist/zkettle serve --port 3333 --data /tmp/zkettle-e2e`

- [ ] CLI create: `echo "test secret" | ./dist/zkettle create --server http://localhost:3333 --views 1 --minutes 5`
- [ ] CLI read: `./dist/zkettle read "<url-from-create>"` — verify plaintext matches
- [ ] Verify consumed: second read returns error
- [ ] CLI create with multiple views: `--views 3` — read 3 times, verify 4th fails
- [ ] CLI revoke: create, then `./dist/zkettle revoke --server http://localhost:3333 --token <token> <id>` — verify success message
- [ ] CLI generate: `./dist/zkettle generate` — outputs random string (32 chars, no newline)
- [ ] CLI generate with options: `./dist/zkettle generate --length 64 --charset hex` — verify hex output
- [ ] Pipeline: `./dist/zkettle generate | ./dist/zkettle create --server http://localhost:3333` — verify URL returned
- [ ] CLI list (with admin token): start server with `ZKETTLE_ADMIN_TOKEN=test`, create a secret, then `./dist/zkettle list --server http://localhost:3333 --admin-token test` — verify metadata returned
- [ ] CLI create `--json` flag: verify JSON output format with url, id, delete_token, expires_at

## API E2E (automated)

- [ ] Health endpoint: `curl http://localhost:3333/health` — 200 `{"status":"ok"}`
- [ ] Create secret via API: POST /api/secrets with valid JSON — 201
- [ ] Status endpoint: `GET /api/secrets/<id>/status` — 200 `{"status":"available"}`
- [ ] Status after consumed: returns 404
- [ ] Metrics endpoint: start server with `ZKETTLE_ADMIN_TOKEN=test --metrics`, `curl -H "Authorization: Bearer test" http://localhost:3333/metrics` — returns JSON metrics
- [ ] Metrics without auth: returns 401
- [ ] Admin list endpoint: `curl -H "Authorization: Bearer test" http://localhost:3333/api/admin/secrets` — returns array
- [ ] POST /api/secrets without Content-Type: returns 415
- [ ] GET /api/secrets/invalid-id: returns 400
- [ ] DELETE /api/secrets/<id> with wrong token: returns 403
- [ ] CORS: verify headers present when `--cors-origins` configured

## MCP E2E (automated)

Start MCP server: `./dist/zkettle mcp --port 3337` — verify it starts.

Test all 5 tools end-to-end:

- [ ] `create_secret`: create via MCP tool call, verify URL + delete_token returned
- [ ] `read_secret`: read the URL from create, verify plaintext matches original content
- [ ] `read_secret` consumed: read same URL again, verify error (expired or already viewed)
- [ ] `create_secret` with custom views/minutes: create with views=3, minutes=60, read 3 times, verify 4th fails
- [ ] `revoke_secret`: create a secret, revoke with ID + delete_token, verify read fails after revoke
- [ ] `revoke_secret` wrong token: verify error
- [ ] `list_secrets`: create 2 secrets, call list, verify 2 items returned with metadata (no content/keys)
- [ ] `generate_secret`: call with defaults, verify 32-char alphanumeric output
- [ ] `generate_secret` with charset: call with `charset: "hex"`, verify hex-only output
- [ ] `generate_secret` with create=true: verify URL + delete_token returned, then read_secret to verify roundtrip
- [ ] `create_secret` empty content: verify error
- [ ] `create_secret` oversized content: verify error
- [ ] `read_secret` missing key fragment: verify error
- [ ] `read_secret` invalid key: verify error

## Configuration E2E (automated)

- [ ] Config file: create `zkettle.toml` with `port = 3334`, verify server starts on 3334
- [ ] Env var: `ZKETTLE_PORT=3335 ./dist/zkettle serve` — verify port 3335
- [ ] Precedence: config file says port=3334, env var says port=3335 — verify 3335 wins

## Docker E2E (automated)

- [ ] Docker build: `docker build -t zkettle-test .`
- [ ] Docker run: `docker run -d -p 3336:3000 zkettle-test` — verify health endpoint
- [ ] Docker create+read: create a secret via API against docker container, read it back

## Manual (user-assisted)

- [ ] Browser: open `http://localhost:3333/` — landing page loads, all content renders
- [ ] Browser: open `http://localhost:3333/create` — create page loads
- [ ] Browser: create a secret via web UI — get shareable URL
- [ ] Browser: open URL in incognito — click "Reveal Secret" — verify plaintext
- [ ] Browser: refresh same URL — verify "already viewed" message
- [ ] Browser: mobile viewport — verify responsive design
- [ ] Browser: copy button — verify clipboard works + auto-clear countdown
- [ ] Browser: generate button on create page — verify random secret fills textarea
- [ ] Cloudflare tunnel: `./dist/zkettle serve --tunnel` — verify public URL works (optional)
- [ ] TLS: test with `--tls-cert` and `--tls-key` if certs available (optional)
- [ ] MCP in Claude Code: add MCP config, verify `create_secret`, `read_secret`, `revoke_secret`, `list_secrets`, and `generate_secret` tools all work
