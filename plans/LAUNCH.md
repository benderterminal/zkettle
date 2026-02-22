# zKettle Launch Roadmap

Stripped-down build plan for a go-to-market product that "just works." 21 tasks across 3 phases. Post-launch backlog is tracked in the "What Comes Next" section below.

## What Ships

A self-destructing secret sharing tool with:
- Web UI to create secrets (textarea, options, one click)
- Landing page explaining what it is
- Polished viewer (loading state, availability pre-check, clipboard auto-clear)
- GitHub releases with pre-built binaries for easy agent/developer install
- MCP server for AI agent integration (existing, just needs docs)

## What Doesn't Ship

- Authentication / recipient gating — URL sharing model works without it; scaffolding was explored and intentionally removed to keep the core focused
- On-chain policy contracts — web3 differentiator, not v1
- Blob architecture — alternative track, needs threat model first
- Prometheus metrics, structured logging — ops tooling for scale
- Client libraries (Python, Node) — developer ecosystem, post-launch
- Slack integration, x402 payment, agent-to-agent protocol — features for later
- Config file support — CLI flags work fine
- Per-IP rate limiting — global rate limiter already exists
- HSTS headers — reverse proxy handles this
- Docker — target users (devs/agents) can run a binary directly
- Homebrew formula — binary downloads are enough
- Most documentation — README + MCP guide covers launch

---

## Phase 1: Make It Usable

The product is currently CLI/API-only. Phase 1 adds the web experience.

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| L-01 | Web-based creation UI | — | New `/create` page: textarea for secret, dropdowns for max views (1/5/10/unlimited) and TTL (1h/24h/7d), client-side AES-256-GCM encryption via Web Crypto API, POST ciphertext to API, display shareable URL with key in fragment. Single HTML file, no build step. |
| L-02 | Landing page at root URL | — | Minimal page at `/` explaining zKettle in one sentence, "Create a Secret" button linking to `/create`, version in footer. Currently returns 404. |
| L-03 | Loading state and favicon | — | CSS spinner during fetch/decrypt on viewer page, inline SVG favicon via data URI (lock or kettle icon), `<noscript>` fallback message. |
| L-04 | Pre-check secret availability | — | HEAD or metadata endpoint (`GET /api/secrets/{id}/status`) returns 200/404/410 without consuming a view. Viewer calls this before showing "Reveal" button — prevents burning a view on an already-expired secret. |
| L-05 | Auto-clear clipboard after timeout | L-03 | After copy-to-clipboard, overwrite clipboard contents after 60 seconds. Countdown indicator near the copy button. "Keep in clipboard" checkbox to opt out. |
| L-06 | CORS middleware | — | Same-origin default. Configurable `--cors-origins` flag for allowed origins list. OPTIONS preflight handler. Required for web creation UI to POST to the API. |

**After Phase 1:** A non-technical user can visit the site, create a secret, copy the link, send it to someone, and the recipient can view and copy it. The core product loop works end-to-end in a browser.

---

## Phase 2: Make It Reliable

Test-first approach: write failing tests before every implementation change. Start by backfilling test gaps from Phase 1, then proceed with each fix as a red-green cycle.

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| L-07 | Backfill Phase 1 test coverage | — | **Tests only, no implementation changes.** Add tests for all Phase 1 code that shipped without coverage: `store.Status()` (available, not found, expired, consumed), `handleStatus` endpoint (200/404/410), `handleLanding` (200 + content), `handleCreatePage` (200 + content), `CORSMiddleware` (no-config passthrough, matching origin, non-matching origin, wildcard, OPTIONS preflight). Update `newTestServer` to include `index.html` and `create.html` in `fstest.MapFS`. |
| L-08 | Add expires_at index | — | **Test first:** add a store test that creates 1000 secrets with mixed expiry times, runs Cleanup(), and verifies only expired rows are removed. (This test passes before and after the index — it validates correctness, the index improves performance.) **Then implement:** `CREATE INDEX IF NOT EXISTS idx_expires ON secrets(expires_at)` in `store.go`. |
| L-09 | Replace polling cleanup with next-expiry timer | — | **Test first:** add a store test that creates a secret expiring in 1 second, waits 1.5 seconds, then calls `Status()` to verify the secret is reported as expired and the row is deleted from the database (not just inaccessible). Add a second test: create two secrets with different expiry times, verify each is deleted at its exact expiry (not batched on a polling interval). **Then implement:** replace the fixed-interval `time.NewTicker(1 * time.Hour)` cleanup goroutine in `store.go` with a next-expiry timer: query `SELECT MIN(expires_at) FROM secrets WHERE expires_at > unixepoch()` to find the nearest expiry, schedule a single `time.AfterFunc` for that moment, run `Cleanup()` when it fires, then reschedule for the next expiry. Reschedule on new secret creation if the new secret expires sooner than the current timer. On server restart, reconstruct the timer from the database. This eliminates the stale-ciphertext-on-disk window — secrets are deleted at exact expiry, not up to 60 seconds later. |
| L-10 | Extract shared generateID() | — | **Test first:** write `internal/id/id_test.go` — verify output is 32-char hex string, verify uniqueness across 1000 calls, verify no trailing `=` characters. **Then implement:** create `internal/id/id.go` with canonical `Generate()`, update `server.go` and `mcptools/tools.go` to import `id.Generate()`, delete both local `generateID()` functions. |
| L-11 | Secret ID format validation | L-10 | **Test first:** add server tests for `handleGet` and `handleDelete` with malformed IDs (empty, too short, non-hex chars, SQL injection attempts) — assert 400 response. **Then implement:** add hex format validation using the `internal/id` package's expected format. |
| L-12 | Content-Type enforcement on POST | — | **Test first:** add server test that POSTs to `/api/secrets` without `Content-Type` header and with `Content-Type: text/plain` — assert 415 response. Verify existing test with `application/json` still returns 201. **Then implement:** add Content-Type check at the top of `handleCreate`. |
| L-13 | Improve health endpoint | — | **Test first:** add `store.Ping()` test (success case with live DB, failure case after `Close()`). Add server test that health returns 200 with `{"status":"ok"}` normally. (503 case is hard to unit test without mocking — verify via integration tests.) **Then implement:** add `Ping()` method to store, update `handleHealth` to call it. |
| L-14 | Add graceful shutdown timeout | — | **Test first:** not directly unit-testable (requires signal handling). Add a test in `cmd/` that verifies `runServe` returns without hanging when the context is cancelled. **Then implement:** replace `context.Background()` with `context.WithTimeout(ctx, 10*time.Second)` in `cmd/serve.go` and `cmd/mcp.go`. |
| L-15 | Integration tests | L-07 | **Full end-to-end test suite.** New `integration_test.go` in `internal/server/`: start `httptest.Server` with real handler + in-memory store, exercise: (1) create → read → verify consumed (404 on second read), (2) create with views=3 → read 3 times → verify 404, (3) create → delete → verify 404, (4) create with 1s TTL → wait → verify status returns 410, (5) POST without Content-Type → 415, (6) GET with malformed ID → 400, (7) CORS headers with configured origins. All tests use the public HTTP API, no store internals. |

**After Phase 2:** Every feature has test coverage written before the implementation. Known bugs are fixed, expired secrets are cleaned up promptly, the server shuts down cleanly, and `go test -race ./...` validates the entire surface area.

---

## Phase 3: Make It Shippable

Package it for distribution and write the one doc that matters.

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| L-16 | GitHub Actions CI workflow | — | `.github/workflows/ci.yml`: `go vet ./...`, `go test -race ./...`, `go build` on push to main and on PRs. |
| L-17 | GitHub Actions release workflow | L-16 | Trigger on `v*` tag push. Cross-compile: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64. Create GitHub Release with binaries + SHA256 checksums. Agents install via `curl -L .../releases/latest/download/zkettle-{os}-{arch}`. |
| L-18 | Build metadata in version command | — | `go build -ldflags "-X main.version=... -X main.commit=... -X main.date=..."`. `zkettle version` shows all three. |
| L-19 | CSP nonce for inline scripts | — | Generate random nonce per request, set in `Content-Security-Policy` header, inject into `<script>` tags. Eliminate `unsafe-inline`. Table stakes for a security product — reviewers will flag this. |
| L-20 | MCP integration guide | — | `docs/mcp-guide.md`: how to add zKettle to Claude Desktop and Claude Code, all 4 tools with usage examples, common patterns (create-and-share, read-and-delete). The agent angle is a differentiator — it needs a clear onboarding doc. |
| L-21 | Agent skill file | — | Write `SKILL.md` in repo root: what zKettle is, when to use it, MCP setup snippet, tool reference, common agent patterns (credential rotation, temporary access), security guarantees, size limits. Uses the open SKILL.md standard compatible with Claude Code, Cursor, Codex CLI. Must ship with v0.1.0. |

**After Phase 3:** Tagged releases produce cross-platform binaries automatically. Agents and devs install with a single `curl` command. Security reviewers see CSP nonces. The MCP integration — zKettle's unique angle — has a dedicated guide. The agent skill file ships with the binary.

---

## Dependency Graph

```
L-03 ──> L-05
L-10 ──> L-11
L-07 ──> L-15
L-16 ──> L-17
```

4 dependency edges across 21 tasks. Within Phase 2, L-07 (backfill tests) must land first to establish the test baseline, and L-10 (extract generateID) must land before L-11 (ID validation).

---

## Verification

- **After Phase 1:** Open browser, create a secret via web UI, copy link, open in incognito, reveal secret, verify it's consumed. Test on mobile viewport.
- **After Phase 2:** `go test -race ./...` passes with full coverage of all API endpoints, store methods, and middleware. Every Phase 2 implementation change has a corresponding test that was written first (red) and passes after (green).
- **After Phase 3:** `git tag v0.1.0 && git push --tags` triggers release. Download binary from GitHub Releases, run it, verify version output.

---

## What Comes Next (Post-Launch Priorities)

Once the launch roadmap ships, the next priorities in order of impact:

1. **Structured logging + request logging (MO-01, SH-04)** — needed before real traffic
2. **Blob architecture (BL track)** — alternative storage model, gated by threat model
3. **Authentication (AU-01 through AU-08)** — recipient gating via wallet signatures, API keys, passwords (scaffolding was explored and removed; will be re-implemented via the `ExtraRoutes`/`Middleware` composability layer when needed)
4. **Hosted product + on-chain policy (HP-01 through HP-08)** — multi-tenant, on-chain access policy, pricing/billing (deferred pending strategic direction)

Everything else (client libs, Slack, x402, agent protocol, paranoid mode) is feature development driven by user demand.
