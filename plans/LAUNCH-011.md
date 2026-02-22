# zKettle v0.1.1 — Hardening + DX Patch Release

v0.1.0 shipped with all 21 LAUNCH.md tasks complete: web UI, test-first hardening, CI/CD, release automation, CSP nonces, MCP guide, and SKILL.md. This plan covers a focused v0.1.1 patch: security hardening, code quality fixes, DX improvements, and a new feature (generate secret). Test-first approach throughout.

## What Ships

- Constant-time delete token comparison
- CSP without `style-src 'unsafe-inline'`
- Boolean flag handling fix in CLI
- MCP edge-case test coverage
- Store close/double-close test coverage
- Config file support (`zkettle.toml` + `ZKETTLE_*` env vars)
- Startup configuration logging
- `zkettle generate` command (CLI + MCP + web)
- Enhanced MCP tool descriptions

---

## Phase 1: Security Hardening

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| P1-01 | Constant-time delete token comparison | — | **Test first:** add benchmark test to `store_test.go` validating constant-time behavior. **Then implement:** replace `storedHash != hashToken(deleteToken)` in `store.go:190` with `subtle.ConstantTimeCompare` on raw hash bytes. Change `hashToken` to return `[]byte`, update `Delete` and `Create` to use raw bytes. |
| P1-02 | Eliminate `style-src 'unsafe-inline'` from CSP | — | **Test first:** add `server_test.go` test asserting CSP header on HTML pages does NOT contain `unsafe-inline` in `style-src`. **Then implement:** (1) add CSS utility classes (`.hidden`, `.text-error`, `.text-success`, `.text-muted`, `.byte-counter-wrap`, `.recent-row`, `.recent-info`, `.recent-btn-sm`, `.gone-note`), (2) replace all `el.style.x` in create.html JS with `classList` toggling, (3) replace inline style attributes in viewer.html with class names, (4) remove `'unsafe-inline'` from `style-src` in `server.go:319`. |

**After Phase 1:** `go test -race ./...` passes. CSP header on all HTML pages has no `unsafe-inline` in `style-src`. Browser test: create page, viewer page, and index page render correctly with no console CSP violations.

---

## Phase 2: Code Quality

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| P2-01 | Fix reorderFlags boolean flag handling | — | **Test first:** create `cmd/flags_test.go` — test `reorderFlags` with boolean flags (`--json`, `-q`, `--quiet`, `--tunnel`, `--trust-proxy`) to verify they don't consume the next positional arg. **Then implement:** maintain a set of known boolean flags; skip value consumption for them. |
| P2-02 | MCP edge-case tests | — | **Test only:** extend `mcptools_test.go` with: bad key fragment, invalid key, expired secret (1s TTL + wait), empty content, oversized content, views=0 default, revoke with wrong token, revoke nonexistent ID. |
| P2-03 | Store close/double-close tests | — | **Test only:** extend `store_test.go` — verify `Close()` is idempotent (double-close no panic), ops after `Close()` return errors (`Create`, `Get`, `List`, `Cleanup` after close). |
| P2-04 | Delete token wrong-auth test coverage | — | **Test first:** add `TestDeleteWrongToken` and `TestDeleteMissingSecret` to `store_test.go`. Verify existing coverage and add if missing. |

**After Phase 2:** `go test -race ./...` passes with new edge-case and close/double-close tests. `zkettle create --json "my secret"` correctly parses the `--json` boolean flag.

---

## Phase 3: DX Improvements

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| P3-01 | Config file support | — | New `internal/config/config.go` + tests. Support `zkettle.toml` config file + `ZKETTLE_*` env vars. Precedence: CLI flags > env vars > config file > defaults. Config fields: `port`, `host`, `data`, `base_url`, `cors_origins`, `trust_proxy`, `tunnel`. Search: `./zkettle.toml`, `$HOME/.config/zkettle/zkettle.toml`. Use `github.com/BurntSushi/toml`. |
| P3-02 | Startup configuration logging | P3-01 | **Test first:** verify `runServe` logs resolved config at startup. **Then implement:** log all resolved config at INFO level: port, host, data dir, base URL, CORS origins, trust-proxy, version. |

**After Phase 3:** `zkettle serve` with a `zkettle.toml` file respects config values. `ZKETTLE_PORT=4000 zkettle serve` uses port 4000. Startup log shows all resolved config. `go test -race ./...` passes.

---

## Phase 4: New Features

| ID | Title | Blocked By | Description |
|----|-------|------------|-------------|
| P4-01 | Generate secret — CLI | — | New `cmd/generate.go`: `zkettle generate [--length 32] [--charset alphanumeric\|symbols\|hex\|base64url]`. Outputs to stdout, can be piped: `zkettle generate \| zkettle create`. Uses `crypto/rand`. **Test first:** `cmd/generate_test.go` — default 32 chars alphanumeric, `--length 64` works, `--charset hex` hex-only, two calls differ, no trailing newline. |
| P4-02 | Generate secret — MCP | — | New `generate_secret` MCP tool in `tools.go`. Params: `length` (default 32), `charset` (default alphanumeric), `create` (bool, default false). When `create=true`: generates, creates secret, returns URL + delete_token. **Test first:** extend `mcptools_test.go`. |
| P4-03 | Generate secret — Web UI | — | "Generate" button on `/create` next to textarea. Uses `crypto.getRandomValues`. Options: password (mixed), token (alphanumeric), hex key. No automated test — manual browser verification. |
| P4-04 | Enhanced MCP tool descriptions | — | Improve `jsonschema` annotations on input structs with richer descriptions, examples, and constraints. Documentation-only change to struct tags and tool Description fields. |

**After Phase 4:** `zkettle generate` outputs a random secret. `zkettle generate | zkettle create` works end-to-end. MCP `generate_secret` tool works. `go test -race ./...` passes.

---

## Dependency Graph

```
P1-01 (no deps)
P1-02 (no deps)
P2-01 (no deps)
P2-02 (no deps)
P2-03 (no deps)
P2-04 (no deps)
P3-01 (no deps)
P3-02 ──> P3-01
P4-01 (no deps)
P4-02 (no deps)
P4-03 (no deps)
P4-04 (no deps)
```

Nearly flat — only P3-02 depends on P3-01. All phases can proceed in parallel within themselves.

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `plans/LAUNCH-011.md` | **Create** — this file |
| `internal/store/store.go` | Modify — constant-time comparison (P1-01) |
| `internal/store/store_test.go` | Modify — new tests (P1-01, P2-03, P2-04) |
| `web/create.html` | Modify — CSS class toggling (P1-02), generate button (P4-03) |
| `web/viewer.html` | Modify — remove inline style (P1-02) |
| `internal/server/server.go` | Modify — remove unsafe-inline from CSP (P1-02) |
| `internal/server/server_test.go` | Modify — CSP assertion test (P1-02) |
| `cmd/flags.go` | Modify — boolean flag handling (P2-01) |
| `cmd/flags_test.go` | **Create** — reorderFlags tests (P2-01) |
| `internal/mcptools/mcptools_test.go` | Modify — edge-case tests (P2-02), generate tests (P4-02) |
| `internal/config/config.go` | **Create** — config file + env var support (P3-01) |
| `internal/config/config_test.go` | **Create** — precedence tests (P3-01) |
| `cmd/serve.go` | Modify — config integration + startup logging (P3-01, P3-02) |
| `cmd/mcp.go` | Modify — config integration (P3-01) |
| `cmd/generate.go` | **Create** — generate command (P4-01) |
| `cmd/generate_test.go` | **Create** — generate tests (P4-01) |
| `main.go` | Modify — add generate command (P4-01) |
| `internal/mcptools/tools.go` | Modify — generate_secret tool + enhanced descriptions (P4-02, P4-04) |

---

## Verification

- **After Phase 1:** `go test -race ./...` passes. CSP header on all HTML pages has no `unsafe-inline` in `style-src`. Manual browser test: create page, viewer page, and index page all render correctly with no console CSP violations.
- **After Phase 2:** `go test -race ./...` passes with new edge-case and close/double-close tests. `zkettle create --json "my secret"` correctly parses the `--json` boolean flag.
- **After Phase 3:** `zkettle serve` with a `zkettle.toml` file respects config values. `ZKETTLE_PORT=4000 zkettle serve` uses port 4000. Startup log shows all resolved config. `go test -race ./...` passes.
- **After Phase 4:** `zkettle generate` outputs a random secret. `zkettle generate | zkettle create` works end-to-end. MCP `generate_secret` tool works in Claude Code. `go test -race ./...` passes.
- **Final:** Tag v0.1.1, push, verify release workflow produces binaries.
