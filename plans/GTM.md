# zKettle v1.0.0 — Go-to-Market Plan

## Positioning

**Tagline:** encrypted. ephemeral. evaporated.

**One-liner:** Zero-knowledge encrypted secrets that boil away.

**Pitch:** zKettle is a self-hosted tool for sharing secrets (passwords, API keys, tokens, certificates) via one-time URLs. Secrets are encrypted client-side with AES-256-GCM before storage — the server never sees the plaintext or the key. Secrets auto-delete after a configurable number of views or time limit. It ships as a single Go binary with no external dependencies, and it's AI-native — agents can create, read, revoke, and audit secrets programmatically via MCP, CLI, or API.

**Key differentiators:**
- Zero-knowledge encryption (AES-256-GCM, key in URL fragment)
- Configurable burn (view limits + time-to-live)
- AI-native (MCP server with 5 tools, CLI, API, web UI)
- Runs anywhere (single binary, embedded SQLite, no external deps)
- Self-hosted (AGPL-3.0, full control over your data)

## Target Audiences (prioritized)

1. **Anyone sharing secrets** — the universal use case. Passwords, keys, tokens, sensitive config.
2. **AI agents & agent developers** — AI-native is the differentiator. Agents can manage secrets without human intervention.
3. **Developers & DevOps** — one binary, self-hosted, pipe-friendly CLI, Docker-ready.
4. **Security-conscious teams & enterprises** — zero-knowledge, AGPL, self-hosted, auditable.

## Launch Actions

### Pre-launch (before making repo public)
- [x] Module path fix (`github.com/benderterminal/zkettle`)
- [x] E2E testing (automated + manual — see plans/E2E-TESTING.md for checklist)
- [x] README with install instructions
- [x] SKILL.md updated for v1.0.0
- [ ] Deep review passing
- [ ] Full E2E re-test after deep review fixes

### Launch day
- [ ] Make repo public
- [ ] Tag v1.0.0, push — triggers release workflow (5 binaries + checksums)
- [ ] Post-release verification (`go install`, binary download, smoke test)
- [ ] Post tweet
- [ ] Submit SKILL.md to marketplaces

### Post-launch
- [ ] Show HN post
- [ ] GitHub Pages landing page (`benderterminal.github.io/zkettle`)
- [ ] Demo video

## Draft Tweet

```
zKettle — self-hosted zero-knowledge secret sharing.

AES-256-GCM encryption, one-time URLs, configurable burn.
Single binary. No dependencies. AI-native.

encrypted. ephemeral. evaporated.

github.com/benderterminal/zkettle
```

## Draft Show HN

**Title:** Show HN: zKettle – Self-hosted zero-knowledge secret sharing, AI-native

**Body:**

I built zKettle to share passwords, API keys, and tokens securely without trusting a third-party service.

How it works: secrets are encrypted client-side with AES-256-GCM. The server stores only ciphertext. The decryption key lives in the URL fragment (#), which browsers never send to the server. Secrets auto-delete after a configurable number of views or time limit.

It ships as a single binary with no external dependencies and runs anywhere — your laptop, a server, or a Docker container. There's a web UI, CLI, REST API, and an MCP server so any user, developer, or AI agent can manage secrets programmatically.

Self-hosted, AGPL-3.0.

https://github.com/benderterminal/zkettle

## SKILL.md Marketplace Submissions

After repo is public, submit to:

| Marketplace | Priority | URL |
|-------------|----------|-----|
| Anthropic Skills (official) | High | PR to github.com/anthropics/skills |
| MCP Market | High | mcpmarket.com |
| SkillsMP | High | skillsmp.com |
| Awesome MCP Servers | Medium | mcpservers.org |
| Claude Marketplaces | Medium | claudemarketplaces.com |
| awesome-mcp-servers GitHub lists | Medium | Search GitHub |

## Marketing Claims Verification

Every claim maps to implementation:

| Claim | Verified | Source |
|-------|----------|--------|
| Zero-knowledge | Yes | Key in URL fragment, server stores only ciphertext |
| AES-256-GCM | Yes | `internal/crypto/` uses Go stdlib `crypto/aes` + `cipher.NewGCM` |
| Self-destructing / boil away | Yes | View counting + time expiry in `store/store.go` |
| One binary | Yes | Go binary with `//go:embed web` |
| AI-native | Yes | `cmd/mcp.go` + `internal/mcptools/tools.go` (5 tools) |
| No external dependencies | Yes | SQLite via `modernc.org/sqlite` (pure Go, no CGO) |
| encrypted. ephemeral. evaporated. | Yes | AES-256-GCM encryption, time/view expiry, auto-deletion |
