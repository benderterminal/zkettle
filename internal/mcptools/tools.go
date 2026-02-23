package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/benderterminal/zkettle/baseurl"
	"github.com/benderterminal/zkettle/internal/clipboard"
	"github.com/benderterminal/zkettle/internal/crypto"
	"github.com/benderterminal/zkettle/internal/generate"
	"github.com/benderterminal/zkettle/internal/limits"
	"github.com/benderterminal/zkettle/id"
	"github.com/benderterminal/zkettle/store"
)

// privateNetworks is parsed once at init; used by isPrivateIP.
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateNetworks = append(privateNetworks, network)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func validateURLScheme(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("only http and https schemes are allowed")
	}
	return u, nil
}

// validateFilePath rejects path traversal sequences and resolves the path to
// an absolute form. It does not check whether the file exists.
func validateFilePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path is empty")
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("file path must not contain '..' components")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving file path: %w", err)
	}
	return abs, nil
}

func validateViewsMinutes(views, minutes int) (int, int, error) {
	if views == 0 {
		views = limits.DefaultViews
	}
	if views < limits.MinViews || views > limits.MaxViews {
		return 0, 0, fmt.Errorf("views must be %d-%d", limits.MinViews, limits.MaxViews)
	}
	if minutes == 0 {
		minutes = limits.DefaultMinutes
	}
	if minutes < limits.MinMinutes || minutes > limits.MaxMinutes {
		return 0, 0, fmt.Errorf("minutes must be %d-%d (%d days)", limits.MinMinutes, limits.MaxMinutes, limits.MaxMinutes/1440)
	}
	return views, minutes, nil
}

// newSSRFSafeClient returns an HTTP client that prevents DNS rebinding attacks.
// DNS is resolved once, all IPs are validated as non-private, then the connection
// is made directly to the validated IP — eliminating the TOCTOU window between
// validation and connection that allows DNS rebinding.
func newSSRFSafeClient(timeout time.Duration, allowPrivate bool) *http.Client {
	if allowPrivate {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("resolving host %q: %w", host, err)
				}
				for _, ipAddr := range ips {
					if isPrivateIP(ipAddr.IP) {
						return nil, fmt.Errorf("requests to private/internal addresses are not allowed")
					}
				}
				var dialer net.Dialer
				for _, ipAddr := range ips {
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ipAddr.String(), port))
					if err == nil {
						return conn, nil
					}
				}
				return nil, fmt.Errorf("failed to connect to any resolved address for %s", host)
			},
		},
	}
}

type CreateSecretInput struct {
	Content string `json:"content,omitempty" jsonschema:"The plaintext secret to encrypt and share. WARNING: This content will be visible in the AI agent's conversation context. For maximum security, use the file parameter instead, or use generate_secret with create=true. Maximum 500KB."`
	File    string `json:"file,omitempty" jsonschema:"Read secret content from this file path instead of the content parameter. Keeps plaintext out of the agent conversation context. The file must be readable by the OS user running the zkettle process. Read once, not modified. Path traversal ('..') is rejected."`
	Views   int    `json:"views,omitempty" jsonschema:"Maximum number of views before the secret is permanently deleted. Default 1 (single-use). Range: 1-100. Use 1 for one-time passwords, higher values for shared team credentials."`
	Minutes int    `json:"minutes,omitempty" jsonschema:"Minutes until the secret expires and is permanently deleted regardless of remaining views. Default 1440 (24 hours). Range: 1-43200 (30 days). Use short TTLs for sensitive credentials."`
}

type ReadSecretInput struct {
	URL       string `json:"url" jsonschema:"The full zKettle secret URL including the decryption key in the fragment (#). Format: https://host/s/{id}#{key}. WARNING: Reading consumes one view -- if this is the last view the secret is permanently destroyed."`
	File      string `json:"file,omitempty" jsonschema:"Write decrypted secret to this file path (0600 permissions) instead of returning it in the response. Keeps plaintext out of the agent conversation context. Path traversal ('..') is rejected. Mutually exclusive with clipboard."`
	Clipboard bool   `json:"clipboard,omitempty" jsonschema:"Copy decrypted secret to system clipboard instead of returning it in the response. The user can then paste it where needed. No auto-clear. Mutually exclusive with file."`
}

type RevokeSecretInput struct {
	ID          string `json:"id" jsonschema:"The 32-character hex secret ID to permanently delete. Found in the URL path: /s/{id}"`
	DeleteToken string `json:"delete_token" jsonschema:"The delete token returned by create_secret. Required for authorization -- prevents unauthorized deletion."`
}

type ListSecretsInput struct{}

// maxContentSize is the plaintext size limit before encryption. Derived from
// limits.DefaultMaxSecretSize. The server's maxBodySize (1MB) accommodates
// this after base64 encoding + JSON overhead.
const maxContentSize = limits.DefaultMaxSecretSize

type GenerateSecretInput struct {
	Length  int    `json:"length,omitempty" jsonschema:"Length of generated secret in characters. Default 32. Range: 1-4096."`
	Charset string `json:"charset,omitempty" jsonschema:"Character set: alphanumeric (default), symbols, hex, base64url."`
	Create  bool   `json:"create,omitempty" jsonschema:"If true, encrypt and store the generated secret, returning URL + delete_token instead of raw text."`
	Views   int    `json:"views,omitempty" jsonschema:"When create=true, max views before deletion. Default 1."`
	Minutes int    `json:"minutes,omitempty" jsonschema:"When create=true, minutes until expiry. Default 1440 (24h)."`
}

// Options configures MCP tool behavior.
type Options struct {
	// AllowPrivateIPs disables SSRF protection for read_secret.
	// Only set to true in tests that use local httptest servers.
	AllowPrivateIPs bool
}

func isOwnServer(urlOrigin, base string) bool {
	if base == "" {
		return false
	}
	bu, err := url.Parse(base)
	if err != nil {
		return false
	}
	baseOrigin := fmt.Sprintf("%s://%s", bu.Scheme, bu.Host)
	return strings.EqualFold(urlOrigin, baseOrigin)
}

// toolSet holds shared dependencies for MCP tool handlers.
type toolSet struct {
	store   *store.Store
	baseURL *baseurl.BaseURL
	client  *http.Client
}

func (ts *toolSet) createSecret(_ context.Context, _ *mcp.CallToolRequest, args CreateSecretInput) (*mcp.CallToolResult, any, error) {
	hasContent := args.Content != ""
	hasFile := args.File != ""
	if hasContent && hasFile {
		return nil, nil, fmt.Errorf("provide either content or file, not both")
	}

	var plaintext []byte
	if hasFile {
		path, err := validateFilePath(args.File)
		if err != nil {
			return nil, nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading file: %w", err)
		}
		defer crypto.Zero(data)
		plaintext = data
	} else {
		plaintext = []byte(args.Content)
	}

	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("content is required (via content or file parameter)")
	}
	if len(plaintext) > maxContentSize {
		return nil, nil, fmt.Errorf("content exceeds %dKB limit", maxContentSize/1024)
	}

	views, minutes, err := validateViewsMinutes(args.Views, args.Minutes)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, iv, key, err := crypto.Encrypt(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting: %w", err)
	}

	secretID := id.Generate()
	deleteToken := id.Generate()
	expiresAt := time.Now().Add(time.Duration(minutes) * time.Minute)

	if err := ts.store.Create(secretID, ciphertext, iv, views, expiresAt, deleteToken); err != nil {
		return nil, nil, fmt.Errorf("storing secret: %w", err)
	}

	secretURL := fmt.Sprintf("%s/s/%s#%s", ts.baseURL.Get(), secretID, crypto.EncodeKey(key))
	result := fmt.Sprintf("url: %s\ndelete_token: %s", secretURL, deleteToken)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, nil, nil
}

func (ts *toolSet) readSecret(_ context.Context, _ *mcp.CallToolRequest, args ReadSecretInput) (*mcp.CallToolResult, any, error) {
	if args.File != "" && args.Clipboard {
		return nil, nil, fmt.Errorf("file and clipboard are mutually exclusive")
	}

	u, err := validateURLScheme(args.URL)
	if err != nil {
		return nil, nil, err
	}

	parts := strings.SplitN(u.Path, "/s/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil, nil, fmt.Errorf("invalid secret URL")
	}
	secretID := parts[1]
	if !id.Valid(secretID) {
		return nil, nil, fmt.Errorf("invalid secret ID format")
	}

	keyStr := u.Fragment
	if keyStr == "" {
		return nil, nil, fmt.Errorf("no decryption key in URL")
	}
	key, err := crypto.DecodeKey(keyStr)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding key: %w", err)
	}

	var encBytes, ivBytes []byte
	urlOrigin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	if isOwnServer(urlOrigin, ts.baseURL.Get()) {
		var storeErr error
		encBytes, ivBytes, storeErr = ts.store.Get(secretID)
		if storeErr != nil {
			return nil, nil, fmt.Errorf("secret not found (expired or already viewed)")
		}
	} else {
		apiURL := fmt.Sprintf("%s/api/secrets/%s", urlOrigin, secretID)
		resp, err := ts.client.Get(apiURL)
		if err != nil {
			if strings.Contains(err.Error(), "private/internal") {
				return nil, nil, fmt.Errorf("request blocked: cannot connect to private/internal addresses")
			}
			slog.Warn("read_secret fetch failed", "error", err, "host", u.Host)
			return nil, nil, fmt.Errorf("network error: could not connect to %s", u.Host)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, nil, fmt.Errorf("secret not found (expired or already viewed)")
		}
		if resp.StatusCode != http.StatusOK {
			slog.Warn("read_secret unexpected status", "status", resp.StatusCode, "host", u.Host)
			return nil, nil, fmt.Errorf("server returned unexpected status %d", resp.StatusCode)
		}

		var data struct {
			Encrypted string `json:"encrypted"`
			IV        string `json:"iv"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxContentSize*2)).Decode(&data); err != nil {
			return nil, nil, fmt.Errorf("decoding response: %w", err)
		}

		encBytes, err = crypto.DecodeKey(data.Encrypted)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding ciphertext: %w", err)
		}
		ivBytes, err = crypto.DecodeKey(data.IV)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding iv: %w", err)
		}
	}

	plaintext, err := crypto.Decrypt(encBytes, ivBytes, key)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting: %w", err)
	}
	defer crypto.Zero(plaintext)
	defer crypto.Zero(key)

	if args.File != "" {
		path, err := validateFilePath(args.File)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, plaintext, 0600); err != nil {
			return nil, nil, fmt.Errorf("writing to file: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Secret written to %s (0600 permissions)", path)}},
		}, nil, nil
	}

	if args.Clipboard {
		if err := clipboard.Write(plaintext); err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "Secret copied to clipboard."}},
		}, nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(plaintext)}},
	}, nil, nil
}

func (ts *toolSet) revokeSecret(_ context.Context, _ *mcp.CallToolRequest, args RevokeSecretInput) (*mcp.CallToolResult, any, error) {
	if !id.Valid(args.ID) {
		return nil, nil, fmt.Errorf("invalid secret ID format")
	}
	if args.DeleteToken == "" {
		return nil, nil, fmt.Errorf("delete_token is required")
	}
	if err := ts.store.Delete(args.ID, args.DeleteToken); err != nil {
		return nil, nil, fmt.Errorf("deleting secret: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "secret revoked"}},
	}, nil, nil
}

func (ts *toolSet) listSecrets(_ context.Context, _ *mcp.CallToolRequest, _ ListSecretsInput) (*mcp.CallToolResult, any, error) {
	metas, err := ts.store.List()
	if err != nil {
		return nil, nil, fmt.Errorf("listing secrets: %w", err)
	}
	b, err := json.MarshalIndent(metas, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func (ts *toolSet) generateSecret(_ context.Context, _ *mcp.CallToolRequest, args GenerateSecretInput) (*mcp.CallToolResult, any, error) {
	length := args.Length
	if length == 0 {
		length = 32
	}
	if length < 1 || length > 4096 {
		return nil, nil, fmt.Errorf("length must be 1-4096")
	}

	charsetName := args.Charset
	if charsetName == "" {
		charsetName = "alphanumeric"
	}
	var chars string
	switch charsetName {
	case "alphanumeric":
		chars = generate.Alphanumeric
	case "symbols":
		chars = generate.Symbols
	case "hex":
		chars = generate.Hex
	case "base64url":
		chars = generate.Base64URL
	default:
		return nil, nil, fmt.Errorf("unknown charset %q (use: alphanumeric, symbols, hex, base64url)", charsetName)
	}

	secret, err := generate.RandomString(length, chars)
	if err != nil {
		return nil, nil, fmt.Errorf("generating secret: %w", err)
	}

	if !args.Create {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: secret}},
		}, nil, nil
	}

	views, minutes, err := validateViewsMinutes(args.Views, args.Minutes)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, iv, key, err := crypto.Encrypt([]byte(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting: %w", err)
	}

	secretID := id.Generate()
	deleteToken := id.Generate()
	expiresAt := time.Now().Add(time.Duration(minutes) * time.Minute)

	if err := ts.store.Create(secretID, ciphertext, iv, views, expiresAt, deleteToken); err != nil {
		return nil, nil, fmt.Errorf("storing secret: %w", err)
	}

	secretURL := fmt.Sprintf("%s/s/%s#%s", ts.baseURL.Get(), secretID, crypto.EncodeKey(key))
	resultText := fmt.Sprintf("url: %s\ndelete_token: %s", secretURL, deleteToken)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: resultText}},
	}, nil, nil
}

func RegisterTools(srv *mcp.Server, st *store.Store, baseURL *baseurl.BaseURL, opts ...Options) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}

	ts := &toolSet{
		store:   st,
		baseURL: baseURL,
		client:  newSSRFSafeClient(30*time.Second, opt.AllowPrivateIPs),
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_secret",
		Description: "Encrypt and store a secret that self-destructs after being viewed. Use this to share passwords, API keys, tokens, certificates, or other sensitive data via a one-time URL. The secret is encrypted client-side before storage — the server never sees the plaintext. WARNING: When using the content parameter, the secret is visible in the AI agent's conversation context. For maximum security, use the file parameter to read from a file, or use generate_secret with create=true.",
	}, ts.createSecret)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_secret",
		Description: "Retrieve and decrypt a secret from a zKettle URL. WARNING: This consumes one view — if the secret has only 1 view remaining, it will be permanently deleted after this call. The URL must include the decryption key in the fragment (#). Use the file or clipboard parameters to keep the decrypted secret out of the agent conversation context.",
	}, ts.readSecret)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "revoke_secret",
		Description: "Permanently delete a secret before it expires or is viewed. Requires the delete_token returned by create_secret. Use this to revoke access to a secret you created.",
	}, ts.revokeSecret)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List all active secrets on this server (metadata only — no encrypted content or decryption keys). Only accessible via local MCP stdio transport; not exposed over the network.",
	}, ts.listSecrets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "generate_secret",
		Description: "Generate a cryptographically random secret (password, token, API key, or hex key). Optionally encrypt and store it as a self-destructing secret in one step. Uses crypto/rand — no network calls for generation. Recommended: use create=true to generate and encrypt in one step — the generated plaintext never appears in the response.",
	}, ts.generateSecret)
}
