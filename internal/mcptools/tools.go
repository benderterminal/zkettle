package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/crypto"
	"github.com/taw/zkettle/internal/id"
	"github.com/taw/zkettle/internal/store"
)

// isPrivateIP returns true if the IP is in a private, loopback, or link-local range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// validateURLScheme checks that a URL uses http or https.
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
	Content string `json:"content" jsonschema:"The plaintext secret to encrypt and share. Maximum 500KB."`
	Views   int    `json:"views,omitempty" jsonschema:"Maximum number of views before the secret is permanently deleted. Default 1 (single-use). Range: 1-100."`
	Hours   int    `json:"hours,omitempty" jsonschema:"Hours until the secret expires and is permanently deleted regardless of remaining views. Default 24. Range: 1-720 (30 days)."`
}

type ReadSecretInput struct {
	URL string `json:"url" jsonschema:"The full zKettle secret URL including the decryption key in the fragment (#)."`
}

type RevokeSecretInput struct {
	ID          string `json:"id" jsonschema:"The secret ID to permanently delete."`
	DeleteToken string `json:"delete_token" jsonschema:"The delete token returned by create_secret when the secret was originally created. Required for authorization."`
}

type ListSecretsInput struct{}

const maxContentSize = 500 * 1024 // 500KB plaintext limit

// Options configures MCP tool behavior.
type Options struct {
	// AllowPrivateIPs disables SSRF protection for read_secret.
	// Only set to true in tests that use local httptest servers.
	AllowPrivateIPs bool
}

func RegisterTools(srv *mcp.Server, st *store.Store, baseURL *baseurl.BaseURL, opts ...Options) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	client := newSSRFSafeClient(30*time.Second, opt.AllowPrivateIPs)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_secret",
		Description: "Encrypt and store a secret that self-destructs after being viewed. Use this to share passwords, API keys, tokens, certificates, or other sensitive data via a one-time URL. The secret is encrypted client-side before storage — the server never sees the plaintext.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args CreateSecretInput) (*mcp.CallToolResult, any, error) {
		if args.Content == "" {
			return nil, nil, fmt.Errorf("content is required")
		}
		if len(args.Content) > maxContentSize {
			return nil, nil, fmt.Errorf("content exceeds %dKB limit", maxContentSize/1024)
		}

		views := args.Views
		if views == 0 {
			views = 1
		}
		if views < 1 || views > 100 {
			return nil, nil, fmt.Errorf("views must be 1-100")
		}
		hours := args.Hours
		if hours == 0 {
			hours = 24
		}
		if hours < 1 || hours > 720 {
			return nil, nil, fmt.Errorf("hours must be 1-720")
		}

		ciphertext, iv, key, err := crypto.Encrypt([]byte(args.Content))
		if err != nil {
			return nil, nil, fmt.Errorf("encrypting: %w", err)
		}

		secretID := id.Generate()
		deleteToken := id.Generate()
		expiresAt := time.Now().Add(time.Duration(hours) * time.Hour)

		if err := st.Create(secretID, ciphertext, iv, views, expiresAt, deleteToken); err != nil {
			return nil, nil, fmt.Errorf("storing secret: %w", err)
		}

		secretURL := fmt.Sprintf("%s/s/%s#%s", baseURL.Get(), secretID, crypto.EncodeKey(key))
		result := fmt.Sprintf("url: %s\ndelete_token: %s", secretURL, deleteToken)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_secret",
		Description: "Retrieve and decrypt a secret from a zKettle URL. WARNING: This consumes one view — if the secret has only 1 view remaining, it will be permanently deleted after this call. The URL must include the decryption key in the fragment (#).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ReadSecretInput) (*mcp.CallToolResult, any, error) {
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

		// HTTP GET to the target host (could be remote)
		apiURL := fmt.Sprintf("%s://%s/api/secrets/%s", u.Scheme, u.Host, secretID)
		resp, err := client.Get(apiURL)
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
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, nil, fmt.Errorf("decoding response: %w", err)
		}

		ciphertext, err := crypto.DecodeKey(data.Encrypted)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding ciphertext: %w", err)
		}
		ivBytes, err := crypto.DecodeKey(data.IV)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding iv: %w", err)
		}

		plaintext, err := crypto.Decrypt(ciphertext, ivBytes, key)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting: %w", err)
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(plaintext)}},
		}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "revoke_secret",
		Description: "Permanently delete a secret before it expires or is viewed. Requires the delete_token returned by create_secret. Use this to revoke access to a secret you created.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args RevokeSecretInput) (*mcp.CallToolResult, any, error) {
		if !id.Valid(args.ID) {
			return nil, nil, fmt.Errorf("invalid secret ID format")
		}
		if args.DeleteToken == "" {
			return nil, nil, fmt.Errorf("delete_token is required")
		}
		if err := st.Delete(args.ID, args.DeleteToken); err != nil {
			return nil, nil, fmt.Errorf("deleting secret: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "secret revoked"}},
		}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List all active secrets on this server (metadata only — no encrypted content or decryption keys). Only accessible via local MCP stdio transport; not exposed over the network.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ListSecretsInput) (*mcp.CallToolResult, any, error) {
		metas, err := st.List()
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
	})
}
