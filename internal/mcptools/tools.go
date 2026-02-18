package mcptools

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/crypto"
	"github.com/taw/zkettle/internal/store"
)

type CreateSecretInput struct {
	Content string `json:"content" jsonschema:"the plaintext secret to encrypt"`
	Views   int    `json:"views,omitempty" jsonschema:"max views before expiry, default 1"`
	Hours   int    `json:"hours,omitempty" jsonschema:"hours until expiry, default 24"`
}

type ReadSecretInput struct {
	URL string `json:"url" jsonschema:"the full zKettle secret URL including the key fragment"`
}

type RevokeSecretInput struct {
	ID          string `json:"id" jsonschema:"the secret ID to revoke"`
	DeleteToken string `json:"delete_token" jsonschema:"the delete token returned when the secret was created"`
}

type ListSecretsInput struct{}

func RegisterTools(srv *mcp.Server, st *store.Store, baseURL *baseurl.BaseURL) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_secret",
		Description: "Encrypt and store a secret, returning an expiring URL",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args CreateSecretInput) (*mcp.CallToolResult, any, error) {
		views := args.Views
		if views == 0 {
			views = 1
		}
		hours := args.Hours
		if hours == 0 {
			hours = 24
		}

		ciphertext, iv, key, err := crypto.Encrypt([]byte(args.Content))
		if err != nil {
			return nil, nil, fmt.Errorf("encrypting: %w", err)
		}

		id := generateID()
		deleteToken := generateID()
		expiresAt := time.Now().Add(time.Duration(hours) * time.Hour)

		if err := st.Create(id, ciphertext, iv, views, expiresAt, deleteToken); err != nil {
			return nil, nil, fmt.Errorf("storing secret: %w", err)
		}

		secretURL := fmt.Sprintf("%s/s/%s#%s", baseURL.Get(), id, crypto.EncodeKey(key))
		result := fmt.Sprintf("url: %s\ndelete_token: %s", secretURL, deleteToken)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, nil, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_secret",
		Description: "Retrieve and decrypt a secret from a zKettle URL",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ReadSecretInput) (*mcp.CallToolResult, any, error) {
		u, err := url.Parse(args.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing URL: %w", err)
		}

		parts := strings.SplitN(u.Path, "/s/", 2)
		if len(parts) != 2 || parts[1] == "" {
			return nil, nil, fmt.Errorf("invalid secret URL")
		}
		id := parts[1]

		keyStr := u.Fragment
		if keyStr == "" {
			return nil, nil, fmt.Errorf("no decryption key in URL")
		}
		key, err := crypto.DecodeKey(keyStr)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding key: %w", err)
		}

		// HTTP GET to the target host (could be remote)
		apiURL := fmt.Sprintf("%s://%s/api/secrets/%s", u.Scheme, u.Host, id)
		resp, err := http.Get(apiURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching secret: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, nil, fmt.Errorf("secret not found (expired or already viewed)")
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
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
		Description: "Delete a secret by ID (requires the delete_token from creation)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args RevokeSecretInput) (*mcp.CallToolResult, any, error) {
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
		Description: "List all active secrets (metadata only, no content)",
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

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}
