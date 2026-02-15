package mcptools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
)

// setupTestEnv creates a store, MCP server, and HTTP test server.
// Returns the MCP server, a function to call tools, and a cleanup function.
func setupTestEnv(t *testing.T) (*mcp.Server, *store.Store, string) {
	t.Helper()

	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Start a real HTTP test server so read_secret can make HTTP calls
	viewerFS := fstest.MapFS{
		"viewer.html": &fstest.MapFile{Data: []byte("<html>test</html>")},
	}
	cfg := server.Config{}
	srv := server.New(cfg, st, viewerFS)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "zkettle-test",
		Version: "test",
	}, nil)

	RegisterTools(mcpSrv, st, ts.URL)

	return mcpSrv, st, ts.URL
}

func callTool(t *testing.T, mcpSrv *mcp.Server, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	// Use in-memory transport to call the tool
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()

	ss, err := mcpSrv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCreateSecretReturnURL(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)

	result := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "my secret data",
		"views":   1,
		"hours":   24,
	})

	if len(result.Content) == 0 {
		t.Fatal("no content in result")
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.HasPrefix(text, baseURL+"/s/") {
		t.Fatalf("expected URL starting with %s/s/, got: %s", baseURL, text)
	}
	if !strings.Contains(text, "#") {
		t.Fatal("URL missing key fragment")
	}
}

func TestReadSecretReturnsPlaintext(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	// Create a secret first
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "readable secret",
	})
	url := createResult.Content[0].(*mcp.TextContent).Text

	// Read it back
	readResult := callTool(t, mcpSrv, "read_secret", map[string]any{
		"url": url,
	})

	text := readResult.Content[0].(*mcp.TextContent).Text
	if text != "readable secret" {
		t.Fatalf("expected 'readable secret', got: %s", text)
	}
}

func TestListSecretsReturnsMetadata(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	// Create two secrets
	callTool(t, mcpSrv, "create_secret", map[string]any{"content": "secret1", "views": 3})
	callTool(t, mcpSrv, "create_secret", map[string]any{"content": "secret2"})

	result := callTool(t, mcpSrv, "list_secrets", map[string]any{})
	text := result.Content[0].(*mcp.TextContent).Text

	var metas []store.SecretMeta
	if err := json.Unmarshal([]byte(text), &metas); err != nil {
		t.Fatalf("failed to unmarshal list result: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(metas))
	}
}

func TestRevokeSecretDeletes(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)

	// Create a secret and extract its ID
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "to be revoked",
		"views":   5,
	})
	secretURL := createResult.Content[0].(*mcp.TextContent).Text
	// Extract ID from URL: baseURL/s/{id}#key
	idAndKey := strings.TrimPrefix(secretURL, baseURL+"/s/")
	id := strings.SplitN(idAndKey, "#", 2)[0]

	// Revoke it
	revokeResult := callTool(t, mcpSrv, "revoke_secret", map[string]any{"id": id})
	text := revokeResult.Content[0].(*mcp.TextContent).Text
	if text != "secret revoked" {
		t.Fatalf("expected 'secret revoked', got: %s", text)
	}

	// Verify it's gone via HTTP
	resp, err := http.Get(baseURL + "/api/secrets/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after revoke, got %d", resp.StatusCode)
	}
}
