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
	"github.com/taw/zkettle/baseurl"
	"github.com/taw/zkettle/server"
	"github.com/taw/zkettle/store"
)

func callToolMayFail(t *testing.T, mcpSrv *mcp.Server, name string, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
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
	return result, err
}

func isToolError(result *mcp.CallToolResult, err error) bool {
	if err != nil {
		return true
	}
	return result != nil && result.IsError
}

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
	bu := baseurl.New("")
	cfg := server.Config{BaseURL: bu}
	srv := server.New(context.Background(), cfg, st, viewerFS)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	bu.Set(ts.URL)

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "zkettle-test",
		Version: "test",
	}, nil)

	RegisterTools(mcpSrv, st, bu, Options{AllowPrivateIPs: true})

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

// parseCreateResult extracts url and delete_token from the create_secret response.
func parseCreateResult(t *testing.T, result *mcp.CallToolResult) (url, deleteToken string) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("no content in result")
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "url: ") {
			url = strings.TrimPrefix(line, "url: ")
		}
		if strings.HasPrefix(line, "delete_token: ") {
			deleteToken = strings.TrimPrefix(line, "delete_token: ")
		}
	}
	return
}

func TestCreateSecretReturnURL(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)

	result := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "my secret data",
		"views":   1,
		"minutes": 1440,
	})

	url, deleteToken := parseCreateResult(t, result)
	if !strings.HasPrefix(url, baseURL+"/s/") {
		t.Fatalf("expected URL starting with %s/s/, got: %s", baseURL, url)
	}
	if !strings.Contains(url, "#") {
		t.Fatal("URL missing key fragment")
	}
	if deleteToken == "" {
		t.Fatal("missing delete_token in response")
	}
}

func TestReadSecretReturnsPlaintext(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	// Create a secret first
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "readable secret",
	})
	secretURL, _ := parseCreateResult(t, createResult)

	// Read it back
	readResult := callTool(t, mcpSrv, "read_secret", map[string]any{
		"url": secretURL,
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

	// Create a secret and extract its ID and delete token
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "to be revoked",
		"views":   5,
	})
	secretURL, deleteToken := parseCreateResult(t, createResult)
	// Extract ID from URL: baseURL/s/{id}#key
	idAndKey := strings.TrimPrefix(secretURL, baseURL+"/s/")
	id := strings.SplitN(idAndKey, "#", 2)[0]

	// Revoke it with the delete token
	revokeResult := callTool(t, mcpSrv, "revoke_secret", map[string]any{
		"id":           id,
		"delete_token": deleteToken,
	})
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

func TestReadSecretMissingKeyFragment(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "test"})
	secretURL, _ := parseCreateResult(t, createResult)
	noKey := strings.SplitN(secretURL, "#", 2)[0]
	_ = baseURL
	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{"url": noKey})
	if !isToolError(result, err) {
		t.Fatal("expected error for URL missing key fragment")
	}
}

func TestReadSecretInvalidKey(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "test"})
	secretURL, _ := parseCreateResult(t, createResult)
	badURL := strings.SplitN(secretURL, "#", 2)[0] + "#notbase64!!!"
	_ = baseURL
	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{"url": badURL})
	if !isToolError(result, err) {
		t.Fatal("expected error for invalid key in URL")
	}
}

func TestReadSecretConsumed(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "once only"})
	secretURL, _ := parseCreateResult(t, createResult)
	// First read succeeds
	callTool(t, mcpSrv, "read_secret", map[string]any{"url": secretURL})
	// Second read should fail
	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{"url": secretURL})
	if !isToolError(result, err) {
		t.Fatal("expected error for consumed secret")
	}
}

func TestCreateSecretEmptyContent(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	result, err := callToolMayFail(t, mcpSrv, "create_secret", map[string]any{"content": ""})
	if !isToolError(result, err) {
		t.Fatal("expected error for empty content")
	}
}

func TestCreateSecretOversized(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	bigContent := strings.Repeat("a", 500*1024+1)
	result, err := callToolMayFail(t, mcpSrv, "create_secret", map[string]any{"content": bigContent})
	if !isToolError(result, err) {
		t.Fatal("expected error for oversized content")
	}
}

func TestCreateSecretDefaultViews(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "one view"})
	secretURL, _ := parseCreateResult(t, createResult)
	callTool(t, mcpSrv, "read_secret", map[string]any{"url": secretURL})
	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{"url": secretURL})
	if !isToolError(result, err) {
		t.Fatal("expected error on second read with default 1 view")
	}
}

func TestRevokeSecretWrongToken(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "test", "views": 5})
	secretURL, _ := parseCreateResult(t, createResult)
	idAndKey := strings.TrimPrefix(secretURL, baseURL+"/s/")
	secretID := strings.SplitN(idAndKey, "#", 2)[0]
	result, err := callToolMayFail(t, mcpSrv, "revoke_secret", map[string]any{
		"id":           secretID,
		"delete_token": "wrong-token",
	})
	if !isToolError(result, err) {
		t.Fatal("expected error for wrong delete token")
	}
}

func TestRevokeSecretNonexistent(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	result, err := callToolMayFail(t, mcpSrv, "revoke_secret", map[string]any{
		"id":           "aa000000000000000000000000000099",
		"delete_token": "any-token",
	})
	if !isToolError(result, err) {
		t.Fatal("expected error for nonexistent secret")
	}
}

func TestGenerateSecretDefaults(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	result := callTool(t, mcpSrv, "generate_secret", map[string]any{})
	text := result.Content[0].(*mcp.TextContent).Text
	if len(text) != 32 {
		t.Fatalf("expected 32 char default, got %d: %q", len(text), text)
	}
}

func TestGenerateSecretHexCharset(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	result := callTool(t, mcpSrv, "generate_secret", map[string]any{"charset": "hex"})
	text := result.Content[0].(*mcp.TextContent).Text
	for _, c := range text {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hex charset produced non-hex char: %c in %q", c, text)
		}
	}
}

func TestGenerateSecretCreateMode(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)
	result := callTool(t, mcpSrv, "generate_secret", map[string]any{"create": true})
	url, deleteToken := parseCreateResult(t, result)
	if !strings.HasPrefix(url, baseURL+"/s/") {
		t.Fatalf("expected URL starting with %s/s/, got: %s", baseURL, url)
	}
	if deleteToken == "" {
		t.Fatal("missing delete_token in create mode")
	}
}

func TestGenerateSecretRandomness(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	r1 := callTool(t, mcpSrv, "generate_secret", map[string]any{})
	r2 := callTool(t, mcpSrv, "generate_secret", map[string]any{})
	t1 := r1.Content[0].(*mcp.TextContent).Text
	t2 := r2.Content[0].(*mcp.TextContent).Text
	if t1 == t2 {
		t.Fatal("two generate calls produced identical output")
	}
}
