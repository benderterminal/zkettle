package mcptools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/benderterminal/zkettle/baseurl"
	"github.com/benderterminal/zkettle/server"
	"github.com/benderterminal/zkettle/store"
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
	mcpSrv, _, _ := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "test"})
	secretURL, _ := parseCreateResult(t, createResult)
	noKey := strings.SplitN(secretURL, "#", 2)[0]
	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{"url": noKey})
	if !isToolError(result, err) {
		t.Fatal("expected error for URL missing key fragment")
	}
}

func TestReadSecretInvalidKey(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)
	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{"content": "test"})
	secretURL, _ := parseCreateResult(t, createResult)
	badURL := strings.SplitN(secretURL, "#", 2)[0] + "#notbase64!!!"
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

func TestReadSecretToFile(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "file-output-secret",
		"views":   1,
	})
	secretURL, _ := parseCreateResult(t, createResult)

	outPath := filepath.Join(t.TempDir(), "secret.txt")
	readResult := callTool(t, mcpSrv, "read_secret", map[string]any{
		"url":  secretURL,
		"file": outPath,
	})

	text := readResult.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, outPath) {
		t.Fatalf("expected file path in result, got: %s", text)
	}
	if !strings.Contains(text, "0600") {
		t.Fatalf("expected 0600 in result, got: %s", text)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(data) != "file-output-secret" {
		t.Fatalf("expected 'file-output-secret', got: %s", string(data))
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got: %o", info.Mode().Perm())
	}
}

func TestReadSecretToClipboard(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "clipboard-secret",
		"views":   1,
	})
	secretURL, _ := parseCreateResult(t, createResult)

	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{
		"url":       secretURL,
		"clipboard": true,
	})

	// On systems without a clipboard utility, this will error — that's expected.
	if err != nil || (result != nil && result.IsError) {
		t.Skip("clipboard not available in test environment")
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "clipboard") {
		t.Fatalf("expected clipboard confirmation, got: %s", text)
	}
}

func TestCreateSecretFromFile(t *testing.T) {
	mcpSrv, _, baseURL := setupTestEnv(t)

	// Write a secret to a file
	secretFile := filepath.Join(t.TempDir(), "input-secret.txt")
	if err := os.WriteFile(secretFile, []byte("secret-from-file"), 0600); err != nil {
		t.Fatal(err)
	}

	result := callTool(t, mcpSrv, "create_secret", map[string]any{
		"file": secretFile,
	})

	url, deleteToken := parseCreateResult(t, result)
	if !strings.HasPrefix(url, baseURL+"/s/") {
		t.Fatalf("expected URL starting with %s/s/, got: %s", baseURL, url)
	}
	if deleteToken == "" {
		t.Fatal("missing delete_token")
	}

	// Read the secret back to verify content
	readResult := callTool(t, mcpSrv, "read_secret", map[string]any{"url": url})
	text := readResult.Content[0].(*mcp.TextContent).Text
	if text != "secret-from-file" {
		t.Fatalf("expected 'secret-from-file', got: %s", text)
	}
}

func TestCreateSecretContentAndFileMutuallyExclusive(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	secretFile := filepath.Join(t.TempDir(), "conflict.txt")
	if err := os.WriteFile(secretFile, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := callToolMayFail(t, mcpSrv, "create_secret", map[string]any{
		"content": "inline",
		"file":    secretFile,
	})
	if !isToolError(result, err) {
		t.Fatal("expected error when both content and file are provided")
	}
}

func TestCreateSecretFromNonexistentFile(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	result, err := callToolMayFail(t, mcpSrv, "create_secret", map[string]any{
		"file": "/nonexistent/path/secret.txt",
	})
	if !isToolError(result, err) {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadSecretFileAndClipboardMutuallyExclusive(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "exclusive-test",
		"views":   2,
	})
	secretURL, _ := parseCreateResult(t, createResult)

	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{
		"url":       secretURL,
		"file":      "/tmp/out.txt",
		"clipboard": true,
	})
	if !isToolError(result, err) {
		t.Fatal("expected error when both file and clipboard are provided")
	}
}

func TestCreateSecretPathTraversal(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	result, err := callToolMayFail(t, mcpSrv, "create_secret", map[string]any{
		"file": "../../../etc/passwd",
	})
	if !isToolError(result, err) {
		t.Fatal("expected error for path traversal in file")
	}
}

func TestReadSecretPathTraversal(t *testing.T) {
	mcpSrv, _, _ := setupTestEnv(t)

	createResult := callTool(t, mcpSrv, "create_secret", map[string]any{
		"content": "path-traversal-test",
		"views":   1,
	})
	secretURL, _ := parseCreateResult(t, createResult)

	result, err := callToolMayFail(t, mcpSrv, "read_secret", map[string]any{
		"url":  secretURL,
		"file": "../../../tmp/evil.txt",
	})
	if !isToolError(result, err) {
		t.Fatal("expected error for path traversal in output file")
	}
}
