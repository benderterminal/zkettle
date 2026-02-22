package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/benderterminal/zkettle/baseurl"
	"github.com/benderterminal/zkettle/server"
	"github.com/benderterminal/zkettle/store"
)

// testServer creates an httptest server with a real store and server handler.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	dbPath := t.TempDir() + "/test.db"
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	webFS := fstest.MapFS{
		"index.html":  {Data: []byte("<html>index</html>")},
		"create.html": {Data: []byte("<html>create</html>")},
		"viewer.html": {Data: []byte("<html>viewer</html>")},
	}
	var subFS fs.FS = webFS

	bu := baseurl.New("http://placeholder")
	cfg := server.Config{BaseURL: bu}
	srv := server.New(context.Background(), cfg, st, subFS)
	ts := httptest.NewServer(srv.Handler())
	bu.Set(ts.URL)
	t.Cleanup(ts.Close)
	return ts
}

// captureStdout replaces os.Stdout with a pipe, runs fn, and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

// captureStderr replaces os.Stderr with a pipe, runs fn, and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

// pipeStdin sets os.Stdin to read from the given string for the duration of fn.
func pipeStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	old := os.Stdin
	r, w, _ := os.Pipe()
	w.WriteString(input)
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = old }()
	fn()
}

func TestCLICreateReadRevoke(t *testing.T) {
	ts := testServer(t)

	// Create a secret
	var createOut string
	var createErr string
	pipeStdin(t, "my test secret\n", func() {
		createErr = captureStderr(t, func() {
			createOut = captureStdout(t, func() {
				err := RunCreate([]string{"--server", ts.URL, "--views", "2", "--minutes", "60"})
				if err != nil {
					t.Fatalf("RunCreate: %v", err)
				}
			})
		})
	})

	secretURL := strings.TrimSpace(createOut)
	if !strings.Contains(secretURL, "/s/") || !strings.Contains(secretURL, "#") {
		t.Fatalf("unexpected create output: %q", secretURL)
	}

	// Stderr should contain expiry and revoke info
	if !strings.Contains(createErr, "expires:") {
		t.Errorf("stderr missing expires info: %q", createErr)
	}
	if !strings.Contains(createErr, "revoke:") {
		t.Errorf("stderr missing revoke info: %q", createErr)
	}

	// Read the secret
	var readOut string
	readOut = captureStdout(t, func() {
		err := RunRead([]string{secretURL})
		if err != nil {
			t.Fatalf("RunRead: %v", err)
		}
	})
	if strings.TrimSpace(readOut) != "my test secret" {
		t.Fatalf("RunRead output = %q, want %q", strings.TrimSpace(readOut), "my test secret")
	}

	// Extract ID and token from stderr for revoke
	// stderr format: "  revoke:  zkettle revoke --server URL --token TOKEN ID\n"
	var token, secretID string
	for _, line := range strings.Split(createErr, "\n") {
		if strings.Contains(line, "revoke:") {
			parts := strings.Fields(line)
			// ... --token TOKEN ID
			for i, p := range parts {
				if p == "--token" && i+1 < len(parts) {
					token = parts[i+1]
				}
			}
			if len(parts) > 0 {
				secretID = parts[len(parts)-1]
			}
		}
	}
	if token == "" || secretID == "" {
		t.Fatalf("could not parse token/ID from stderr: %q", createErr)
	}

	// Revoke the secret
	var revokeOut string
	revokeOut = captureStdout(t, func() {
		err := RunRevoke([]string{"--server", ts.URL, "--token", token, secretID})
		if err != nil {
			t.Fatalf("RunRevoke: %v", err)
		}
	})
	if !strings.Contains(revokeOut, "revoked") {
		t.Errorf("RunRevoke output = %q, want 'revoked'", revokeOut)
	}

	// Reading again should fail
	err := RunRead([]string{secretURL})
	if err == nil {
		t.Fatal("expected error reading revoked secret, got nil")
	}
}

func TestCLICreateJSON(t *testing.T) {
	ts := testServer(t)

	var createOut string
	pipeStdin(t, "json test secret\n", func() {
		captureStderr(t, func() {
			createOut = captureStdout(t, func() {
				err := RunCreate([]string{"--server", ts.URL, "--json"})
				if err != nil {
					t.Fatalf("RunCreate --json: %v", err)
				}
			})
		})
	})

	var result map[string]string
	if err := json.Unmarshal([]byte(createOut), &result); err != nil {
		t.Fatalf("JSON parse error: %v\noutput: %q", err, createOut)
	}
	for _, key := range []string{"url", "id", "delete_token", "expires_at"} {
		if result[key] == "" {
			t.Errorf("JSON missing key %q", key)
		}
	}
}

func TestCLICreateQuiet(t *testing.T) {
	ts := testServer(t)

	var stderrOut string
	pipeStdin(t, "quiet test secret\n", func() {
		stderrOut = captureStderr(t, func() {
			captureStdout(t, func() {
				err := RunCreate([]string{"--server", ts.URL, "-q"})
				if err != nil {
					t.Fatalf("RunCreate -q: %v", err)
				}
			})
		})
	})

	if strings.Contains(stderrOut, "expires:") || strings.Contains(stderrOut, "revoke:") {
		t.Errorf("quiet mode should suppress stderr metadata, got: %q", stderrOut)
	}
}

func TestCLICreateEmptyInput(t *testing.T) {
	pipeStdin(t, "", func() {
		err := RunCreate([]string{"--server", "http://localhost:9999"})
		if err == nil {
			t.Fatal("expected error for empty input")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("error should mention 'empty', got: %v", err)
		}
	})
}

func TestCLICreatePositionalArg(t *testing.T) {
	err := RunCreate([]string{"--server", "http://localhost:9999", "my-secret"})
	if err == nil {
		t.Fatal("expected error for positional arg")
	}
	if !strings.Contains(err.Error(), "process lists") {
		t.Errorf("error should mention process lists, got: %v", err)
	}
}

func TestCLIRevokeInvalidToken(t *testing.T) {
	ts := testServer(t)

	// First create a secret so there's something to revoke
	var createErr string
	pipeStdin(t, "revoke test\n", func() {
		createErr = captureStderr(t, func() {
			captureStdout(t, func() {
				err := RunCreate([]string{"--server", ts.URL})
				if err != nil {
					t.Fatalf("RunCreate: %v", err)
				}
			})
		})
	})

	// Extract the secret ID
	var secretID string
	for _, line := range strings.Split(createErr, "\n") {
		if strings.Contains(line, "revoke:") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				secretID = parts[len(parts)-1]
			}
		}
	}
	if secretID == "" {
		t.Fatal("could not extract secret ID")
	}

	// Try to revoke with wrong token
	err := RunRevoke([]string{"--server", ts.URL, "--token", "wrong-token-value-here-00000000", secretID})
	if err == nil {
		t.Fatal("expected error revoking with wrong token")
	}
}
