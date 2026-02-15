package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/taw/zkettle/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	viewerFS := fstest.MapFS{
		"viewer.html": &fstest.MapFile{Data: []byte("<html>test viewer</html>")},
	}
	srv := New(Config{}, st, viewerFS)
	return srv, st
}

func TestPostCreateSecret(t *testing.T) {
	srv, _ := newTestServer(t)
	body := map[string]any{
		"encrypted": "dGVzdA",
		"iv":        "MTIzNDU2Nzg5MDEy",
		"views":     1,
		"hours":     24,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("POST /api/secrets: got %d, want %d. Body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Fatal("missing id in response")
	}
	if resp["expires_at"] == nil {
		t.Fatal("missing expires_at in response")
	}
}

func TestGetSecret(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create("get-1", []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest("GET", "/api/secrets/get-1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["encrypted"] == nil {
		t.Fatal("missing encrypted in response")
	}
	if resp["iv"] == nil {
		t.Fatal("missing iv in response")
	}
}

func TestSecondGetSingleViewReturns404(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create("sv-1", []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour))

	// First GET
	req := httptest.NewRequest("GET", "/api/secrets/sv-1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first GET: got %d, want 200", w.Code)
	}

	// Second GET
	req = httptest.NewRequest("GET", "/api/secrets/sv-1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second GET: got %d, want 404", w.Code)
	}
}

func TestGetNonexistentReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/secrets/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET nonexistent: got %d, want 404", w.Code)
	}
}

func TestDeleteReturns204(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create("del-1", []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour))

	req := httptest.NewRequest("DELETE", "/api/secrets/del-1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want 204", w.Code)
	}
}

func TestPostMissingFieldsReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	body := map[string]any{"views": 1}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST missing fields: got %d, want 400. Body: %s", w.Code, w.Body.String())
	}
}

func TestPostOversizedBodyReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	// Create a body larger than 1MB
	bigData := make([]byte, 1024*1024+1)
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(bigData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST oversized: got %d, want 400", w.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health: got %d, want 200", w.Code)
	}
}

func TestViewerHTML(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/s/some-id", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /s/{id}: got %d, want 200", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("test viewer")) {
		t.Fatalf("viewer response does not contain expected content")
	}
}
