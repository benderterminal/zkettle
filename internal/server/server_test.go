package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/taw/zkettle/internal/store"
)

// Valid 32-char hex IDs for tests
const (
	testID1      = "aa000000000000000000000000000001"
	testID2      = "aa000000000000000000000000000002"
	testIDDel    = "aa000000000000000000000000000003"
	testIDStat   = "aa000000000000000000000000000004"
	testIDStatEx = "aa000000000000000000000000000005"
	testIDNone   = "aa000000000000000000000000ffffff" // valid format, doesn't exist
)

func newTestServerWithConfig(t *testing.T, cfg Config) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	viewerFS := fstest.MapFS{
		"viewer.html": &fstest.MapFile{Data: []byte("<html><body>test viewer<script>console.log('ok')</script></body></html>")},
		"index.html":  &fstest.MapFile{Data: []byte("<html>zKettle landing</html>")},
		"create.html": &fstest.MapFile{Data: []byte("<html><body>create secret<script>console.log('ok')</script></body></html>")},
	}
	srv := New(cfg, st, viewerFS)
	return srv, st
}

func newTestServer(t *testing.T) (*Server, *store.Store) {
	return newTestServerWithConfig(t, Config{})
}

func TestPostCreateSecret(t *testing.T) {
	srv, _ := newTestServer(t)
	body := map[string]any{
		"encrypted": "dGVzdA",
		"iv":        "MTIzNDU2Nzg5MDEy",
		"views":     1,
		"minutes":   1440,
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
	st.Create(testID1, []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok")

	req := httptest.NewRequest("GET", "/api/secrets/"+testID1, nil)
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
	st.Create(testID1, []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok")

	// First GET
	req := httptest.NewRequest("GET", "/api/secrets/"+testID1, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first GET: got %d, want 200", w.Code)
	}

	// Second GET
	req = httptest.NewRequest("GET", "/api/secrets/"+testID1, nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second GET: got %d, want 404", w.Code)
	}
}

func TestGetNonexistentReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/secrets/"+testIDNone, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET nonexistent: got %d, want 404", w.Code)
	}
}

func TestDeleteReturns204(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create(testIDDel, []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "del-tok")

	// Without token should fail
	req := httptest.NewRequest("DELETE", "/api/secrets/"+testIDDel, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE without token: got %d, want 401", w.Code)
	}

	// With wrong token should fail with 403 (not 404)
	req = httptest.NewRequest("DELETE", "/api/secrets/"+testIDDel, nil)
	req.Header.Set("Authorization", "Bearer wrong-tok")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DELETE with wrong token: got %d, want 403", w.Code)
	}

	// With correct token should succeed
	req = httptest.NewRequest("DELETE", "/api/secrets/"+testIDDel, nil)
	req.Header.Set("Authorization", "Bearer del-tok")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE with correct token: got %d, want 204", w.Code)
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

// --- Phase 1 backfill tests (L-07) ---

func TestHandleStatusAvailable(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create(testIDStat, []byte("enc"), []byte("123456789012"), 3, time.Now().Add(1*time.Hour), "tok")

	req := httptest.NewRequest("GET", "/api/secrets/"+testIDStat+"/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status available: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"status":"available"`)) {
		t.Fatalf("expected available status, got: %s", w.Body.String())
	}
}

func TestHandleStatusNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/secrets/"+testIDNone+"/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status not found: got %d, want 404", w.Code)
	}
}

func TestHandleStatusExpired(t *testing.T) {
	srv, st := newTestServer(t)
	st.Create(testIDStatEx, []byte("enc"), []byte("123456789012"), 3, time.Now().Add(-1*time.Second), "tok")

	req := httptest.NewRequest("GET", "/api/secrets/"+testIDStatEx+"/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status expired: got %d, want 404", w.Code)
	}
}

func TestHandleLanding(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type: got %q, want text/html; charset=utf-8", ct)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("zKettle landing")) {
		t.Fatalf("landing page missing expected content, got: %s", w.Body.String())
	}
}

func TestGetMalformedIDReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	malformed := []string{
		"abc",                                // too short
		"xyz-not-hex-chars-here-padding1234", // non-hex chars, correct length
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  // non-hex chars, correct length
	}
	for _, id := range malformed {
		req := httptest.NewRequest("GET", "/api/secrets/"+id, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET /api/secrets/%q: got %d, want 400. Body: %s", id, w.Code, w.Body.String())
		}
	}
}

func TestDeleteMalformedIDReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	malformed := []string{
		"abc",                                // too short
		"xyz-not-hex-chars-here-padding1234", // non-hex chars, correct length
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  // non-hex chars, correct length
	}
	for _, id := range malformed {
		req := httptest.NewRequest("DELETE", "/api/secrets/"+id, nil)
		req.Header.Set("Authorization", "Bearer some-token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("DELETE /api/secrets/%q: got %d, want 400. Body: %s", id, w.Code, w.Body.String())
		}
	}
}

func TestPostWithoutContentTypeReturns415(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte(`{"encrypted":"dGVzdA","iv":"MTIzNDU2Nzg5MDEy","views":1,"minutes":1440}`)

	// No Content-Type header
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("POST without Content-Type: got %d, want 415. Body: %s", w.Code, w.Body.String())
	}

	// Wrong Content-Type
	req = httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("POST with text/plain: got %d, want 415. Body: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreatePage(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/create", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /create: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type: got %q, want text/html; charset=utf-8", ct)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("create secret")) {
		t.Fatalf("create page missing expected content, got: %s", w.Body.String())
	}
}

// --- CSP nonce tests (M-2) ---

func TestCSPNonceOnHTMLPages(t *testing.T) {
	srv, _ := newTestServer(t)

	// Pages with scripts should have nonce in CSP header and script tag
	for _, path := range []string{"/create", "/s/some-id"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		csp := w.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("GET %s: missing CSP header", path)
		}
		if !strings.Contains(csp, "nonce-") {
			t.Fatalf("GET %s: CSP missing nonce: %s", path, csp)
		}
		if strings.Contains(csp, "script-src 'unsafe-inline'") {
			t.Fatalf("GET %s: CSP script-src still contains unsafe-inline: %s", path, csp)
		}
		if !bytes.Contains(w.Body.Bytes(), []byte("script nonce=")) {
			t.Fatalf("GET %s: response body missing script nonce attribute", path)
		}
	}

	// Landing page (no scripts) should still get CSP but no script nonce in body
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("GET /: missing CSP header")
	}
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("GET /: CSP script-src still contains unsafe-inline: %s", csp)
	}

	// API endpoints should NOT have CSP
	req = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if csp := w.Header().Get("Content-Security-Policy"); csp != "" {
		t.Fatalf("GET /health: API endpoint should not have CSP, got: %s", csp)
	}
}

func TestCSPNonceUniquePerRequest(t *testing.T) {
	srv, _ := newTestServer(t)

	req1 := httptest.NewRequest("GET", "/create", nil)
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)

	req2 := httptest.NewRequest("GET", "/create", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	csp1 := w1.Header().Get("Content-Security-Policy")
	csp2 := w2.Header().Get("Content-Security-Policy")
	if csp1 == csp2 {
		t.Fatal("CSP nonces should be unique per request, but got identical headers")
	}
}

// --- HSTS tests (S-6, M-1) ---

func TestHSTSHeaderOnHTTPS(t *testing.T) {
	srv, _ := newTestServerWithConfig(t, Config{TrustProxy: true})

	// Simulate request behind HTTPS proxy with trust-proxy enabled
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("expected HSTS header for HTTPS request with trust-proxy, got none")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Fatalf("HSTS missing max-age: %s", hsts)
	}
}

func TestNoHSTSOnHTTP(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Fatalf("expected no HSTS header for HTTP request, got: %s", hsts)
	}
}

func TestNoHSTSWithoutTrustProxy(t *testing.T) {
	srv, _ := newTestServer(t) // TrustProxy defaults to false

	// X-Forwarded-Proto should be ignored when trust-proxy is disabled
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Fatalf("expected no HSTS when trust-proxy disabled, even with X-Forwarded-Proto, got: %s", hsts)
	}
}

func TestCSPContainsBaseURIAndFormAction(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/create", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "base-uri 'none'") {
		t.Fatalf("CSP missing base-uri 'none': %s", csp)
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("CSP missing form-action 'self': %s", csp)
	}
}

func TestCSPNoUnsafeInlineStyleSrc(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/", "/create", "/s/some-id"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		csp := w.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("GET %s: missing CSP header", path)
		}
		// Extract style-src directive
		for _, directive := range strings.Split(csp, ";") {
			directive = strings.TrimSpace(directive)
			if strings.HasPrefix(directive, "style-src") {
				if strings.Contains(directive, "'unsafe-inline'") {
					t.Fatalf("GET %s: style-src still contains 'unsafe-inline': %s", path, csp)
				}
			}
		}
	}
}

func TestCreateEndpointRateLimit(t *testing.T) {
	srv, _ := newTestServer(t)

	// The create limiter is 10 rps with burst 10.
	// Send 11 rapid requests — the 11th should be rate limited.
	body := []byte(`{"encrypted":"dGVzdA","iv":"MTIzNDU2Nzg5MDEy","views":1,"minutes":1440}`)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("request %d: got %d, want 201", i+1, w.Code)
		}
	}

	// 11th request should hit the create rate limit
	req := httptest.NewRequest("POST", "/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("11th request: got %d, want 429", w.Code)
	}
}
