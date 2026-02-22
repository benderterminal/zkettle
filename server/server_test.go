package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/taw/zkettle/store"
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
	srv := New(context.Background(), cfg, st, viewerFS)
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

// --- Composability extension point tests (L12-01) ---

func TestNewWithZeroValueConfig(t *testing.T) {
	// Zero-value Config has nil ExtraRoutes and nil Middleware.
	// Server should construct and behave identically to before the refactor.
	srv, st := newTestServer(t)

	// Core routes still work.
	st.Create(testID1, []byte("encrypted"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok")

	req := httptest.NewRequest("GET", "/api/secrets/"+testID1, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET with zero-value config: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	// Health endpoint works.
	req = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health with zero-value config: got %d, want 200", w.Code)
	}

	// Security headers still applied.
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options header with zero-value config")
	}
}

func TestExtraRoutesAddsCustomRoute(t *testing.T) {
	cfg := Config{
		ExtraRoutes: func(mux *http.ServeMux) {
			mux.HandleFunc("GET /custom", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("custom-route"))
			})
		},
	}
	srv, _ := newTestServerWithConfig(t, cfg)

	// Custom route is reachable.
	req := httptest.NewRequest("GET", "/custom", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /custom: got %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != "custom-route" {
		t.Fatalf("GET /custom body: got %q, want %q", got, "custom-route")
	}

	// Core routes still work alongside custom route.
	req = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health with ExtraRoutes: got %d, want 200", w.Code)
	}
}

func TestMiddlewareWrapsHandler(t *testing.T) {
	var order []string

	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1-before")
			w.Header().Set("X-Mw1", "applied")
			next.ServeHTTP(w, r)
			order = append(order, "mw1-after")
		})
	}
	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2-before")
			w.Header().Set("X-Mw2", "applied")
			next.ServeHTTP(w, r)
			order = append(order, "mw2-after")
		})
	}

	cfg := Config{
		Middleware: []func(http.Handler) http.Handler{mw1, mw2},
	}
	srv, _ := newTestServerWithConfig(t, cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /health with middleware: got %d, want 200", w.Code)
	}

	// Both middleware headers should be present.
	if got := w.Header().Get("X-Mw1"); got != "applied" {
		t.Fatalf("X-Mw1 header: got %q, want %q", got, "applied")
	}
	if got := w.Header().Get("X-Mw2"); got != "applied" {
		t.Fatalf("X-Mw2 header: got %q, want %q", got, "applied")
	}

	// Security headers still present (middleware wraps, not replaces).
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing when middleware is applied")
	}

	// Middleware applied in slice order: mw1 wraps first, then mw2 wraps mw1.
	// Last in slice = outermost. So mw2 executes first (outermost).
	// Execution order: mw2-before, mw1-before, handler, mw1-after, mw2-after
	expected := []string{"mw2-before", "mw1-before", "mw1-after", "mw2-after"}
	if len(order) != len(expected) {
		t.Fatalf("middleware execution order: got %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Fatalf("middleware execution order[%d]: got %q, want %q (full: %v)", i, order[i], v, order)
		}
	}
}

// --- Admin endpoint tests ---

func TestAdminListDisabledWithoutToken(t *testing.T) {
	srv, _ := newTestServer(t) // no AdminToken set
	req := httptest.NewRequest("GET", "/api/admin/secrets", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin endpoint without token config: got %d, want 404", w.Code)
	}
}

func TestAdminListUnauthorized(t *testing.T) {
	srv, _ := newTestServerWithConfig(t, Config{AdminToken: "test-token"})

	// No auth header
	req := httptest.NewRequest("GET", "/api/admin/secrets", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("admin no auth: got %d, want 401", w.Code)
	}

	// Wrong token
	req = httptest.NewRequest("GET", "/api/admin/secrets", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("admin wrong token: got %d, want 401", w.Code)
	}
}

func TestAdminListSuccess(t *testing.T) {
	srv, st := newTestServerWithConfig(t, Config{AdminToken: "test-token"})

	// Create a secret
	st.Create("aa000000000000000000000000000010", []byte("enc"), []byte("123456789012"), 3, time.Now().Add(1*time.Hour), "tok")

	req := httptest.NewRequest("GET", "/api/admin/secrets", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin list: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var secrets []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &secrets); err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0]["id"] != "aa000000000000000000000000000010" {
		t.Fatalf("unexpected id: %v", secrets[0]["id"])
	}
	// Verify no encrypted content is exposed
	if _, ok := secrets[0]["encrypted"]; ok {
		t.Fatal("admin endpoint should not expose encrypted content")
	}
}

// --- Metrics endpoint tests ---

func TestMetricsDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	// Without MetricsEnabled, the route is not registered — expect 404 or 405
	if w.Code == http.StatusOK {
		t.Fatal("metrics should not be enabled by default")
	}
}

func TestMetricsEnabled(t *testing.T) {
	srv, st := newTestServerWithConfig(t, Config{MetricsEnabled: true, AdminToken: "test-admin-token1"})

	st.Create("aa000000000000000000000000000011", []byte("enc"), []byte("123456789012"), 1, time.Now().Add(1*time.Hour), "tok")

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer test-admin-token1")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: got %d, want 200. Body: %s", w.Code, w.Body.String())
	}

	var metrics map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics["zkettle_secrets_active"] != 1 {
		t.Fatalf("expected 1 active secret, got %d", metrics["zkettle_secrets_active"])
	}
}

func TestMetricsRequiresAuth(t *testing.T) {
	srv, _ := newTestServerWithConfig(t, Config{MetricsEnabled: true, AdminToken: "test-admin-token1"})

	// No auth header
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("metrics no auth: got %d, want 401", w.Code)
	}

	// Wrong token
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token-here")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("metrics wrong token: got %d, want 401", w.Code)
	}
}

func TestMetricsReturns404WithoutAdminToken(t *testing.T) {
	srv, _ := newTestServerWithConfig(t, Config{MetricsEnabled: true})

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("metrics without admin token config: got %d, want 404", w.Code)
	}
}
