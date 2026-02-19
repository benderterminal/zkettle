package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterRejects(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Very low limit: 1 request per second, burst of 1
	limited := RateLimiter(1, 1)(handler)

	// First request should succeed
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	limited.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w.Code)
	}

	// Second request should be rate limited
	req = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	limited.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", w.Code)
	}
}

// --- CORS middleware tests (L-07) ---

func TestCORSNoConfig(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cors := CORSMiddleware(nil)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	cors.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no CORS header with empty config, got %q", got)
	}
}

func TestCORSMatchingOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cors := CORSMiddleware([]string{"https://example.com"})(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	cors.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("CORS origin: got %q, want %q", got, "https://example.com")
	}
}

func TestCORSNonMatchingOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cors := CORSMiddleware([]string{"https://example.com"})(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()
	cors.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no CORS header for non-matching origin, got %q", got)
	}
}

func TestCORSWildcard(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cors := CORSMiddleware([]string{"*"})(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://anything.com")
	w := httptest.NewRecorder()
	cors.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://anything.com" {
		t.Fatalf("wildcard CORS: got %q, want %q", got, "https://anything.com")
	}
}

func TestCORSPreflight(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cors := CORSMiddleware([]string{"https://example.com"})(handler)

	req := httptest.NewRequest("OPTIONS", "/api/secrets", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	cors.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("preflight missing Access-Control-Allow-Methods")
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("preflight missing Access-Control-Allow-Headers")
	}
}
