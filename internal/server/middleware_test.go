package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterRejects(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Very low limit: 1 request per second, burst of 1
	limited := RateLimiter(context.Background(), 1, 1)(handler)

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

// --- clientIP / proxy tests (S-2) ---

func TestClientIPNoProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	// trustProxy=false, should ignore XFF
	ip := clientIP(req, false)
	if ip == "1.2.3.4" {
		t.Fatalf("trustProxy=false should ignore X-Forwarded-For, got %q", ip)
	}
}

func TestClientIPWithProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	ip := clientIP(req, true)
	if ip != "1.2.3.4" {
		t.Fatalf("trustProxy=true: got %q, want %q", ip, "1.2.3.4")
	}
}

func TestClientIPXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	ip := clientIP(req, true)
	if ip != "5.6.7.8" {
		t.Fatalf("X-Real-Ip: got %q, want %q", ip, "5.6.7.8")
	}
}

func TestClientIPXFFPriority(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	ip := clientIP(req, true)
	if ip != "1.2.3.4" {
		t.Fatalf("XFF should take priority over X-Real-Ip: got %q", ip)
	}
}

func TestRateLimiterTrustProxy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	limited := RateLimiter(context.Background(), 1, 1, true)(handler)

	// Two requests from different XFF IPs should both succeed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	w1 := httptest.NewRecorder()
	limited.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "2.2.2.2")
	w2 := httptest.NewRecorder()
	limited.ServeHTTP(w2, req2)

	if w1.Code != 200 || w2.Code != 200 {
		t.Fatalf("different XFF IPs should not share rate limit: got %d, %d", w1.Code, w2.Code)
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
