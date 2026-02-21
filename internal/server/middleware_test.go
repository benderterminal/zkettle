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

	// Very low limit: 1 request per second, burst of 1 for both read and write
	limited := RateLimiter(context.Background(), 1, 1, 1, 1, false, 1)(handler)

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
	ip := clientIP(req, false, 1)
	if ip == "1.2.3.4" {
		t.Fatalf("trustProxy=false should ignore X-Forwarded-For, got %q", ip)
	}
}

func TestClientIPWithProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	// proxyDepth=1: take 1st-from-right (IP our trusted proxy saw)
	ip := clientIP(req, true, 1)
	if ip != "10.0.0.1" {
		t.Fatalf("trustProxy=true, depth=1: got %q, want %q", ip, "10.0.0.1")
	}
	// proxyDepth=2: take 2nd-from-right (real client behind two proxies)
	ip = clientIP(req, true, 2)
	if ip != "1.2.3.4" {
		t.Fatalf("trustProxy=true, depth=2: got %q, want %q", ip, "1.2.3.4")
	}
}

func TestClientIPXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	ip := clientIP(req, true, 1)
	if ip != "5.6.7.8" {
		t.Fatalf("X-Real-Ip: got %q, want %q", ip, "5.6.7.8")
	}
}

func TestClientIPXFFPriority(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	ip := clientIP(req, true, 1)
	if ip != "1.2.3.4" {
		t.Fatalf("XFF should take priority over X-Real-Ip: got %q", ip)
	}
}

func TestRateLimiterTrustProxy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	limited := RateLimiter(context.Background(), 1, 1, 1, 1, true, 1)(handler)

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

// --- Read/write rate limit differentiation (B3) ---

func TestRateLimiterReadWriteSplit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// readRPS=10, readBurst=10, writeRPS=1, writeBurst=1
	limited := RateLimiter(context.Background(), 10, 10, 1, 1, false, 1)(handler)

	// First POST should succeed
	req := httptest.NewRequest("POST", "/api/secrets", nil)
	w := httptest.NewRecorder()
	limited.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first POST: got %d, want 200", w.Code)
	}

	// Second POST should be rate limited (write burst = 1)
	req = httptest.NewRequest("POST", "/api/secrets", nil)
	w = httptest.NewRecorder()
	limited.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second POST: got %d, want 429", w.Code)
	}

	// GETs should still work (read burst = 10)
	for i := 0; i < 5; i++ {
		req = httptest.NewRequest("GET", "/api/secrets/test", nil)
		w = httptest.NewRecorder()
		limited.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET #%d: got %d, want 200", i+1, w.Code)
		}
	}
}

// --- X-Forwarded-For depth (B4) ---

func TestRequestLoggerSetsRequestID(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logged := RequestLogger(false, 1)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	logged.ServeHTTP(w, req)

	reqID := w.Header().Get("X-Request-Id")
	if reqID == "" {
		t.Fatal("expected X-Request-Id header to be set")
	}
	if len(reqID) != 8 {
		t.Fatalf("expected 8 hex chars, got %d chars: %q", len(reqID), reqID)
	}
}

func TestRequestLoggerUniqueIDs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logged := RequestLogger(false, 1)(handler)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		logged.ServeHTTP(w, req)
		id := w.Header().Get("X-Request-Id")
		if ids[id] {
			t.Fatalf("duplicate request ID after %d requests: %s", i, id)
		}
		ids[id] = true
	}
}

func TestClientIPProxyDepth(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		depth      int
		trustProxy bool
		want       string
	}{
		{"depth=1 single entry", "1.2.3.4", 1, true, "1.2.3.4"},
		{"depth=1 two entries", "spoofed, 1.2.3.4", 1, true, "1.2.3.4"},
		{"depth=2 two entries", "1.2.3.4, 10.0.0.1", 2, true, "1.2.3.4"},
		{"depth=1 three entries", "spoofed, real, proxy", 1, true, "proxy"},
		{"depth=2 three entries", "spoofed, real, proxy", 2, true, "real"},
		{"depth=3 three entries", "spoofed, real, proxy", 3, true, "spoofed"},
		{"no trust ignores xff", "1.2.3.4", 1, false, "192.0.2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tt.xff)
			got := clientIP(req, tt.trustProxy, tt.depth)
			if got != tt.want {
				t.Errorf("clientIP(xff=%q, trust=%v, depth=%d) = %q, want %q",
					tt.xff, tt.trustProxy, tt.depth, got, tt.want)
			}
		})
	}
}
