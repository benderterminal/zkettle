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
