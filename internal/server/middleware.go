package server

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RateLimiter returns middleware that limits requests globally.
// rps is requests per second, burst is the maximum burst size.
func RateLimiter(rps float64, burst int) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware returns middleware that sets CORS headers for the given origins.
// If origins is empty, no CORS headers are set (same-origin only).
func CORSMiddleware(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) > 0 {
				origin := r.Header.Get("Origin")
				if allowed["*"] || allowed[origin] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
					w.Header().Set("Access-Control-Max-Age", "86400")
				}
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
