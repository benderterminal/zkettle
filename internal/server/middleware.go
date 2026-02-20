package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipRateLimiter tracks per-IP rate limiters with automatic cleanup of stale entries.
type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipEntry
	rps      rate.Limit
	burst    int
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(ctx context.Context, rps float64, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*ipEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &ipEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()
	return entry.limiter.Allow()
}

func (rl *ipRateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, entry := range rl.limiters {
				if entry.lastSeen.Before(cutoff) {
					delete(rl.limiters, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// clientIP extracts the client IP address from a request.
// When trustProxy is true, X-Forwarded-For is consulted (leftmost entry).
// Otherwise, RemoteAddr is used directly.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For: client, proxy1, proxy2 — take the leftmost
			if i := strings.IndexByte(xff, ','); i > 0 {
				xff = xff[:i]
			}
			xff = strings.TrimSpace(xff)
			if xff != "" {
				return xff
			}
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

// RateLimiter returns middleware that limits requests per IP address.
// rps is requests per second, burst is the maximum burst size.
// When trustProxy is true, X-Forwarded-For / X-Real-Ip headers are used for client IP.
// The cleanup goroutine exits when ctx is cancelled.
func RateLimiter(ctx context.Context, rps float64, burst int, trustProxy ...bool) func(http.Handler) http.Handler {
	rl := newIPRateLimiter(ctx, rps, burst)
	trust := len(trustProxy) > 0 && trustProxy[0]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, trust)
			if !rl.allow(ip) {
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
				w.Header().Add("Vary", "Origin")
				origin := r.Header.Get("Origin")
				if allowed["*"] || allowed[origin] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
					w.Header().Set("Access-Control-Max-Age", "86400")
					if r.Method == http.MethodOptions {
						w.WriteHeader(http.StatusNoContent)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
