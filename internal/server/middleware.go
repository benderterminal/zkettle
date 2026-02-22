package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// RequestLogger returns middleware that logs each request.
// Logs: timestamp, method, path, status code, duration, client IP.
// Sensitive data (bodies, auth headers) is never logged.
func RequestLogger(trustProxy bool, proxyDepth int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := generateRequestID()
			w.Header().Set("X-Request-Id", reqID)
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			slog.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start).Round(time.Millisecond),
				"ip", clientIP(r, trustProxy, proxyDepth),
				"request_id", reqID,
			)
		})
	}
}

// generateRequestID returns 16 hex characters (8 random bytes) for log correlation.
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ipRateLimiter tracks per-IP rate limiters with automatic cleanup of stale entries.
// maxEntries caps the map size to prevent memory exhaustion from IP spoofing attacks.
type ipRateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*ipEntry
	rps        rate.Limit
	burst      int
	maxEntries int
}

type ipEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(ctx context.Context, rps float64, burst int, maxEntries int) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters:   make(map[string]*ipEntry),
		rps:        rate.Limit(rps),
		burst:      burst,
		maxEntries: maxEntries,
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	entry, ok := rl.limiters[ip]
	if !ok {
		if rl.maxEntries > 0 && len(rl.limiters) >= rl.maxEntries {
			rl.evictOldest()
		}
		entry = &ipEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()
	return entry.limiter.Allow()
}

// evictOldest removes the least recently seen entry. Must be called with mu held.
func (rl *ipRateLimiter) evictOldest() {
	var oldestIP string
	var oldestTime time.Time
	first := true
	for ip, entry := range rl.limiters {
		if first || entry.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = entry.lastSeen
			first = false
		}
	}
	if oldestIP != "" {
		delete(rl.limiters, oldestIP)
	}
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
func clientIP(r *http.Request, trustProxy bool, proxyDepth int) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if proxyDepth <= 0 {
				proxyDepth = 1
			}
			// Take the Nth-from-right entry where N = proxyDepth.
			// This correctly ignores client-spoofed entries prepended
			// before the first trusted proxy.
			idx := len(parts) - proxyDepth
			if idx >= 0 && idx < len(parts) {
				ip := strings.TrimSpace(parts[idx])
				if ip != "" {
					return ip
				}
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
func RateLimiter(ctx context.Context, readRPS float64, readBurst int, writeRPS float64, writeBurst int, trustProxy bool, proxyDepth int) func(http.Handler) http.Handler {
	readRL := newIPRateLimiter(ctx, readRPS, readBurst, 10000)
	writeRL := newIPRateLimiter(ctx, writeRPS, writeBurst, 10000)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, trustProxy, proxyDepth)
			rl := readRL
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				rl = writeRL
			}
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
