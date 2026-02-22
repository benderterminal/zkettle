package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/taw/zkettle/auth"
	"github.com/taw/zkettle/baseurl"
	"github.com/taw/zkettle/id"
	"github.com/taw/zkettle/store"
)

const maxBodySize = 1024 * 1024 // 1MB

type Config struct {
	BaseURL     *baseurl.BaseURL
	TrustProxy  bool
	ProxyDepth  int
	CORSOrigins []string
	ReadRPS     float64
	ReadBurst   int
	WriteRPS    float64
	WriteBurst  int

	// Extension points for composability.
	// All are optional; nil values are safe defaults (no auth, no extra routes, no middleware).

	// AuthFunc extracts an identity from a request. nil = no authentication.
	// Used by handleGet and handleStatus to enforce recipient gating.
	AuthFunc func(r *http.Request) (*auth.Identity, error)

	// ExtraRoutes registers additional routes on the server mux. nil = no extra routes.
	ExtraRoutes func(mux *http.ServeMux)

	// Middleware is a chain of additional middleware applied after security headers.
	// Each function wraps the handler; they are applied in slice order (last = outermost).
	Middleware []func(http.Handler) http.Handler
}

// BuildHandler composes the middleware chain around the given handler.
// Zero-value rate limit fields default to 120/120 read and 60/60 write.
func BuildHandler(ctx context.Context, cfg Config, handler http.Handler) http.Handler {
	readRPS := cfg.ReadRPS
	if readRPS == 0 {
		readRPS = 120
	}
	readBurst := cfg.ReadBurst
	if readBurst == 0 {
		readBurst = 120
	}
	writeRPS := cfg.WriteRPS
	if writeRPS == 0 {
		writeRPS = 60
	}
	writeBurst := cfg.WriteBurst
	if writeBurst == 0 {
		writeBurst = 60
	}
	proxyDepth := cfg.ProxyDepth
	if proxyDepth == 0 {
		proxyDepth = 1
	}

	h := handler
	h = RateLimiter(ctx, readRPS, readBurst, writeRPS, writeBurst, cfg.TrustProxy, proxyDepth)(h)
	h = CORSMiddleware(cfg.CORSOrigins)(h)
	h = RequestLogger(cfg.TrustProxy, proxyDepth)(h)
	return h
}

type Server struct {
	cfg           Config
	store         *store.Store
	webFS         fs.FS
	mux           *http.ServeMux
	createLimiter *ipRateLimiter
}

func New(ctx context.Context, cfg Config, st *store.Store, webFS fs.FS) *Server {
	s := &Server{
		cfg:           cfg,
		store:         st,
		webFS:         webFS,
		mux:           http.NewServeMux(),
		createLimiter: newIPRateLimiter(ctx, 10, 10, 10000),
	}
	s.mux.HandleFunc("GET /{$}", s.handleLanding)
	s.mux.HandleFunc("GET /create", s.handleCreatePage)
	s.mux.HandleFunc("POST /api/secrets", s.handleCreate)
	s.mux.HandleFunc("GET /api/secrets/{id}", s.handleGet)
	s.mux.HandleFunc("GET /api/secrets/{id}/status", s.handleStatus)
	s.mux.HandleFunc("DELETE /api/secrets/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /s/{id}", s.handleViewer)
	s.mux.HandleFunc("GET /health", s.handleHealth)

	if cfg.ExtraRoutes != nil {
		cfg.ExtraRoutes(s.mux)
	}

	return s
}

func (s *Server) Handler() http.Handler {
	h := s.securityHeaders(s.mux)
	for _, mw := range s.cfg.Middleware {
		h = mw(h)
	}
	return h
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil || (s.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// Prevent caching of API responses
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type createRequest struct {
	Encrypted string `json:"encrypted"`
	IV        string `json:"iv"`
	Views     int    `json:"views"`
	Minutes   int    `json:"minutes"`
}

type createResponse struct {
	ID          string `json:"id"`
	ExpiresAt   string `json:"expires_at"`
	DeleteToken string `json:"delete_token"`
}

type getResponse struct {
	Encrypted string `json:"encrypted"`
	IV        string `json:"iv"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r, s.cfg.TrustProxy, s.cfg.ProxyDepth)
	if !s.createLimiter.allow(ip) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Encrypted == "" {
		writeError(w, http.StatusBadRequest, "encrypted is required")
		return
	}
	if req.IV == "" {
		writeError(w, http.StatusBadRequest, "iv is required")
		return
	}

	encBytes, err := base64.RawURLEncoding.DecodeString(req.Encrypted)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64url for encrypted")
		return
	}
	if len(encBytes) > 500*1024 {
		writeError(w, http.StatusBadRequest, "encrypted exceeds 500KB limit")
		return
	}

	ivBytes, err := base64.RawURLEncoding.DecodeString(req.IV)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64url for iv")
		return
	}
	if len(ivBytes) != 12 {
		writeError(w, http.StatusBadRequest, "iv must be 12 bytes")
		return
	}

	if req.Views == 0 {
		req.Views = 1
	}
	if req.Views < 1 || req.Views > 100 {
		writeError(w, http.StatusBadRequest, "views must be 1-100")
		return
	}
	if req.Minutes == 0 {
		req.Minutes = 1440 // 24 hours
	}
	if req.Minutes < 1 || req.Minutes > 43200 {
		writeError(w, http.StatusBadRequest, "minutes must be 1-43200 (30 days)")
		return
	}

	secretID := id.Generate()
	deleteToken := id.Generate()
	expiresAt := time.Now().Add(time.Duration(req.Minutes) * time.Minute)

	if err := s.store.Create(secretID, encBytes, ivBytes, req.Views, expiresAt, deleteToken); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createResponse{
		ID:          secretID,
		ExpiresAt:   expiresAt.UTC().Format(time.RFC3339),
		DeleteToken: deleteToken,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	if !id.Valid(secretID) {
		writeError(w, http.StatusBadRequest, "invalid secret ID format")
		return
	}

	// Check recipient gating before consuming a view.
	// Note: there is a small TOCTOU window between GetMeta and Get. A concurrent
	// request could consume the last view between these calls. The second caller
	// would get a 404, which is acceptable behavior.
	meta, err := s.store.GetMeta(secretID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to retrieve secret")
		return
	}

	r, ok := s.checkRecipientAuth(w, r, meta)
	if !ok {
		return
	}

	encrypted, iv, err := s.store.Get(secretID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to retrieve secret")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getResponse{
		Encrypted: base64.RawURLEncoding.EncodeToString(encrypted),
		IV:        base64.RawURLEncoding.EncodeToString(iv),
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	if !id.Valid(secretID) {
		writeError(w, http.StatusBadRequest, "invalid secret ID format")
		return
	}

	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, "Authorization header with Bearer token required")
		return
	}

	if err := s.store.Delete(secretID, token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		if errors.Is(err, store.ErrUnauthorized) {
			writeError(w, http.StatusForbidden, "invalid delete token")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	s.servePage(w, "index.html")
}

func (s *Server) handleCreatePage(w http.ResponseWriter, r *http.Request) {
	s.servePage(w, "create.html")
}

func (s *Server) handleViewer(w http.ResponseWriter, r *http.Request) {
	s.servePage(w, "viewer.html")
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	secretID := r.PathValue("id")
	if !id.Valid(secretID) {
		writeError(w, http.StatusBadRequest, "invalid secret ID format")
		return
	}

	meta, err := s.store.GetMeta(secretID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to check secret status")
		return
	}

	if _, ok := s.checkRecipientAuth(w, r, meta); !ok {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"available"}`))
}

// checkRecipientAuth enforces recipient gating for a secret.
// If the secret has a recipient, it verifies auth and stores identity in context.
// Returns the (possibly updated) request and true if the caller should proceed,
// or writes an error response and returns false.
func (s *Server) checkRecipientAuth(w http.ResponseWriter, r *http.Request, meta *store.SecretMeta) (*http.Request, bool) {
	if meta.Recipient == nil || *meta.Recipient == "" {
		return r, true
	}
	if s.cfg.AuthFunc == nil {
		// Self-hosted instance with no auth — can't verify recipient
		writeError(w, http.StatusForbidden, "this secret requires authentication on a hosted instance")
		return r, false
	}
	// Auth is available — authenticate the request and store identity in context.
	// The hosted server's AuthFunc handles the actual recipient matching.
	identity, authErr := s.cfg.AuthFunc(r)
	if authErr != nil {
		slog.Warn("authentication failed", "secret_id", meta.ID, "error", authErr)
		writeError(w, http.StatusUnauthorized, "authentication required")
		return r, false
	}
	r = r.WithContext(auth.ContextWithIdentity(r.Context(), identity))
	return r, true
}

func (s *Server) servePage(w http.ResponseWriter, name string) {
	data, err := fs.ReadFile(s.webFS, name)
	if err != nil {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}

	// Generate a per-request nonce for CSP
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	// Inject nonce into all <script> and <style> tags
	html := strings.ReplaceAll(string(data), "<script>", fmt.Sprintf(`<script nonce="%s">`, nonce))
	html = strings.ReplaceAll(html, "<style>", fmt.Sprintf(`<style nonce="%s">`, nonce))

	// Set CSP header: nonce for both script-src and style-src
	csp := fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'self'", nonce, nonce)
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := s.store.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"error"}`))
		return
	}
	w.Write([]byte(`{"status":"ok"}`))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
