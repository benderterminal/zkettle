package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/id"
	"github.com/taw/zkettle/internal/store"
)

const maxBodySize = 1024 * 1024 // 1MB

type Config struct {
	BaseURL *baseurl.BaseURL
}

type Server struct {
	cfg   Config
	store *store.Store
	webFS fs.FS
	mux   *http.ServeMux
}

func New(cfg Config, st *store.Store, webFS fs.FS) *Server {
	s := &Server{
		cfg:   cfg,
		store: st,
		webFS: webFS,
		mux:   http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /{$}", s.handleLanding)
	s.mux.HandleFunc("GET /create", s.handleCreatePage)
	s.mux.HandleFunc("POST /api/secrets", s.handleCreate)
	s.mux.HandleFunc("GET /api/secrets/{id}", s.handleGet)
	s.mux.HandleFunc("GET /api/secrets/{id}/status", s.handleStatus)
	s.mux.HandleFunc("DELETE /api/secrets/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /s/{id}", s.handleViewer)
	s.mux.HandleFunc("GET /health", s.handleHealth)
	return s
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

type createRequest struct {
	Encrypted string `json:"encrypted"`
	IV        string `json:"iv"`
	Views     int    `json:"views"`
	Hours     int    `json:"hours"`
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
	if req.Hours == 0 {
		req.Hours = 24
	}
	if req.Hours < 1 || req.Hours > 720 {
		writeError(w, http.StatusBadRequest, "hours must be 1-720")
		return
	}

	secretID := id.Generate()
	deleteToken := id.Generate()
	expiresAt := time.Now().Add(time.Duration(req.Hours) * time.Hour)

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
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
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
	err := s.store.Status(secretID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to check secret status")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"available"}`))
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

	// Inject nonce into <script> tags (pages have at most 1 script tag)
	html := strings.Replace(string(data), "<script>", fmt.Sprintf(`<script nonce="%s">`, nonce), 1)

	// Set CSP header with nonce for script-src
	csp := fmt.Sprintf("default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:", nonce)
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
