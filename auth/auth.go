package auth

import (
	"context"
	"net/http"
)

// Identity represents an authenticated user.
type Identity struct {
	ID            string
	Email         string
	WalletAddress string
	Method        string // "password", "wallet", "apikey"
}

// Authenticator extracts identity from a request.
type Authenticator interface {
	Authenticate(r *http.Request) (*Identity, error)
}

type contextKey struct{}

// ContextWithIdentity returns a new context with the given identity stored.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFromContext extracts the identity from the context, or nil if not present.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}
