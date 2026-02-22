package auth

import (
	"context"
	"net/http"
	"testing"
)

// mockAuthenticator implements Authenticator for testing.
type mockAuthenticator struct {
	identity *Identity
	err      error
}

func (m *mockAuthenticator) Authenticate(r *http.Request) (*Identity, error) {
	return m.identity, m.err
}

func TestAuthenticatorInterface(t *testing.T) {
	id := &Identity{
		ID:            "user-123",
		Email:         "alice@example.com",
		WalletAddress: "0xAbC123",
		Method:        "password",
	}
	var a Authenticator = &mockAuthenticator{identity: id}
	req, _ := http.NewRequest("GET", "/", nil)
	got, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != id.ID {
		t.Errorf("got ID %q, want %q", got.ID, id.ID)
	}
	if got.Email != id.Email {
		t.Errorf("got Email %q, want %q", got.Email, id.Email)
	}
	if got.WalletAddress != id.WalletAddress {
		t.Errorf("got WalletAddress %q, want %q", got.WalletAddress, id.WalletAddress)
	}
	if got.Method != id.Method {
		t.Errorf("got Method %q, want %q", got.Method, id.Method)
	}
}

func TestContextWithIdentity(t *testing.T) {
	id := &Identity{ID: "user-456", Email: "bob@example.com", Method: "wallet"}
	ctx := ContextWithIdentity(context.Background(), id)
	got := IdentityFromContext(ctx)
	if got == nil {
		t.Fatal("expected identity, got nil")
	}
	if got.ID != id.ID {
		t.Errorf("got ID %q, want %q", got.ID, id.ID)
	}
	if got.Email != id.Email {
		t.Errorf("got Email %q, want %q", got.Email, id.Email)
	}
}

func TestIdentityFromContext_Empty(t *testing.T) {
	got := IdentityFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestIdentityFromContext_NilIdentity(t *testing.T) {
	ctx := ContextWithIdentity(context.Background(), nil)
	got := IdentityFromContext(ctx)
	if got != nil {
		t.Errorf("expected nil for nil identity, got %+v", got)
	}
}
