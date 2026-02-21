package cmd

import (
	"regexp"
	"testing"
)

func TestGenerateDefaultLength(t *testing.T) {
	secret, err := Generate(32, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected 32 chars, got %d", len(secret))
	}
}

func TestGenerateCustomLength(t *testing.T) {
	secret, err := Generate(64, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Fatalf("expected 64 chars, got %d", len(secret))
	}
}

func TestGenerateHexCharset(t *testing.T) {
	secret, err := Generate(32, charsetHex)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(secret) {
		t.Fatalf("hex charset produced non-hex chars: %q", secret)
	}
}

func TestGenerateBase64URLCharset(t *testing.T) {
	secret, err := Generate(32, charsetBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(secret) {
		t.Fatalf("base64url charset produced invalid chars: %q", secret)
	}
}

func TestGenerateAlphanumericCharset(t *testing.T) {
	secret, err := Generate(32, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(secret) {
		t.Fatalf("alphanumeric charset produced invalid chars: %q", secret)
	}
}

func TestGenerateSymbolsCharset(t *testing.T) {
	secret, err := Generate(32, charsetSymbols)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected 32 chars, got %d", len(secret))
	}
}

func TestGenerateRandomness(t *testing.T) {
	s1, err := Generate(32, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Generate(32, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Fatal("two Generate calls produced identical output")
	}
}

func TestGenerateNoNewline(t *testing.T) {
	secret, err := Generate(32, charsetAlphanumeric)
	if err != nil {
		t.Fatal(err)
	}
	if secret[len(secret)-1] == '\n' {
		t.Fatal("output contains trailing newline")
	}
}
