package id

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateLength(t *testing.T) {
	id := Generate()
	if len(id) != 32 {
		t.Fatalf("Generate() returned %d chars, want 32: %q", len(id), id)
	}
}

func TestGenerateIsHex(t *testing.T) {
	id := Generate()
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("Generate() is not valid hex: %q: %v", id, err)
	}
}

func TestGenerateNoTrailingEquals(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := Generate()
		if strings.HasSuffix(id, "=") {
			t.Fatalf("Generate() has trailing '=': %q", id)
		}
	}
}

func TestGenerateUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := Generate()
		if seen[id] {
			t.Fatalf("duplicate ID on iteration %d: %q", i, id)
		}
		seen[id] = true
	}
}
