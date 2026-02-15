package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("hello, world! this is a secret message")
	ciphertext, iv, key, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ciphertext, iv, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", got, plaintext)
	}
}

func TestKeyEncodeDecodeRoundTrip(t *testing.T) {
	_, _, key, err := Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodeKey(key)
	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatalf("key round-trip failed: got %x, want %x", decoded, key)
	}
}

func TestWrongKeyReturnsError(t *testing.T) {
	plaintext := []byte("secret data")
	ciphertext, iv, _, err := Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = 0xff
	}
	_, err = Decrypt(ciphertext, iv, wrongKey)
	if err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	plaintext := []byte{}
	ciphertext, iv, key, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	got, err := Decrypt(ciphertext, iv, key)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("empty round-trip failed: got %q, want %q", got, plaintext)
	}
}

func TestCorruptedCiphertextFails(t *testing.T) {
	plaintext := []byte("tamper test")
	ciphertext, iv, key, err := Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext to corrupt the GCM auth tag
	ciphertext[len(ciphertext)-1] ^= 0xff
	_, err = Decrypt(ciphertext, iv, key)
	if err == nil {
		t.Fatal("expected error with corrupted ciphertext, got nil")
	}
}
