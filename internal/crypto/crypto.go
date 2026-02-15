package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Encrypt encrypts plaintext with a random AES-256-GCM key.
// Returns ciphertext (with appended auth tag), IV, and key.
func Encrypt(plaintext []byte) (ciphertext, iv, key []byte, err error) {
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, nil, fmt.Errorf("generating key: %w", err)
	}
	iv = make([]byte, 12)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("generating iv: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating gcm: %w", err)
	}
	ciphertext = gcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, iv, key, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given IV and key.
func Decrypt(ciphertext, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// EncodeKey encodes a key as base64url without padding.
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64url-encoded key (no padding).
func DecodeKey(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
