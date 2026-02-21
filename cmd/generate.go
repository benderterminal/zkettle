package cmd

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
)

const (
	charsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetSymbols      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetHex          = "0123456789abcdef"
	charsetBase64URL    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// Generate produces a cryptographically random string of the given length
// using characters from the specified charset.
func Generate(length int, charset string) (string, error) {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("generating random byte: %w", err)
		}
		result[i] = charset[idx.Int64()]
	}
	return string(result), nil
}

func RunGenerate(args []string) error {
	f := flag.NewFlagSet("generate", flag.ExitOnError)
	length := f.Int("length", 32, "Length of generated secret")
	charset := f.String("charset", "alphanumeric", "Character set: alphanumeric, symbols, hex, base64url")
	if err := f.Parse(args); err != nil {
		return err
	}

	if *length < 1 || *length > 4096 {
		return fmt.Errorf("length must be 1-4096")
	}

	var chars string
	switch *charset {
	case "alphanumeric":
		chars = charsetAlphanumeric
	case "symbols":
		chars = charsetSymbols
	case "hex":
		chars = charsetHex
	case "base64url":
		chars = charsetBase64URL
	default:
		return fmt.Errorf("unknown charset %q (use: alphanumeric, symbols, hex, base64url)", *charset)
	}

	secret, err := Generate(*length, chars)
	if err != nil {
		return err
	}

	// Write without trailing newline for clean piping
	fmt.Fprint(os.Stdout, secret)
	return nil
}
