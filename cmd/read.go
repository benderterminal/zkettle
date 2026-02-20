package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/taw/zkettle/internal/crypto"
	"github.com/taw/zkettle/internal/id"
)

func RunRead(args []string) error {
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: zkettle read <url>")
	}
	rawURL := fs.Arg(0)

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}

	// Extract ID from path /s/{id}
	parts := strings.SplitN(u.Path, "/s/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("invalid secret URL: expected /s/{id} in path")
	}
	secretID := parts[1]
	if !id.Valid(secretID) {
		return fmt.Errorf("invalid secret ID format")
	}

	// Extract key from fragment
	keyStr := u.Fragment
	if keyStr == "" {
		return fmt.Errorf("no decryption key found in URL fragment")
	}
	key, err := crypto.DecodeKey(keyStr)
	if err != nil {
		return fmt.Errorf("decoding key: %w", err)
	}

	// Build API URL
	apiURL := fmt.Sprintf("%s://%s/api/secrets/%s", u.Scheme, u.Host, secretID)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return connError("fetching secret", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("secret not found (expired or already viewed)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var data struct {
		Encrypted string `json:"encrypted"`
		IV        string `json:"iv"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	ciphertext, err := crypto.DecodeKey(data.Encrypted)
	if err != nil {
		return fmt.Errorf("decoding ciphertext: %w", err)
	}
	iv, err := crypto.DecodeKey(data.IV)
	if err != nil {
		return fmt.Errorf("decoding iv: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, iv, key)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	fmt.Println(string(plaintext))
	return nil
}
